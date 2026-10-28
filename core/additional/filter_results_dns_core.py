"""
Ядро функционала для скриптов filter_results_dns-*
"""
import yaml
import logging
import os
import tldextract
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
from core.maintenance.logs_modules import LoggerManager


_logger = logging.getLogger(__name__)

_extractor = tldextract.TLDExtract(
    suffix_list_urls=("https://publicsuffix.org/list/public_suffix_list.dat",),
    cache_dir="./cache/filter_results_dns/tldextract",    # постоянный каталог для кэша
    fallback_to_snapshot=True,            # если сети/кэша нет — встроенный PSL
)

def load_yaml_file(file_path):
    """Загрузка YAML файла с обработкой ошибок"""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        _logger.error(f"Файл не найден: {file_path}")
        raise
    except yaml.YAMLError as e:
        _logger.error(f"Ошибка парсинга YAML в файле {file_path}: {e}")
        raise
    except Exception as e:
        _logger.error(f"Неожиданная ошибка при чтении файла {file_path}: {e}")
        raise

def save_yaml_file(data, file_path):
    """Сохранение данных в YAML файл"""
    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            yaml.dump(data, file, allow_unicode=True, sort_keys=False)
        _logger.info(f"Файл успешно сохранен: {file_path}")
    except Exception as e:
        _logger.error(f"Ошибка при сохранении файла {file_path}: {e}")
        raise

def save_yaml_file_atomic(data, file_path):
    """Атомарное сохранение данных в YAML файл с использованием временного файла"""
    temp_file_path = Path(file_path).parent / f".{Path(file_path).name}.tmp"

    try:
        # Сохраняет во временный файл
        with open(temp_file_path, 'w', encoding='utf-8') as file:
            yaml.dump(data, file, allow_unicode=True, sort_keys=False)

        # Если сохранение успешно, заменяет оригинальный файл
        Path(temp_file_path).replace(file_path)
        _logger.info(f"Файл успешно сохранен: {file_path}")

    except Exception as e:
        # При ошибке удаляет временный файл если он существует
        if Path(temp_file_path).exists():
            Path(temp_file_path).unlink()
        _logger.error(f"Ошибка при атомарном сохранении файла {file_path}: {e}")
        raise

def load_existing_output_file(file_path):
    """Загрузка существующего выходного файла"""
    try:
        if Path(file_path).exists():
            _logger.info(f"Обнаружен существующий файл: {file_path}")
            return load_yaml_file(file_path)
        else:
            _logger.info(f"Файл не существует, будет создан новый: {file_path}")
            return None
    except Exception as e:
        logging.warning(f"Не удалось загрузить существующий файл {file_path}: {e}. Будет создан новый.")
        return None

def merge_categories(existing_categories, new_categories):
    """Объединение существующих и новых категорий с устранением дубликатов"""
    merged_categories = {}
    total_added_domains = 0

    # Копирование существующих категорий
    if existing_categories:
        for category, domains in existing_categories.items():
            merged_categories[category] = domains.copy()

    for category, domains in new_categories.items():
        if category in merged_categories:
            # Объедение доменов, без дубликатов
            existing_domains = set(merged_categories[category])
            new_domains = set(domains)
            added_domains_count = len(new_domains - existing_domains)
            if added_domains_count > 0:
                merged_domains = sorted(list(existing_domains.union(new_domains)))
                merged_categories[category] = merged_domains
                _logger.info(f"Обновлена категория '{category}': добавлено {added_domains_count} новых доменов")
                total_added_domains += added_domains_count
        else:
            merged_categories[category] = sorted(domains)
            _logger.info(f"Добавлена новая категория '{category}': {len(domains)} доменов")
            total_added_domains += len(domains)

    return merged_categories, total_added_domains

def process_dns_data(input_data, existing_output_data=None):
    """Обработка DNS данных и создание/обновление фильтрованной структуры"""
    try:
        # Проверка входных данных
        if not input_data:
            raise ValueError("Входные данные пусты или некорректны")

        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if existing_output_data and isinstance(existing_output_data, dict):
            # Основные данные
            output_data = existing_output_data.copy()
            output_data['meta']['last_updated'] = current_time
            output_data['meta']['update_mode'] = 'incremental'
            output_data['meta']['skip_duplicates'] = True

            if 'generated_at' not in output_data['meta']:
                output_data['meta']['generated_at'] = current_time
        else:
            output_data = {
                'meta': {
                    'generated_at': current_time,
                    'last_updated': current_time,
                    'update_mode': 'incremental',
                    'skip_duplicates': True
                },
                'categories': {}
            }

        if 'meta' in input_data and isinstance(input_data['meta'], dict):
            dns_meta_to_preserve = ['dns_servers', 'timeout']
            for key in dns_meta_to_preserve:
                if key in input_data['meta']:
                    output_data['meta'][key] = input_data['meta'][key]

        if 'categories' in input_data and isinstance(input_data['categories'], dict):
            new_categories = {}
            for category, domains in input_data['categories'].items():
                if domains and isinstance(domains, dict):
                    domain_list = sorted(list(domains.keys()))
                    new_categories[category] = domain_list
                elif domains and isinstance(domains, list):
                    new_categories[category] = sorted(domains)
                else:
                    new_categories[category] = []

            merged_categories, total_added = merge_categories(
                output_data.get('categories', {}),
                new_categories
            )
            output_data['categories'] = merged_categories

            if total_added > 0:
                _logger.info(f"Всего добавлено доменов во все категории: {total_added}")

        # Итоговая статистика
        total_domains = sum(len(domains) for domains in output_data['categories'].values())
        output_data['meta']['statistics'] = {
            'total_categories': len(output_data['categories']),
            'total_domains': total_domains,
            'categories_breakdown': {category: len(domains) for category, domains in output_data['categories'].items()}
        }

        return output_data

    except Exception as e:
        _logger.error(f"Ошибка при обработке DNS данных: {e}")
        raise

def get_registrable_domain(domain: str):
    ext = _extractor(domain)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"

def create_catsort_file(output_data, output_file_path, existing_catsort_data=None):
    try:
        today = datetime.now().strftime('%Y-%m-%d')

        old_meta = {}
        if existing_catsort_data and isinstance(existing_catsort_data.get('categories'), dict):
            for cat, cat_data in existing_catsort_data['categories'].items():
                old_meta[cat] = {}
                domains_map = (cat_data or {}).get('domains') or {}
                for l2, l2_val in domains_map.items():
                    if isinstance(l2_val, dict):
                        old_meta[cat][l2] = {
                            'date_added': l2_val.get('_date_added', today),
                            'subdomains': {k: v for k, v in l2_val.items() if k != '_date_added'},
                        }
                    elif isinstance(l2_val, list):
                        old_meta[cat][l2] = {'date_added': today, 'subdomains': {}}

        catsort_data = {'meta': output_data['meta'].copy(), 'categories': {}}
        total_l2_domains = 0

        for category, domains in output_data['categories'].items():
            catsort_data['categories'][category] = {'domains': {}}
            domain_tree = {}

            for domain in domains:
                if domain is None or not isinstance(domain, str):
                    _logger.warning(f"Пропущен некорректный домен: {domain}")
                    continue

                reg = get_registrable_domain(domain)
                if not reg:
                    _logger.warning(f"Не удалось определить registrable domain: {domain!r} (категория: {category})")
                    continue

                domain_tree.setdefault(reg, set())
                if domain != reg:
                    domain_tree[reg].add(domain)

            old_cat = old_meta.get(category, {})

            for reg_domain in sorted(domain_tree.keys()):
                subs = sorted(domain_tree[reg_domain])
                old_l2 = old_cat.get(reg_domain, {})
                old_subs = old_l2.get('subdomains', {})

                l2_date = old_l2.get('date_added', today)
                entry = {'_date_added': l2_date}
                for sub in subs:
                    entry[sub] = old_subs.get(sub, today)

                catsort_data['categories'][category]['domains'][reg_domain] = entry
                total_l2_domains += 1

        catsort_data['meta']['statistics']['total_domains_l2'] = total_l2_domains

        catsort_path = output_file_path.parent / f"{output_file_path.stem}-catsort.yaml"
        save_yaml_file_atomic(catsort_data, catsort_path)
        _logger.info(f"Создан файл категоризации: {catsort_path}")
        return True
    except Exception as e:
        _logger.error(f"Ошибка при создании catsort файла: {e}")
        return False

class FilterResultsDnsCore:
    def __init__(self, config: Dict[str, Any], script_name: str, logger=None):
       self.config = config
       self.script_name = script_name

       self.logger = logger if logger is not None else logging.getLogger(__name__)
       global _logger
       _logger = self.logger

       self.input_file = Path(config['input_file'])
       self.output_file = Path(config['output_file'])
       self.domains_catsort = str(config.get('domains_catsort', 'True')).lower()

    def run(self) -> bool:
        """Основной метод, который выполняет всю логику"""

        _logger.info(f"\n=== Запуск {self.script_name} ===")

        try:
            # Получение настроек из конфига
            INPUT_FILE = self.config['input_file']
            OUTPUT_FILE = self.config['output_file']
            DOMAINS_CATSORT = str(self.config.get('domains_catsort', 'True')).lower()

            # Преобразование пути
            input_path = Path(INPUT_FILE).absolute()
            output_path = Path(OUTPUT_FILE).absolute()
            _logger.info(f"Начало обработки DNS данных")
            _logger.info(f"Входной файл: {input_path}")
            _logger.info(f"Выходной файл: {output_path}")

            # Проверка существования входного файла
            if not input_path.exists():
                raise FileNotFoundError(f"Входной файл не найден: {input_path}")

            # Загрузка существующих выходных данных
            _logger.info("Проверка существующего выходного файла...")
            existing_output_data = load_existing_output_file(output_path)

            # Загрузка данных из входного файла
            _logger.info("Загрузка входного файла...")
            input_data = load_yaml_file(input_path)

            # Обработка данных
            _logger.info("Обработка DNS данных...")
            output_data = process_dns_data(input_data, existing_output_data)

            # Сохранение результата - атомарное
            _logger.info("Сохранение результата...")
            save_yaml_file_atomic(output_data, output_path)

            if DOMAINS_CATSORT.lower() == "true":
                _logger.info("Создание файла категоризации доменов...")
                final_output_data = load_yaml_file(output_path)

                catsort_path = output_path.parent / f"{output_path.stem}-catsort.yaml"
                existing_catsort_data = None
                if catsort_path.exists():
                    try:
                        existing_catsort_data = load_yaml_file(catsort_path)
                        _logger.info(f"Обнаружен существующий catsort-файл: {catsort_path}")
                    except Exception as e:
                        _logger.warning(f"Не удалось загрузить существующий catsort-файл: {e}. Даты будут проставлены заново.")

                create_catsort_file(final_output_data, output_path, existing_catsort_data)

            # Логирование статистики
            stats = output_data['meta']['statistics']
            _logger.info(f"Выполнение успешно! Всего в файле: категории - {stats['total_categories']}, домены - {stats['total_domains']}")

        except Exception as e:
            _logger.error(f"Критическая ошибка: {e}")
            return False
        return True
