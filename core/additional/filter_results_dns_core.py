"""
Ядро функционала для скриптов filter_results_dns-*
"""
import yaml
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
from core.maintenance.logs_modules import LoggerManager

_logger = logging.getLogger(__name__)

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
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if existing_output_data:
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

        if 'meta' in input_data:
            dns_meta_to_preserve = ['dns_servers', 'timeout']
            for key in dns_meta_to_preserve:
                if key in input_data['meta']:
                    output_data['meta'][key] = input_data['meta'][key]

        if 'categories' in input_data:
            new_categories = {}
            for category, domains in input_data['categories'].items():
                domain_list = sorted(list(domains.keys()))
                new_categories[category] = domain_list

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

def create_catsort_file(output_data, output_file_path):
    """Создание файла с категоризацией доменов по уровням"""
    try:
        catsort_data = {
            'meta': output_data['meta'].copy(),
            'categories': {}
        }

        # Обновляет статистику для catsort
        total_l2_domains = 0

        for category, domains in output_data['categories'].items():
            catsort_data['categories'][category] = {'domains': {}}

            # Группирует домены по доменам 2-го уровня
            domain_tree = {}

            for domain in domains:
                parts = domain.split('.')
                if len(parts) >= 2:
                    l2_domain = '.'.join(parts[-2:])
                    if len(parts) > 2:
                        subdomain = '.'.join(parts[:-2])
                        if l2_domain not in domain_tree:
                            domain_tree[l2_domain] = []
                        domain_tree[l2_domain].append(domain)
                    else:
                        if l2_domain not in domain_tree:
                            domain_tree[l2_domain] = []

            # Сортирует и формирует структуру
            for l2_domain, subdomains in sorted(domain_tree.items()):
                if subdomains:
                    unique_subs = sorted(list(set(subdomains)))
                    catsort_data['categories'][category]['domains'][l2_domain] = unique_subs
                    total_l2_domains += 1
                else:
                    # Домен без субдоменов - пустой список
                    catsort_data['categories'][category]['domains'][l2_domain] = []
                    total_l2_domains += 1

        # Обновление статистики
        catsort_data['meta']['statistics']['total_domains_l2'] = total_l2_domains

        # Сохранение файла
        catsort_path = output_file_path.parent / f"{output_file_path.stem}-catsort.yaml"
        save_yaml_file(catsort_data, catsort_path)
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

            # Сохранение результата
            _logger.info("Сохранение результата...")
            save_yaml_file(output_data, output_path)

            # Создание catsort файла если включено
            if DOMAINS_CATSORT.lower() == "true":
                _logger.info("Создание файла категоризации доменов...")
                # Загрузка OUTPUT_FILE для категоризации
                final_output_data = load_yaml_file(output_path)
                create_catsort_file(final_output_data, output_path)

            # Логирование статистики
            stats = output_data['meta']['statistics']
            _logger.info(f"Выполнение успешно! Всего в файле: категории - {stats['total_categories']}, домены - {stats['total_domains']}")

        except Exception as e:
            logger.error(f"Критическая ошибка: {e}")
            return False
        return True
