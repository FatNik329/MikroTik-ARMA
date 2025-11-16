import yaml
import logging
import os
from datetime import datetime
from pathlib import Path

# ========== НАСТРОЙКИ ==========
INPUT_FILE = "raw-data/Example-list/DNS/results-dns.yaml"  # Путь к входному YAML (results-dns.yaml) файлу
OUTPUT_FILE = "raw-data/Example-list/DNS/filter-results-dns.yaml"  # Путь к выходному файлу (filter-results-dns.yaml)
# ===============================

# Автоматическое определение имени лог файла
script_name = Path(__file__).stem
log_filename = f"{script_name}.log"

# Создание директории в logs (автоматическое имя из названия скрипта)
log_path = Path(f'logs/additional/filter_results_dns/{log_filename}')
log_path.parent.mkdir(parents=True, exist_ok=True)

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)

def load_yaml_file(file_path):
    """Загрузка YAML файла с обработкой ошибок"""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logging.error(f"Файл не найден: {file_path}")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Ошибка парсинга YAML в файле {file_path}: {e}")
        raise
    except Exception as e:
        logging.error(f"Неожиданная ошибка при чтении файла {file_path}: {e}")
        raise

def save_yaml_file(data, file_path):
    """Сохранение данных в YAML файл"""
    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            yaml.dump(data, file, allow_unicode=True, sort_keys=False)
        logging.info(f"Файл успешно сохранен: {file_path}")
    except Exception as e:
        logging.error(f"Ошибка при сохранении файла {file_path}: {e}")
        raise

def load_existing_output_file(file_path):
    """Загрузка существующего выходного файла"""
    try:
        if Path(file_path).exists():
            logging.info(f"Обнаружен существующий файл: {file_path}")
            return load_yaml_file(file_path)
        else:
            logging.info(f"Файл не существует, будет создан новый: {file_path}")
            return None
    except Exception as e:
        logging.warning(f"Не удалось загрузить существующий файл {file_path}: {e}. Будет создан новый.")
        return None

def merge_categories(existing_categories, new_categories):
    """Объединение существующих и новых категорий с устранением дубликатов"""
    merged_categories = {}
    total_added_domains = 0 # общий счетчик добавленных доменов

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
            if added_domains_count > 0:  # проверка на ненулевые обновления
                merged_domains = sorted(list(existing_domains.union(new_domains)))
                merged_categories[category] = merged_domains
                logging.info(f"Обновлена категория '{category}': добавлено {added_domains_count} новых доменов")
                total_added_domains += added_domains_count
        else:
            # Новая категория
            merged_categories[category] = sorted(domains)
            logging.info(f"Добавлена новая категория '{category}': {len(domains)} доменов")
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
                logging.info(f"Всего добавлено доменов во все категории: {total_added}")

        # Итоговая статистика
        total_domains = sum(len(domains) for domains in output_data['categories'].values())
        output_data['meta']['statistics'] = {
            'total_categories': len(output_data['categories']),
            'total_domains': total_domains,
            'categories_breakdown': {category: len(domains) for category, domains in output_data['categories'].items()}
        }

        return output_data

    except Exception as e:
        logging.error(f"Ошибка при обработке DNS данных: {e}")
        raise

def main():
    """Основная функция скрипта"""
    logging.info("\n=== Запуск %s - фильтратор results-dns.yaml ===", script_name)

    try:
        # Преобразование пути
        input_path = Path(INPUT_FILE).absolute()
        output_path = Path(OUTPUT_FILE).absolute()

        logging.info(f"Начало обработки DNS данных")
        logging.info(f"Входной файл: {input_path}")
        logging.info(f"Выходной файл: {output_path}")

        # Проверка существования входного файла
        if not input_path.exists():
            raise FileNotFoundError(f"Входной файл не найден: {input_path}")

        # Загрузка существующих выходных данных
        logging.info("Проверка существующего выходного файла...")
        existing_output_data = load_existing_output_file(output_path)

        # Загрузка данных из входного файла
        logging.info("Загрузка входного файла...")
        input_data = load_yaml_file(input_path)

        # Обработка данных
        logging.info("Обработка DNS данных...")
        output_data = process_dns_data(input_data, existing_output_data)

        # Сохранение результата
        logging.info("Сохранение результата...")
        save_yaml_file(output_data, output_path)

        # Логирование статистики
        stats = output_data['meta']['statistics']
        logging.info(f"Выполнение успешно! Всего в файле: категории - {stats['total_categories']}, домены - {stats['total_domains']}")

    except Exception as e:
        logging.error(f"Критическая ошибка: {e}")
        return False

    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
  
