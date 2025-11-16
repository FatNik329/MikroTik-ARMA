import logging
import requests
from pathlib import Path
import re
from urllib.parse import urljoin
import sys
import yaml
import idna

# ========== КОНФИГУРАЦИЯ ==========
INPUT_FILE_TLD = "configs/AddressLists/TLD-list/Template/tld_database.html"  # Входной HTML файл - создаётся при скачивании
OUTPUT_FILE_TLD = "configs/AddressLists/TLD-list/Template/tld_domains.txt"   # Выходной TXT файл - создаётся при парсинге
DOWNLOAD_URL = "https://www.iana.org/domains/root/db"  # URL для скачивания TLD доменов
TEMPLATE_DIR_YAML = "configs/AddressLists/TLD-list/DNS" # Путь сохранения YAML шаблонов

# ========== НАСТРОЙКА ЛОГИРОВАНИЯ ==========
# Автоматическое определение имени лог файла
script_name = Path(__file__).stem
log_filename = f"{script_name}.log"

# Создание директории в logs (автоматическое имя из названия скрипта)
log_path = Path(f'logs/additional/tld_parser/{log_filename}')
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

def download_html_file():
    """Скачивает HTML файл с доменами"""
    try:
        logging.info(f"Скачивание файла URL: {DOWNLOAD_URL}")

        response = requests.get(DOWNLOAD_URL, timeout=30)
        response.raise_for_status()

        # Сохраняем файл
        with open(INPUT_FILE_TLD, 'w', encoding='utf-8') as f:
            f.write(response.text)

        logging.info(f"Файл скачан и сохранен: {INPUT_FILE_TLD}")
        return True

    except requests.exceptions.RequestException as e:
        logging.error(f"Ошибка при скачивании файла: {e}")
        return False
    except Exception as e:
        logging.error(f"Неожиданная ошибка при скачивании: {e}")
        return False

def parse_tld_domains(html_content):
    """Парсит HTML и извлекает список TLD доменов"""
    domains = []

    # Регулярное выражение для поиска доменов
    pattern = r'<span class="domain tld"><a href="[^"]*">(\.\w+)</a></span>'

    try:
        matches = re.findall(pattern, html_content)

        for domain in matches:
            domains.append(domain)
            logging.debug(f"Найден домен: {domain}")

        logging.info(f"Всего найдено доменов: {len(domains)}")
        return domains

    except Exception as e:
        logging.error(f"Ошибка при парсинге HTML: {e}")
        return []

def load_existing_domains():
    """Загружает существующие домены из выходного файла"""
    existing_domains = set()

    try:
        if Path(OUTPUT_FILE_TLD).exists():
            with open(OUTPUT_FILE_TLD, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        existing_domains.add(domain)
            logging.info(f"Загружено {len(existing_domains)} существующих доменов")
        else:
            logging.info("Выходной файл не существует, будет создан новый")

    except Exception as e:
        logging.error(f"Ошибка при чтении файла: {e}")

    return existing_domains

def save_domains_incrementally(new_domains):
    """Сохраняет домены инкрементально с сортировкой"""
    try:
        # Загрузка существующих доменов
        existing_domains = load_existing_domains()

        # Объединение старых и новых доменов
        all_domains = existing_domains.union(set(new_domains))

        # Сортировка по алфавиту
        sorted_domains = sorted(all_domains)

        # Сохранение в файл
        with open(OUTPUT_FILE_TLD, 'w', encoding='utf-8') as f:
            for domain in sorted_domains:
                f.write(f"{domain}\n")

        new_count = len(all_domains) - len(existing_domains)
        logging.info(f"Сохранено доменов: {len(sorted_domains)} (новых: {new_count})")
        logging.info(f"Результаты сохранены в: {OUTPUT_FILE_TLD}")

        return sorted_domains

    except Exception as e:
        logging.error(f"Ошибка при сохранении доменов: {e}")
        return False

def convert_domain_to_filename(domain):
    """
    Конвертирует домен в имя файла с обработкой Punycode
    Пример: '.рф' -> 'xn--p1ai', '.aaa' -> 'aaa'
    """
    try:
        # Удаление точки в начале
        domain_name = domain.lstrip('.')

        # Конвертация в Punycode (для IDN доменов)
        try:
            if any(ord(char) > 127 for char in domain_name):
                punycode_domain = idna.encode(domain_name).decode('ascii')
                logging.debug(f"Конвертирован IDN домен: '{domain_name}' -> '{punycode_domain}'")
                return punycode_domain
            else:
                return domain_name
        except idna.IDNAError as e:
            logging.warning(f"Ошибка конвертации IDN домена '{domain_name}': {e}. Используем оригинальное имя.")
            return domain_name

    except Exception as e:
        logging.error(f"Ошибка при конвертации домена '{domain}' в имя файла: {e}")
        return domain.lstrip('.')

def create_yaml_templates(domains):
    """
    Создает YAML шаблон для каждого домена
    Создает только те файлы, которых еще нет в целевой директории
    """
    try:
        if not domains or not isinstance(domains, list):
            logging.error(f"Некорректный список доменов для создания YAML: {domains}")
            return False

        # Создание директории для YAML файлов, если отсутствует
        yaml_dir = Path(TEMPLATE_DIR_YAML)
        yaml_dir.mkdir(parents=True, exist_ok=True)
        logging.info(f"Директория для YAML шаблонов: {yaml_dir.absolute()}")

        created_count = 0
        skipped_count = 0
        error_count = 0

        for domain in domains:
            try:
                # Конвертируем домен в имя файла
                filename = convert_domain_to_filename(domain)
                yaml_file_path = yaml_dir / f"{filename}.yaml"

                # Создаем файл только если он не существует
                if not yaml_file_path.exists():
                    # Создаем структуру данных для YAML
                    yaml_data = {
                        'target_domains': [domain]
                    }

                    # Записываем в YAML файл
                    with open(yaml_file_path, 'w', encoding='utf-8') as f:
                        yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True, indent=2)

                    created_count += 1
                    logging.debug(f"Создан YAML файл: {yaml_file_path.name}")
                else:
                    skipped_count += 1
                    logging.debug(f"YAML файл уже существует, пропускаем: {yaml_file_path.name}")

            except Exception as e:
                error_count += 1
                logging.error(f"Ошибка при создании YAML для домена '{domain}': {e}")

        logging.info(f"YAML шаблонов: создано {created_count}, пропущено {skipped_count}, ошибок {error_count}")

        if error_count > 0:
            logging.warning(f"При создании YAML файлов возникло {error_count} ошибок")
            return False
        return True

    except Exception as e:
        logging.error(f"Критическая ошибка при создании YAML файлов: {e}")
        return False

def main():
    """Основная функция скрипта"""
    logging.info("\n=== Запуск %s - скрипт получения и парсинга TLD доменов ===", script_name)

    success = True

    # Скачивание HTML файла
    if not download_html_file():
        logging.error("Не удалось скачать файл.")
        return

    # Читаем содержимое файла
    try:
        with open(INPUT_FILE_TLD, 'r', encoding='utf-8') as f:
            html_content = f.read()
        logging.info(f"Файл прочитан успешно: {INPUT_FILE_TLD}")
    except Exception as e:
        logging.error(f"Ошибка при чтении файла: {e}")
        success = False
        return

    # Парсинг доменов
    domains = parse_tld_domains(html_content)

    if not domains:
        logging.error("Не удалось извлечь домены из файла")
        success = False
        return

    # Сохраняет домены инкрементально
    saved_domains = save_domains_incrementally(domains)

    if saved_domains:
        # Генерация YAML шаблонов
        logging.info("Генерация YAML шаблонов")
        yaml_success = create_yaml_templates(saved_domains)

        if yaml_success:
            logging.info("YAML шаблоны успешно созданы")
        else:
            logging.debug("Возникли ошибки при генерации YAML шаблонов")
            success = False
    else:
        logging.error("Не удалось сохранить домены в файл")
        success = False

    if success:
        logging.info("Скрипт tld_parser успешно завершил работу")
    else:
        logging.error("Скрипт tld_parser завершил работу с ошибками")
        sys.exit(1)

if __name__ == "__main__":
    main()
