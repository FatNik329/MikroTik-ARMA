import logging
import requests
from pathlib import Path
import re
from urllib.parse import urljoin
import sys
import yaml
import idna

# ========== КОНФИГУРАЦИЯ ==========
INPUT_FILE_TLD = "configs/AddressLists/TLD-ALL-list/Template/tld_database"  # Источник данных (iana.org), файл - создаётся при скачивании
OUTPUT_FILE_TLD = "configs/AddressLists/TLD-ALL-list/Template/tld_domains.txt"   # Выходной TXT файл - создаётся при парсинге
DOWNLOAD_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"  # URL для скачивания TLD
#HTML источник IANA -> https://www.iana.org/domains/root/db
#TXT источник IANA -> https://data.iana.org/TLD/tlds-alpha-by-domain.txt
TEMPLATE_DIR_YAML = "configs/AddressLists/TLD-ALL-list/DNS" # Путь сохранения YAML шаблонов

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

def download_source_file():
    """Скачивает файл с доменами (HTML или TXT)"""
    try:
        logging.info(f"Скачивание файла URL: {DOWNLOAD_URL}")

        response = requests.get(DOWNLOAD_URL, timeout=30)
        response.raise_for_status()

        if DOWNLOAD_URL.endswith('.txt'):
            file_extension = '.txt'
        elif DOWNLOAD_URL.endswith('.html') or 'iana.org/domains/root/db' in DOWNLOAD_URL:
            file_extension = '.html'
        else:
            if response.text.strip().startswith('#'):
                file_extension = '.txt'
            else:
                file_extension = '.html'

        global INPUT_FILE_TLD
        INPUT_FILE_TLD = str(Path(INPUT_FILE_TLD).with_suffix(file_extension))

        # Сохраняет файл
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
    """Парсит содержимое и извлекает список TLD доменов"""
    domains = []

    if DOWNLOAD_URL.endswith('.txt') or html_content.strip().startswith('#'):
        logging.info("Обнаружен текстовый формат данных")
        for line in html_content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Сохраняет в нижнем регистре
                domain = '.' + line.lower()
                domains.append(domain)
                logging.debug(f"Найден домен: {domain}")
    else:
        logging.info("Обнаружен HTML формат данных")
        pattern = r'<span class="domain tld"><a href="[^"]*">(\.?[\w\u0400-\u04FF-]+)</a></span>'
        try:
            matches = re.findall(pattern, html_content)
            for domain in matches:
                if not domain.startswith('.'):
                    domain = '.' + domain
                domains.append(domain)
                logging.debug(f"Найден домен: {domain}")
        except Exception as e:
            logging.error(f"Ошибка при парсинге HTML: {e}")
            return []

    logging.info(f"Всего найдено доменов: {len(domains)}")
    return domains

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
    Конвертирует домен в имя файла
    Возвращает кортеж: (имя_файла, punycode_домен, комментарий)
    """
    try:
        domain_name = domain.lstrip('.')

        # 1. Проверяем, является ли домен уже punycode (начинается с 'xn--')
        if domain_name.lower().startswith('xn--'):
            try:
                # Декодирует punycode обратно в Unicode
                unicode_domain = idna.decode(domain_name.lower())
                # Комментарий с оригинальным Unicode доменом
                comment = f"#.{unicode_domain}"
                logging.debug(f"Декодирован punycode домен: '{domain}' -> '#.{unicode_domain}'")
            except Exception as e:
                comment = f"#{domain}"
                logging.debug(f"Punycode домен (не удалось декодировать): {domain}")

            filename = domain_name.lower()
            return filename, domain, comment

        # 2. Проверка на содержит ли домен не-ASCII символы (кириллицу)
        elif any(ord(char) > 127 for char in domain_name):
            try:
                punycode_domain = idna.encode(domain_name).decode('ascii')
                punycode_with_dot = '.' + punycode_domain
                filename = punycode_domain
                comment = f"#{domain}"
                logging.debug(f"Конвертирован IDN домен: '{domain}' -> '{punycode_with_dot}'")
            except Exception as e:
                logging.warning(f"Ошибка конвертации IDN '{domain}': {e}")
                filename = domain_name
                punycode_with_dot = domain
                comment = f"#{domain}"

            return filename, punycode_with_dot, comment

        # 3. Обычный ASCII домен
        else:
            filename = domain_name
            comment = f"#{domain}"
            return filename, domain, comment

    except Exception as e:
        logging.error(f"Ошибка при обработке домена '{domain}': {e}")
        original = domain if domain.startswith('.') else '.' + domain
        return domain.lstrip('.'), domain, f"#{original}"

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
                # Конвертируем домен (получаем имя файла, punycode версию и комментарий)
                filename, punycode_domain, comment = convert_domain_to_filename(domain)
                yaml_file_path = yaml_dir / f"{filename}.yaml"

                if not yaml_file_path.exists():
                    # Структура данных для YAML
                    yaml_data = {
                        'target_domains': [punycode_domain]  # Всегда сохранять в Punycode
                    }

                    # Генерируем YAML
                    yaml_content = yaml.dump(yaml_data, default_flow_style=False,
                                           allow_unicode=True, indent=2, sort_keys=False)

                    full_content = f"{comment}\n{yaml_content}"

                    with open(yaml_file_path, 'w', encoding='utf-8') as f:
                        f.write(full_content)

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

    # Скачиваем файл
    if not download_source_file():
        logging.error("Не удалось скачать файл.")
        return

    # Читаем содержимое файла
    try:
        with open(INPUT_FILE_TLD, 'r', encoding='utf-8') as f:
            file_content = f.read()
        logging.info(f"Файл прочитан успешно: {INPUT_FILE_TLD}")
    except Exception as e:
        logging.error(f"Ошибка при чтении файла: {e}")
        success = False
        return

    domains = parse_tld_domains(file_content)

    if not domains:
        logging.error("Не удалось извлечь домены из файла")
        success = False
        return

    saved_domains = save_domains_incrementally(domains)

    if saved_domains:
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
        logging.info("Скрипт %s успешно завершил работу", script_name)
    else:
        logging.error("Скрипт %s завершил работу с ошибками", script_name)
        sys.exit(1)

if __name__ == "__main__":
    main()
