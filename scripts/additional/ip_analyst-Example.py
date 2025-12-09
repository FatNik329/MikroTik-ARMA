import ipaddress
import json
import logging
import os
import yaml
import maxminddb
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime, timedelta

# Настройки скрипта
CONFIG = {
    # Пути к файлам
    'ip_list_dir': 'raw-data/list-IPServices',             # Директория с исходными IP-адресами. На основании имени директории формируется имя выходного RSC файла.
    'dns_file_filter': 'none',                             # Файл с DNS записями (исключает совпадения). Опциональный параметр, для отключения 'none'. Для включения указать путь до файла results-dns.yaml '/path/to/results-dns.yaml'
    'asn_db_file': 'raw-data/ASN-db/ip-to-asn.mmdb',       # Файл MMDB база - IPLocate
    'output_dir': 'output-data/list-IPServices/Custom',    # Кастомная директория для сохранения .rsc файла

    # Дополнительные параметры и фильтры
    'prefix_threshold': 2,  # Минимальное количество IP в префиксе для его добавления
    'asn_filter': 'none',  # Пример: определённые ASN ['AS8075', 'AS15169', 'AS32934']. Без фильтрации: one
    'country_filter': 'none', # Пример: фильтрация на основе кода страны ['US', 'FR', 'RU', ...]. Без фильтраации: none
    'remove_last_seen': 20,  # Исключать IP, которые не появлялись более N дней (поддерживает ТОЛЬКО целые числа - дни). Без фильтрации: None
}

# Автоматическое определение имени лог файла
# Получение имени скрипта без расширения .py
script_name = Path(__file__).stem
log_filename = f"{script_name}.log"

# Создание директории в logs (автоматическое имя из названия скрипта)
log_path = Path(f'logs/additional/ip_analyst/{log_filename}')
log_path.parent.mkdir(parents=True, exist_ok=True)

# Настройка логирования (имеется DEBUG)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)

def validate_file_path(file_path: str, file_description: str) -> str:
    """Проверяет существование файла и возвращает абсолютный путь"""
    if not os.path.isabs(file_path):
        file_path = os.path.abspath(file_path)

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_description} не найден: {file_path}")

    return file_path

def validate_directory(dir_path: str, dir_description: str) -> str:
    """Проверяет существование директории и возвращает абсолютный путь"""
    if not os.path.isabs(dir_path):
        dir_path = os.path.abspath(dir_path)

    if not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)
        logging.info(f"Создана директория {dir_description}: {dir_path}")
    elif not os.path.isdir(dir_path):
        raise NotADirectoryError(f"{dir_description} не является директорией: {dir_path}")

    return dir_path

def load_ip_lists_from_dir(dir_path: str) -> Tuple[str, Set[str]]:
    """
    Загружает все TXT и JSON файлы из директории и возвращает:
    - имя директории (для названия выходного файла)
    - объединённое множество всех IP (с учётом фильтрации по времени)
    """
    try:
        abs_dir = validate_directory(dir_path, "Директория с IP-списками")
        all_ips = set()
        days_threshold = CONFIG.get('remove_last_seen')

        # Если включена фильтрация по времени, вычисляет пороговую дату
        threshold_date = None
        if days_threshold is not None:
            from datetime import datetime, timedelta
            threshold_date = datetime.now() - timedelta(days=days_threshold)
            logging.info(f"Применена фильтрация по времени: исключаются IP старше {days_threshold} дней (до {threshold_date.strftime('%Y-%m-%d')})")

        for filename in os.listdir(abs_dir):
            file_path = os.path.join(abs_dir, filename)

            # Обработка TXT файлов
            if filename.endswith('.txt'):
                try:
                    with open(file_path, 'r') as f:
                        ips = {line.strip() for line in f if line.strip()}
                        all_ips.update(ips)
                        logging.info(f"Загружен TXT файл {filename}: {len(ips)} IP-адресов")
                except Exception as e:
                    logging.error(f"Ошибка загрузки TXT файла {filename}: {e}")
                    continue

            # Обработка JSON файлов
            elif filename.endswith('.json'):
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)

                    # Извлечение IP адреса из структуры JSON
                    addresses = data.get('addresses', {})

                    if days_threshold is not None:
                        # Фильтрация IP по времени last_seen
                        filtered_ips = set()
                        for ip, ip_data in addresses.items():
                            last_seen_str = ip_data.get('last_seen')
                            if last_seen_str:
                                try:
                                    last_seen_date = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
                                    if last_seen_date >= threshold_date:
                                        filtered_ips.add(ip)
                                except ValueError:
                                    filtered_ips.add(ip)
                            else:
                                filtered_ips.add(ip)

                        all_ips.update(filtered_ips)
                        logging.info(f"Загружен JSON файл {filename}: {len(filtered_ips)} IP-адресов (после фильтрации по времени)")

                    else:
                        # Без фильтрации по времени - берёт все IP
                        ips_from_json = set(addresses.keys())
                        all_ips.update(ips_from_json)
                        logging.info(f"Загружен JSON файл {filename}: {len(ips_from_json)} IP-адресов")

                except Exception as e:
                    logging.error(f"Ошибка загрузки JSON файла {filename}: {e}")
                    continue

        if not all_ips:
            logging.warning(f"В директории {abs_dir} не найдено IP-адресов в TXT или JSON файлах")

        # Возвращаем имя директории и все IP
        dir_name = os.path.basename(abs_dir)
        return dir_name, all_ips

    except Exception as e:
        logging.error(f"Ошибка загрузки IP-списков из директории: {e}")
        raise

def load_dns_ips(file_path: str) -> Set[str]:
    """Загружает все IPv4 адреса из YAML файла с DNS записями (новая структура)"""
    if file_path.lower() == 'none':
        logging.info("DNS фильтрация отключена (установлено 'none')")
        return set()

    try:
        abs_path = validate_file_path(file_path, "DNS YAML файл")
        with open(abs_path, 'r') as f:
            data = yaml.safe_load(f)

        ip_set = set()
        total_loaded = 0

        categories = data.get('categories', {})
        logging.debug(f"Найдено категорий DNS: {len(categories)}")

        for category_name, category in categories.items():
            category_count = 0
            for domain, domain_data in category.items():
                ipv4_data = domain_data.get('ipv4', {})
                historical_ips = ipv4_data.get('historical', {})

                # Берем только ключи (IP-адреса) из historical
                if historical_ips:
                    ip_set.update(historical_ips.keys())
                    category_count += len(historical_ips)

            logging.debug(f"Категория '{category_name}': {category_count} IP-адресов")
            total_loaded += category_count

        logging.info(f"Всего загружено DNS IP-адресов из historical: {total_loaded}")
        logging.info(f"Уникальных DNS IP-адресов: {len(ip_set)}")

        # Дополнительная диагностика - примеры загруженных IP
        if ip_set:
            sample_ips = list(ip_set)[:5]
            logging.debug(f"Примеры загруженных DNS IP: {sample_ips}")

        return ip_set

    except Exception as e:
        logging.error(f"Ошибка загрузки DNS YAML файла: {e}")
        raise

def load_asn_mmdb(file_path: str) -> maxminddb.Reader:
    """Загружает MMDB базу данных ASN"""
    try:
        abs_path = validate_file_path(file_path, "ASN MMDB файл")
        reader = maxminddb.open_database(abs_path)
        logging.info(f"MMDB база ASN загружена: {abs_path}")
        return reader
    except Exception as e:
        logging.error(f"Ошибка загрузки MMDB файла: {e}")
        raise

def get_asn_info(ip: str, mmdb_reader: maxminddb.Reader) -> Optional[Dict[str, Any]]:
    """
    Получает информацию об ASN для IP из MMDB базы.
    Возвращает словарь с ключами: 'asn', 'org', 'country'
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        if ip_obj.is_private:
            # Для приватных IP возвращает метку
            return {
                'asn': 'ASPRIVATE',
                'org': 'Private Network',
                'country': 'XX'
            }

        # Запрос к MMDB базе
        result = mmdb_reader.get(ip_obj.compressed)

        if not result:
            # Если в MMDB не нашлась информация
            logging.debug(f"Для публичного IP {ip} не найдена информация в MMDB")
            return {
                'asn': 'ASUNKNOWN',
                'org': 'Unknown',
                'country': 'XX'
            }

        # Ключи для ip-to-asn.mmdb
        asn_info = {
            'asn': result.get('asn', 'ASUNKNOWN'),
            'org': result.get('org', 'Unknown'),
            'country': result.get('country_code', 'XX')
        }

        # Если ASN не начинается с "AS", добавляет префикс
        if asn_info['asn'] != 'ASUNKNOWN' and not asn_info['asn'].startswith('AS'):
            asn_info['asn'] = f"AS{asn_info['asn']}"

        # Форматирование названия организации
        if ',' in asn_info['org']:
            asn_info['org'] = asn_info['org'].split(',')[0]

        return asn_info

    except Exception as e:
        logging.debug(f"Ошибка получения ASN для IP {ip}: {e}")
        return {
            'asn': 'ASUNKNOWN',
            'org': 'Unknown',
            'country': 'XX'
        }

def process_ips_with_mmdb(
    ips: List[str],
    mmdb_reader: maxminddb.Reader,
    asn_filter: Optional[List[str]] = None,
    country_filter: Optional[List[str]] = None
) -> Tuple[Dict[Tuple[str, str, str], Dict[str, Any]], List[str]]:
    """
    Обрабатывает IP-адреса с использованием MMDB базы.
    Возвращает:
    - словарь {(asn, org, country): {'prefixes': Dict[префикс: List[IP]], 'total_ips': int}}
    - список IP без найденной ASN информации
    """
    asn_group_map = defaultdict(lambda: {'prefixes': defaultdict(list), 'total_ips': 0})
    no_asn_ips = []

    for ip in ips:
        asn_info = get_asn_info(ip, mmdb_reader)

        if not isinstance(asn_info, dict):
            no_asn_ips.append(ip)
            continue

        # Применяет фильтры
        asn = asn_info['asn']
        country = asn_info['country']

        # Включен фильтр ASN
        if asn_filter:
            if asn not in asn_filter:
                continue

        # Включен фильтр по стране
        if country_filter:
            if country not in country_filter:
                continue

        # Определяем префикс (/24 для IPv4)
        ip_obj = ipaddress.IPv4Address(ip)
        prefix = ipaddress.IPv4Network(f"{ip_obj}/24", strict=False)

        # Группируем по ASN, Org, Country
        key = (asn_info['asn'], asn_info['org'], asn_info['country'])
        asn_group_map[key]['prefixes'][prefix].append(ip)
        asn_group_map[key]['total_ips'] += 1

    return dict(asn_group_map), no_asn_ips

def generate_rsc_content_mmdb(
    asn_group_map: Dict[Tuple[str, str, str], Dict[str, Any]],
    no_asn_ips: List[str],
    list_name: str
) -> str:
    """Генерирует содержимое .rsc файла"""
    lines = ['/ip firewall address-list']
    threshold = CONFIG['prefix_threshold']

    # Функция для проверки приватных адресов
    def is_private_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
        except:
            return True

    # Обрабатываем IP с ASN информацией
    for (asn, org, country), data in asn_group_map.items():
        comment_base = f"{asn}:{org}:{country}"

        for prefix, ips in data['prefixes'].items():
            if len(ips) >= threshold:
                # Добавляем префикс
                lines.append(
                    f'add address={prefix} list={list_name} '
                    f'comment="{comment_base} -> IP={len(ips)}"'
                )
            else:
                # Добавляем отдельные IP
                for ip in ips:
                    lines.append(
                        f'add address={ip} list={list_name} '
                        f'comment="{comment_base} -> {prefix}"'
                    )

    private_ip_count = 0
    for ip in no_asn_ips:
        if not is_private_ip(ip):
            lines.append(f'add address={ip} list={list_name}')
        else:
            private_ip_count += 1

    if private_ip_count > 0:
        logging.info(f"Отфильтровано приватных адресов без ASN: {private_ip_count}")

    return '\n'.join(lines)

def main():
    logging.info("\n=== Запуск %s - генератор RSC из MMDB ASN ===", script_name)

    #logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Валидация путей
        ip_list_dir = CONFIG['ip_list_dir']
        dns_yaml_path = CONFIG['dns_file_filter']
        as_mmdb_path = CONFIG['asn_db_file']
        output_dir = CONFIG['output_dir']
        remove_last_seen = CONFIG.get('remove_last_seen')
        country_filter = CONFIG.get('country_filter')

        # ПРЕОБРАЗОВАНИЕ ПАРАМЕТРОВ:
        asn_filter = CONFIG.get('asn_filter')
        if isinstance(asn_filter, str) and asn_filter.lower() == 'none':
            asn_filter = None
        elif isinstance(asn_filter, list) and len(asn_filter) == 0:
            asn_filter = None

        country_filter = CONFIG.get('country_filter')
        if isinstance(country_filter, str) and country_filter.lower() == 'none':
            country_filter = None
        elif isinstance(country_filter, list) and len(country_filter) == 0:
            country_filter = None

        logging.info(f"Используемые пути и параметры:\n"
                    f"- Директория с IP списками: {ip_list_dir}\n"
                    f"- DNS фильтр (исключает адреса): {'Отключен' if dns_yaml_path.lower() == 'none' else dns_yaml_path}\n"
                    f"- ASN MMDB база: {as_mmdb_path}\n"
                    f"- Выходная директория данных: {output_dir}\n"
                    f"- Фильтр ASN: {asn_filter if asn_filter else 'Отключен'}\n"
                    f"- Фильтр стран: {country_filter if country_filter else 'Отключен'}\n"
                    f"- Фильтр по времени: {f'{remove_last_seen} дней' if remove_last_seen is not None else 'Отключен'}")

        # Загрузка данных
        logging.info("Загрузка исходных IP-адресов из всех TXT и JSON файлов...")
        dir_name, all_source_ips = load_ip_lists_from_dir(ip_list_dir)

        if not all_source_ips:
            logging.warning("Нет IP-адресов для обработки")
            return

        logging.info(f"Всего загружено IP-адресов из всех файлов: {len(all_source_ips)}")

        logging.info("Загрузка MMDB базы ASN...")
        mmdb_reader = load_asn_mmdb(as_mmdb_path)

        # Логика фильтрации DNS
        if dns_yaml_path.lower() == 'none':
            logging.info("DNS фильтрация отключена - используются все исходные IP-адреса")
            unique_ips = all_source_ips
        else:
            logging.info("Загрузка DNS записей...")
            dns_ips = load_dns_ips(dns_yaml_path)
            unique_ips = all_source_ips - dns_ips                            # Поиск уникальных IP (объединённых из всех файлов)
            logging.info(f"Найдено {len(unique_ips)} уникальных IP-адресов")

        if not unique_ips:
            logging.warning("Нет уникальных IP-адресов для обработки")
            return

        # Обработка IP с MMDB
        logging.info("Обработка IP-адресов с MMDB...")
        asn_group_map, no_asn_ips = process_ips_with_mmdb(
            sorted(unique_ips),
            mmdb_reader,
            asn_filter,  # Исправленный фильтр
            country_filter  # Исправленный фильтр
        )

        # Закрываем MMDB reader
        mmdb_reader.close()

        # Статистика
        total_with_asn = sum(data['total_ips'] for data in asn_group_map.values())
        common_prefixes = sum(
            1 for data in asn_group_map.values()
            for ips in data['prefixes'].values()
            if len(ips) >= CONFIG['prefix_threshold']
        )

        logging.info(
            f"Итоговая статистика:\n"
            f"- IP с найденной ASN информацией: {total_with_asn}\n"
            f"- IP без ASN информации: {len(no_asn_ips)}\n"
            f"- Уникальных ASN: {len(asn_group_map)}\n"
            f"- Префиксов для агрегации (>= {CONFIG['prefix_threshold']} IP): {common_prefixes}"
        )

        # Подготовка выходного файла
        output_filename = f"{dir_name}-ipv4.rsc"
        output_path = os.path.join(validate_directory(output_dir, "Выходная директория"), output_filename)

        # Генерация выходного .rsc файла
        logging.info(f"Создание файла {output_filename}...")

        content = generate_rsc_content_mmdb(asn_group_map, no_asn_ips, dir_name)

        with open(output_path, 'w') as f:
            f.write(content)

        logging.info(f"Файл {output_path} успешно создан")
        logging.info("=== Скрипт успешно завершен ===")

    except Exception as e:
        logging.error(f"Критическая ошибка: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
