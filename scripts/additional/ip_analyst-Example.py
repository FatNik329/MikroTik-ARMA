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
    'ip_list_dir': ['raw-data/list-IPServices']  # Директория с исходными IP-адресами.  # Может быть строкой или списком ['путь1', 'путь2']
    'dns_file_filter': 'none', # Файл с DNS записями (исключает совпадения). Опциональный параметр, для отключения 'none'. Для включения указать путь до файла results-dns.yaml '/path/to/results-dns.yaml'
    'asn_db_file': 'raw-data/ASN-db/ip-to-asn.mmdb', # Файл MMDB база - IPLocate
    'output_dir': 'output-data/list-IPServices/Custom', # Кастомная директория для сохранения .rsc файла

    # Имя выходного файла
    'output_filename': 'MyListResource',  # Определяет имя файла и имя листа в RSC. none - используется комбинированное имя всех исходных файлов

    # Дополнительные параметры и фильтры
    'prefix_threshold': 2,  # Минимальное количество IP в префиксе для его добавления
    'asn_filter': 'none',  # Пример: определённые ASN ['AS8075', 'AS15169', 'AS32934']. Без фильтрации: none
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

def load_ip_lists_from_paths(paths_input) -> Tuple[str, Set[str]]:
    """
    Загружает все TXT и JSON файлы из указанных путей.
    Возвращает:
    - имя для использования (или из output_filename или объединенное)
    - объединённое множество всех IP
    """
    all_ips = set()
    days_threshold = CONFIG.get('remove_last_seen')

    if isinstance(paths_input, str):
        paths = [paths_input]
    else:
        paths = paths_input

    # Фильтрация по времени
    threshold_date = None
    if days_threshold is not None:
        threshold_date = datetime.now() - timedelta(days=days_threshold)
        logging.info(f"Применена фильтрация по времени: исключаются IP старше {days_threshold} дней")

    # Обработка каждого пути
    processed_paths = []
    for path in paths:
        try:
            abs_path = validate_directory(path, "Директория с IP-списками")
            processed_paths.append(abs_path)

            for filename in os.listdir(abs_path):
                file_path = os.path.join(abs_path, filename)

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

                else:
                    continue

        except Exception as e:
            logging.error(f"Ошибка загрузки из пути {path}: {e}")
            continue

    if not all_ips:
        logging.warning(f"Не найдено IP-адресов в указанных путях")

    # Определяем имя для использования
    # Если указано несколько путей, создаем объединенное имя
    if len(processed_paths) > 1:
        dir_names = [os.path.basename(p) for p in processed_paths]
        combined_name = "_".join(dir_names)
        logging.info(f"Объединено {len(processed_paths)} директорий: {combined_name}")
        return combined_name, all_ips
    else:
        dir_name = os.path.basename(processed_paths[0])
        return dir_name, all_ips

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
) -> Tuple[Dict[Tuple[str, str, str], Dict[str, Any]], List[str], Dict[str, int]]:
    """
    Обрабатывает IP-адреса с использованием MMDB базы.
    Возвращает:
    - словарь {(asn, org, country): {'prefixes': Dict[префикс: List[IP]], 'total_ips': int}}
      (ТОЛЬКО IP, прошедшие фильтры)
    - список IP без найденной ASN информации
    - словарь с подсчетом IP по ASN {asn: count} (ВСЕ IP, независимо от фильтров)
    """
    asn_group_map = defaultdict(lambda: {'prefixes': defaultdict(list), 'total_ips': 0})
    no_asn_ips = []
    asn_counter_all = defaultdict(int)

    for ip in ips:
        asn_info = get_asn_info(ip, mmdb_reader)

        if not isinstance(asn_info, dict):
            no_asn_ips.append(ip)
            asn_counter_all['ASUNKNOWN'] += 1
            continue

        asn = asn_info['asn']
        country = asn_info['country']

        asn_counter_all[asn] += 1

        skip_filtered = False

        if asn_filter:
            if asn not in asn_filter:
                skip_filtered = True

        # Включен фильтр по стране
        if country_filter:
            if country not in country_filter:
                skip_filtered = True

        # Если IP не проходит фильтры, пропускаем его для asn_group_map
        if skip_filtered:
            continue

        # Определяем префикс (/24 для IPv4)
        ip_obj = ipaddress.IPv4Address(ip)
        prefix = ipaddress.IPv4Network(f"{ip_obj}/24", strict=False)

        # Группируем по ASN, Org, Country (только IP, прошедшие фильтры)
        key = (asn_info['asn'], asn_info['org'], asn_info['country'])
        asn_group_map[key]['prefixes'][prefix].append(ip)
        asn_group_map[key]['total_ips'] += 1

    return dict(asn_group_map), no_asn_ips, dict(asn_counter_all)

def get_asn_info_from_map(
    asn: str,
    asn_group_map: Dict[Tuple[str, str, str], Dict[str, Any]]
) -> Tuple[str, str]:
    """
    Находит организацию и страну для ASN в asn_group_map
    Возвращает (org, country) или ("Unknown", "XX") если не найдено
    """
    for (map_asn, org, country), _ in asn_group_map.items():
        if map_asn == asn:
            return org, country
    return "Unknown", "XX"

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

def print_detailed_asn_statistics(
    asn_counter_all: Dict[str, int],
    asn_group_map: Dict[Tuple[str, str, str], Dict[str, Any]],
    total_ips_processed: int,
    asn_filter: Optional[List[str]] = None
) -> None:
    """
    Выводит детальную статистику по ASN с количеством и процентами
    в формате: {ASN}:{Организация}:{Страна} -> {Количество} (%)
    Использует ВСЕ IP (asn_counter_all), не только отфильтрованные
    """
    if not asn_counter_all:
        logging.info("Нет данных по ASN для статистики")
        return

    logging.info("\n=== ДЕТАЛЬНАЯ СТАТИСТИКА ПО ASN ===")

    # Создаем список для сортировки с информацией об организации и стране
    stats_list = []
    total_counted_ips = 0

    for asn, count in asn_counter_all.items():
        if asn == 'ASUNKNOWN':
            org, country = "Unknown", "XX"
        else:
            org, country = get_asn_info_from_map(asn, asn_group_map)
        stats_list.append((asn, org, country, count))
        total_counted_ips += count

    # Сортируем по количеству IP
    stats_list.sort(key=lambda x: x[3], reverse=True)

    # Фильтруем только указанные ASN, если фильтр активен
    if asn_filter:
        stats_list = [(asn, org, country, count) for asn, org, country, count in stats_list if asn in asn_filter]
        logging.info(f"Показаны только ASN из фильтра ({len(asn_filter)} шт.):")

    # Выводим статистику
    total_shown = sum(count for _, _, _, count in stats_list)

    for asn, org, country, count in stats_list:
        percentage = (count / total_ips_processed) * 100 if total_ips_processed > 0 else 0
        # Очистка названия организации для вывода
        org_short = org[:50] + "..." if len(org) > 50 else org
        logging.info(f"  {asn}:{org_short}:{country} -> {count} IP ({percentage:.2f}%)")

    # Если есть ASN не показанные из-за фильтра
    if asn_filter and total_shown < total_ips_processed:
        other_count = total_ips_processed - total_shown
        other_percentage = (other_count / total_ips_processed) * 100
        logging.info(f"  Остальные ASN: {other_count} IP ({other_percentage:.2f}%)")

    logging.info(f"Всего обработано IP: {total_ips_processed}")
    logging.info(f"Всего учтено в статистике ASN: {total_counted_ips} IP")

def print_geo_statistics(
    asn_counter_all: Dict[str, int],
    asn_group_map: Dict[Tuple[str, str, str], Dict[str, Any]],
    total_ips_processed: int
) -> None:
    """
    Выводит статистику по геолокациям (странам) на основе ВСЕХ IP
    """
    if not asn_counter_all:
        return


    country_stats = defaultdict(lambda: {'asn_set': set(), 'ip_count': 0})


    for asn, count in asn_counter_all.items():
        if asn == 'ASUNKNOWN':
            country = 'XX'
            org = 'Unknown'
        else:

            org, country = get_asn_info_from_map(asn, asn_group_map)

        country_stats[country]['asn_set'].add(asn)
        country_stats[country]['ip_count'] += count

    if not country_stats:
        return

    logging.info("\n=== ДЕТАЛЬНАЯ СТАТИСТИКА ASN GEO ===")

    # Преобразуем sets в counts
    for country in country_stats:
        country_stats[country]['asn_count'] = len(country_stats[country]['asn_set'])

    # Сортируем по количеству IP (по убыванию)
    sorted_countries = sorted(
        country_stats.items(),
        key=lambda x: x[1]['ip_count'],
        reverse=True
    )

    for country, stats in sorted_countries:
        ip_percentage = (stats['ip_count'] / total_ips_processed) * 100 if total_ips_processed > 0 else 0
        # Процент ASN от общего количества уникальных ASN
        total_unique_asn = len(asn_counter_all) - (1 if 'ASUNKNOWN' in asn_counter_all else 0)
        asn_percentage = (stats['asn_count'] / total_unique_asn) * 100 if total_unique_asn > 0 else 0

        logging.info(
            f"  {country}: {stats['asn_count']} ASN "
            f"({stats['ip_count']} IP, {ip_percentage:.1f}% от IP) "
            f"[{asn_percentage:.1f}% от ASN]"
        )

    logging.info(f"Всего стран: {len(country_stats)}")
    logging.info(f"Всего уникальных ASN: {total_unique_asn}")

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
        output_filename_config = CONFIG.get('output_filename')

        # Имя выходного файла
        output_filename_config = CONFIG.get('output_filename')

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

        ip_dirs_str = ip_list_dir if isinstance(ip_list_dir, str) else ', '.join(ip_list_dir)
        logging.info(f"Используемые пути и параметры:\n"
                    f"- Директории с IP списками: {ip_dirs_str}\n"
                    f"- DNS фильтр: {'Отключен' if dns_yaml_path.lower() == 'none' else dns_yaml_path}\n"
                    f"- ASN MMDB база: {as_mmdb_path}\n"
                    f"- Выходная директория: {output_dir}\n"
                    f"- Имя выходного файла/листа: {output_filename_config if output_filename_config != 'none' else 'По имени директории'}\n"
                    f"- Фильтр ASN: {asn_filter if asn_filter else 'Отключен'}\n"
                    f"- Фильтр стран: {country_filter if country_filter else 'Отключен'}\n"
                    f"- Фильтр по времени: {f'{remove_last_seen} дней' if remove_last_seen is not None else 'Отключен'}")

        # Загрузка данных из одного или нескольких путей
        logging.info("Загрузка исходных IP-адресов...")
        dir_name, all_source_ips = load_ip_lists_from_paths(ip_list_dir)

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
        asn_group_map, no_asn_ips, asn_counter = process_ips_with_mmdb(
            sorted(unique_ips),
            mmdb_reader,
            asn_filter,
            country_filter
        )

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

        # Вызов функций статистики:
        print_detailed_asn_statistics(
            asn_counter_all=asn_counter,
            asn_group_map=asn_group_map,
            total_ips_processed=len(unique_ips),
            asn_filter=asn_filter
        )

        print_geo_statistics(
            asn_counter_all=asn_counter,
            asn_group_map=asn_group_map,
            total_ips_processed=len(unique_ips)
        )

        if output_filename_config and output_filename_config.lower() != 'none':
            # Использовать заданное имя из конфига для файла И для листа
            list_name = output_filename_config
            output_filename_base = output_filename_config
        else:
            # Использовать автоматически определенное имя
            list_name = dir_name
            output_filename_base = dir_name

        # Подготовка выходного файла
        output_filename = f"{output_filename_base}-ipv4.rsc"
        output_path = os.path.join(validate_directory(output_dir, "Выходная директория"), output_filename)

        logging.info(f"Имя листа в RSC: {list_name}")
        logging.info(f"Имя выходного файла: {output_filename}")

        logging.info(f"Создание файла {output_filename} с листом '{list_name}'...")
        content = generate_rsc_content_mmdb(asn_group_map, no_asn_ips, list_name)

        mmdb_reader.close()

        with open(output_path, 'w') as f:
            f.write(content)

        logging.info(f"Файл {output_path} успешно создан")
        logging.info("=== Скрипт успешно завершен ===")

    except Exception as e:
        logging.error(f"Критическая ошибка: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
