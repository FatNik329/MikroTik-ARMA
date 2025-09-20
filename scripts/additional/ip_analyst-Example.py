import ipaddress
import json
import logging
import os
import yaml
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime, timedelta

# Настройки скрипта
CONFIG = {
    # Пути к файлам
    'ip_list_dir': 'raw-data/list-IPServices',                          # Директория с исходными IP-адресами
    'dns_file_filter': 'raw-data/list-Domain/DNS/results-dns.yaml',      # Файл с DNS записями
    'asn_file_filter': 'raw-data/list-PrefixAS/AS/results-as.json',       # Файл с ASN префиксами
    'output_dir': 'output-data/list-IPServices/Custom',                 # Кастомная директория для сохранения .rsc файла

    # Дополнительные параметры и фильтры
    'prefix_threshold': 3,  # Минимальное количество IP в префиксе для его добавления
    'asn_filter': ['AS12345', 'AS23456', 'AS34567'],  # Пример: определённые ASN ['AS12345', 'AS23456']. Без фильтрации: None
    'remove_last_seen': 7,  # Исключать IP, которые не появлялись более N дней (поддерживает ТОЛЬКО дни). Без фильтрации: None
}

# Автоматическое определение имени лог файла
# Получение имени скрипта без расширения .py
script_name = Path(__file__).stem  # Например: "ip_analyst-list-IPServices"
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

def filter_as_data(as_data: Dict[str, List[ipaddress.IPv4Network]],
                  asn_filter: Optional[List[str]]) -> Dict[str, List[ipaddress.IPv4Network]]:
    """
    Фильтрует данные AS по заданному списку ASN номеров.
    Если asn_filter is None - возвращает исходные данные без фильтрации.
    """
    if asn_filter is None:
        return as_data

    filtered_data = {}
    missing_asns = set(asn_filter)  # Проверка отсутствующих ASN

    for asn in asn_filter:
        if asn in as_data:
            filtered_data[asn] = as_data[asn]
            missing_asns.discard(asn)
        else:
            logging.warning(f"ASN {asn} из фильтра не найдена в данных AS")

    if missing_asns:
        logging.warning(f"Следующие ASN из фильтра отсутствуют в данных: {sorted(missing_asns)}")

    if not filtered_data:
        raise ValueError("Ни одна ASN из фильтра не найдена в данных. Проверьте настройки.")

    logging.info(f"Применён фильтр ASN: осталось {len(filtered_data)} AS из {len(asn_filter)} запрошенных")
    return filtered_data

def load_dns_ips(file_path: str) -> Set[str]:
    """Загружает все IPv4 адреса из YAML файла с DNS записями"""
    try:
        abs_path = validate_file_path(file_path, "DNS YAML файл")
        with open(abs_path, 'r') as f:
            data = yaml.safe_load(f)

        ip_set = set()

        categories = data.get('categories', {})
        for category in categories.values():
            for domain_data in category.values():
                ipv4_list = domain_data.get('ipv4', [])
                ip_set.update(ipv4_list)

        return ip_set
    except Exception as e:
        logging.error(f"Ошибка загрузки DNS YAML файла: {e}")
        raise

def prepare_as_data(as_data: Dict[str, List[str]]) -> Dict[str, List[ipaddress.IPv4Network]]:
    """Подготавливает данные AS: преобразует префиксы в IPv4Network и сортирует"""
    prepared = {}
    for asn, prefixes in as_data.items():
        # Конвертирорование и сортировка префиксов по длине маски (от больших к меньшим)
        networks = []
        for prefix in prefixes:
            try:
                networks.append(ipaddress.IPv4Network(prefix, strict=False))
            except ValueError as e:
                logging.warning(f"Неверный префикс {prefix} в AS {asn}: {e}")

        # Сортировка по длине префикса (от /32 к /0)
        networks.sort(key=lambda x: x.prefixlen, reverse=True)
        prepared[asn] = networks

    return prepared

def load_as_prefixes(file_path: str, asn_filter: Optional[List[str]] = None) -> Dict[str, List[ipaddress.IPv4Network]]:
    """Загружает и подготавливает префиксы AS из JSON файла с опциональной фильтрацией"""
    try:
        abs_path = validate_file_path(file_path, "AS JSON файл")
        with open(abs_path, 'r') as f:
            data = json.load(f)

        as_data = {}
        for asn, as_info in data.get('as_data', {}).items():
            prefixes = as_info.get('prefixes_v4', [])
            if prefixes:
                as_data[asn] = prefixes

        # Подготавливает данные (конвертируем в IPv4Network)
        prepared_data = prepare_as_data(as_data)

        # Применят фильтр если указан
        if asn_filter is not None:
            prepared_data = filter_as_data(prepared_data, asn_filter)

        return prepared_data

    except Exception as e:
        logging.error(f"Ошибка загрузки AS JSON файла: {e}")
        raise

def find_matching_asn(ip: str, as_data: Dict[str, List[ipaddress.IPv4Network]]) -> Optional[Tuple[str, ipaddress.IPv4Network]]:
    """Находит ASN и префикс для заданного IP-адреса"""
    try:
        ip_obj = ipaddress.IPv4Address(ip)

        for asn, networks in as_data.items():
            for network in networks:
                if ip_obj in network:
                    return (asn, network)

        return None
    except Exception as e:
        logging.error(f"Ошибка проверки IP {ip} в AS префиксах: {e}")
        return None

def process_ips(ips: List[str],
                as_data: Dict[str, List[ipaddress.IPv4Network]],
                asn_filter: Optional[List[str]] = None) -> Tuple[Dict[Tuple[str, ipaddress.IPv4Network], List[str]], List[str]]:
    """
    Обрабатывает IP-адреса, возвращает:
    - словарь {(asn, префикс): [список IP]}
    - список IP без найденных префиксов (только если фильтр отключен)
    """
    prefix_ip_map = defaultdict(list)
    no_prefix_ips = []
    filtered_count = 0

    for ip in ips:
        match = find_matching_asn(ip, as_data)
        if match:
            asn, prefix = match
            # Если фильтр активен, добавляем IP только если ASN в фильтре
            if asn_filter is None or asn in asn_filter:
                prefix_ip_map[(asn, prefix)].append(ip)
            # Если фильтр активен и ASN не в фильтре - пропускает этот IP
            else:
                continue
        else:
            # IP без префиксов добавляет только если фильтр отключен
            if asn_filter is None:
                no_prefix_ips.append(ip)

    if asn_filter is not None and filtered_count > 0:
        logging.info(f"Отфильтровано {filtered_count} IP, не принадлежащих указанным ASN")

    return prefix_ip_map, no_prefix_ips

def generate_rsc_content(prefix_ip_map: Dict[Tuple[str, ipaddress.IPv4Network], List[str]],
                        no_prefix_ips: List[str],
                        list_name: str) -> str:
    """Генерирует содержимое .rsc файла"""
    lines = ['/ip firewall address-list']
    threshold = CONFIG['prefix_threshold']

    # Добавляет префиксы, которые встречаются >= threshold раз
    for (asn, prefix), ips in prefix_ip_map.items():
        if len(ips) >= threshold:
            lines.append(
                f'add address={prefix} list={list_name} '
                f'comment="{asn} -> IP={len(ips)}"'
            )
        else:
            for ip in ips:
                lines.append(
                    f'add address={ip} list={list_name} '
                    f'comment="{asn} -> {prefix}"'
                )

    # Добавляет IP без префиксов
    for ip in no_prefix_ips:
        lines.append(f'add address={ip} list={list_name}')

    return '\n'.join(lines)

def generate_rsc_file(prefix_ip_map: Dict[Tuple[str, ipaddress.IPv4Network], List[str]],
                     no_prefix_ips: List[str],
                     output_path: str,
                     list_name: str):
    """Генерирует .rsc файл для MikroTik"""
    try:
        output_dir = os.path.dirname(output_path)
        validate_directory(output_dir, "Выходная директория")

        content = generate_rsc_content(prefix_ip_map, no_prefix_ips, list_name)

        with open(output_path, 'w') as f:
            f.write(content)

        logging.info(f"Файл {output_path} успешно создан")
    except Exception as e:
        logging.error(f"Ошибка создания .rsc файла: {e}")
        raise

def main():
    logging.info("\n=== Запуск %s - генератор RSC с фильтрацией ===", script_name)

    try:
        # Валидация путей
        ip_list_dir = CONFIG['ip_list_dir']
        dns_yaml_path = CONFIG['dns_file_filter']
        as_json_path = CONFIG['asn_file_filter']
        output_dir = CONFIG['output_dir']
        remove_last_seen = CONFIG.get('remove_last_seen')

        logging.info(f"Используемые пути и параметры:\n"
                    f"- Директория с IP списками: {ip_list_dir}\n"
                    f"- DNS фильтр (исключает адреса): {dns_yaml_path}\n"
                    f"- ASN фильтр (входящие префиксы): {as_json_path}\n"
                    f"- Выходная директория данных: {output_dir}\n"
                    f"- Фильтр ASN: {CONFIG.get('asn_filter', 'Отключен')}\n"
                    f"- Фильтр по времени: {f'{remove_last_seen} дней' if remove_last_seen is not None else 'Отключен'}")

        # Загрузка данных
        logging.info("Загрузка исходных IP-адресов из всех TXT и JSON файлов...")
        dir_name, all_source_ips = load_ip_lists_from_dir(ip_list_dir)

        if not all_source_ips:
            logging.warning("Нет IP-адресов для обработки")
            return

        logging.info(f"Всего загружено IP-адресов из всех файлов: {len(all_source_ips)}")

        logging.info("Загрузка DNS записей...")
        dns_ips = load_dns_ips(dns_yaml_path)

        logging.info("Загрузка и подготовка AS префиксов...")
        as_data = load_as_prefixes(as_json_path, CONFIG.get('asn_filter'))

        # Если после фильтрации данных нет - выход
        if not as_data:
            logging.error("Нет данных AS для обработки после применения фильтра")
            return

        # Поиск уникальных IP (объединённых из всех файлов)
        unique_ips = all_source_ips - dns_ips
        logging.info(f"Найдено {len(unique_ips)} уникальных IP-адресов")

        if not unique_ips:
            logging.warning("Нет уникальных IP-адресов для обработки")
            return

        # Обработка IP
        logging.info("Обработка IP-адресов...")
        prefix_ip_map, no_prefix_ips = process_ips(sorted(unique_ips), as_data, CONFIG.get('asn_filter'))

        # Статистика
        total_with_prefix = sum(len(ips) for ips in prefix_ip_map.values())
        common_prefixes = sum(1 for ips in prefix_ip_map.values() if len(ips) >= CONFIG['prefix_threshold'])

        logging.info(
            f"Итоговая статистика:\n"
            f"- IP с найденными префиксами: {total_with_prefix}\n"
            f"- IP без найденных префиксов: {len(no_prefix_ips)}\n"
            f"- Префиксов для агрегации (>= {CONFIG['prefix_threshold']} IP): {common_prefixes}"
        )

        # Информация о фильтрации
        if CONFIG.get('asn_filter') is not None:
            total_processed = total_with_prefix + len(no_prefix_ips)
            logging.info(
                f"Фильтрация ASN активна: добавлены только данные из {CONFIG['asn_filter']}\n"
                f"- Обработано IP всего (из всех файлов): {len(unique_ips)}\n"
                f"- Соответствует фильтру (включены в итоговый результат): {total_processed}\n"
                f"- Отфильтровано (исключены из итогового результата): {len(unique_ips) - total_processed}"
            )

        # Подготовка имени выходного файла (на основе имени директории)
        output_filename = f"{dir_name}-ipv4.rsc"
        output_path = os.path.join(validate_directory(output_dir, "Выходная директория"), output_filename)

        # Генерация выходного .rsc файла
        logging.info(f"Создание файла {output_filename}...")
        generate_rsc_file(prefix_ip_map, no_prefix_ips, output_path, dir_name)

        logging.info("=== Скрипт ip_analyst успешно завершен ===")

    except Exception as e:
        logging.error(f"Критическая ошибка: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    main()
