"""
Ядро функционала для скриптов ip_analyst-*
Содержит всю общую логику обработки IP и ASN
"""
import ipaddress
import json
import logging
import os
import yaml
import maxminddb
import numpy as np
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime, timedelta

def validate_file_path(file_path: str, file_description: str) -> str:
    """Проверяет существование файла и возвращает абсолютный путь"""
    if not os.path.isabs(file_path):
        file_path = os.path.abspath(file_path)

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_description} не найден: {file_path}")

    return file_path

def validate_directory(dir_path: str, dir_description: str, logger=None) -> str:
    """Проверяет существование директории и возвращает абсолютный путь"""
    if logger is None:
        logger = logging.getLogger(__name__)

    if not os.path.isabs(dir_path):
        dir_path = os.path.abspath(dir_path)

    if not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)
        logger.info(f"Создана директория {dir_description}: {dir_path}")
    elif not os.path.isdir(dir_path):
        raise NotADirectoryError(f"{dir_description} не является директорией: {dir_path}")

    return dir_path

def load_ip_lists_from_paths(paths_input, days_threshold=None, logger=None) -> Tuple[str, Set[str]]:
    """
    Загружает все TXT, JSON и YAML файлы из указанных путей.
    Поддерживаемые форматы:
    - TXT: простой список IP, по одному на строку
    - JSON: структура с 'addresses' и 'last_seen' для каждого IP (генерируется через get_IP_Connections-*.py)
    - YAML/YML: формат results-dns.yaml с разделами categories->ipv4->historical

    Возвращает:
    - имя для использования (или из output_filename или объединенное)
    - объединённое множество всех IP
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    all_ips = set()

    if isinstance(days_threshold, str) and days_threshold.lower() == 'none':
        days_threshold = None
    elif isinstance(days_threshold, int):
        days_threshold = days_threshold
    else:
        days_threshold = None

    if isinstance(paths_input, str):
        paths = [paths_input]
    else:
        paths = paths_input

    # Фильтрация по времени
    threshold_date = None
    if days_threshold is not None:
        threshold_date = datetime.now() - timedelta(days=days_threshold)
        logger.info(f"Применена фильтрация по времени: исключаются IP старше {days_threshold} дней")

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
                            logger.info(f"Загружен TXT файл {filename}: {len(ips)} IP-адресов")
                    except Exception as e:
                        logger.error(f"Ошибка загрузки TXT файла {filename}: {e}")
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
                            logger.info(f"Загружен JSON файл {filename}: {len(filtered_ips)} IP-адресов (после фильтрации по времени)")

                        else:
                            # Без фильтрации по времени - берёт все IP
                            ips_from_json = set(addresses.keys())
                            all_ips.update(ips_from_json)
                            logger.info(f"Загружен JSON файл {filename}: {len(ips_from_json)} IP-адресов")

                    except Exception as e:
                        logger.error(f"Ошибка загрузки JSON файла {filename}: {e}")
                        continue

                # Обработка YAML/YML файлов
                elif filename.endswith(('.yaml', '.yml')):
                    try:
                        with open(file_path, 'r') as f:
                            data = yaml.safe_load(f)

                        # Проверка структуры файла results-dns.yaml
                        if 'categories' in data:
                            all_historical_ips = set()

                            # Обходит все категории и домены
                            for category_name, category_data in data['categories'].items():
                                for domain_name, domain_info in category_data.items():
                                    ipv4_data = domain_info.get('ipv4', {})
                                    historical_ips = ipv4_data.get('historical', {})

                                    if days_threshold is not None:
                                        # Фильтрация IP по времени last_seen в historical
                                        filtered_ips = set()
                                        for ip, last_seen_str in historical_ips.items():
                                            if last_seen_str:
                                                try:
                                                    last_seen_date = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
                                                    if last_seen_date >= threshold_date:
                                                        filtered_ips.add(ip)
                                                except ValueError:
                                                    # Если неверный формат даты, включает IP
                                                    filtered_ips.add(ip)
                                            else:
                                                # Если нет даты, включает IP
                                                filtered_ips.add(ip)

                                        all_historical_ips.update(filtered_ips)
                                    else:
                                        # Без фильтрации - берет все IP из historical
                                        ips_from_yaml = set(historical_ips.keys())
                                        all_historical_ips.update(ips_from_yaml)

                            all_ips.update(all_historical_ips)

                            if days_threshold is not None:
                                logger.info(f"Загружен YAML файл {filename}: {len(all_historical_ips)} IP-адресов из historical (после фильтрации по времени)")
                            else:
                                logger.info(f"Загружен YAML файл {filename}: {len(all_historical_ips)} IP-адресов из historical")

                        else:
                            logger.warning(f"YAML файл {filename} имеет нестандартную структуру, пропускаем")
                    except Exception as e:

                        logger.error(f"Ошибка загрузки YAML файла {filename}: {e}")
                        continue

                else:
                    continue

        except Exception as e:
            logger.error(f"Ошибка загрузки из пути {path}: {e}")
            continue

    if not all_ips:
        logger.warning(f"Не найдено IP-адресов в указанных путях")

    # Определение имени для использования
    # Если указано несколько путей, создаст объединенное имя
    if len(processed_paths) > 1:
        dir_names = [os.path.basename(p) for p in processed_paths]
        combined_name = "_".join(dir_names)
        logger.info(f"Объединено {len(processed_paths)} директорий: {combined_name}")
        return combined_name, all_ips
    else:
        dir_name = os.path.basename(processed_paths[0])
        return dir_name, all_ips

def load_dns_ips(file_path: str, logger=None) -> Set[str]:
    """Загружает все IPv4 адреса из YAML файла с DNS записями (новая структура)"""
    if logger is None:
        logger = logging.getLogger(__name__)

    if file_path.lower() == 'none':
        logger.info("DNS фильтрация отключена (установлено 'none')")
        return set()

    try:
        abs_path = validate_file_path(file_path, "DNS YAML файл")
        with open(abs_path, 'r') as f:
            data = yaml.safe_load(f)

        ip_set = set()
        total_loaded = 0

        categories = data.get('categories', {})
        logger.debug(f"Найдено категорий DNS: {len(categories)}")

        for category_name, category in categories.items():
            category_count = 0
            for domain, domain_data in category.items():
                ipv4_data = domain_data.get('ipv4', {})
                historical_ips = ipv4_data.get('historical', {})

                # Только (ipv4) из historical
                if historical_ips:
                    ip_set.update(historical_ips.keys())
                    category_count += len(historical_ips)

            logger.debug(f"Категория '{category_name}': {category_count} IP-адресов")
            total_loaded += category_count

        logger.info(f"Всего загружено DNS IP-адресов из historical: {total_loaded}")
        logger.info(f"Уникальных DNS IP-адресов: {len(ip_set)}")

        if ip_set:
            sample_ips = list(ip_set)[:5]
            logger.debug(f"Примеры загруженных DNS IP: {sample_ips}")

        return ip_set

    except Exception as e:
        logger.error(f"Ошибка загрузки DNS YAML файла: {e}")
        raise

def load_asn_mmdb(file_path: str, logger=None) -> maxminddb.Reader:
    """Загружает MMDB базу данных ASN"""
    if logger is None:
        logger = logging.getLogger(__name__)

    try:
        abs_path = validate_file_path(file_path, "ASN MMDB файл")
        reader = maxminddb.open_database(abs_path)
        logger.info(f"MMDB база ASN загружена: {abs_path}")
        return reader
    except Exception as e:
        logger.error(f"Ошибка загрузки MMDB файла: {e}")
        raise

def get_asn_info(ip: str, mmdb_reader: maxminddb.Reader, logger=None) -> Optional[Dict[str, Any]]:
    """
    Получает информацию об ASN для IP из MMDB базы.
    Возвращает словарь с ключами: 'asn', 'org', 'country'
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    try:
        # Проверка, на приватный IP
        ip_obj = ipaddress.IPv4Address(ip)
        if ip_obj.is_private:
            # Для приватных IP возвращает специальную метку
            return {
                'asn': 'ASPRIVATE',
                'org': 'Private Network',
                'country': 'XX'
            }

        # Запрос к MMDB базе
        result = mmdb_reader.get(ip_obj.compressed)

        if not result:
            logger.debug(f"Для публичного IP {ip} не найдена информация в MMDB")
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

        # Если ASN не начинается с "AS", добавит префикс
        if asn_info['asn'] != 'ASUNKNOWN' and not asn_info['asn'].startswith('AS'):
            asn_info['asn'] = f"AS{asn_info['asn']}"

        # Очистка названия организации
        if ',' in asn_info['org']:
            asn_info['org'] = asn_info['org'].split(',')[0]

        return asn_info

    except Exception as e:
        logger.debug(f"Ошибка получения ASN для IP {ip}: {e}")
        return {
            'asn': 'ASUNKNOWN',
            'org': 'Unknown',
            'country': 'XX'
        }

def process_ips_with_mmdb(
    ips: List[str],
    mmdb_reader: maxminddb.Reader,
    asn_filter: Optional[List[str]] = None,
    country_filter: Optional[List[str]] = None,
    logger=None
) -> Tuple[Dict[Tuple[str, str, str], Dict[str, Any]], List[str], Dict[str, int]]:
    """
    Обрабатывает IP-адреса с использованием MMDB базы.
    Возвращает:
    - словарь {(asn, org, country): {'prefixes': Dict[префикс: List[IP]], 'total_ips': int}}
      (ТОЛЬКО IP, прошедшие фильтры)
    - список IP без найденной ASN информации
    - словарь с подсчетом IP по ASN {asn: count} (ВСЕ IP, независимо от фильтров)
    """
    if logger is None:
        logger = logging.getLogger(__name__)

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

        # Если включен фильтр по стране
        if country_filter:
            if country not in country_filter:
                skip_filtered = True

        # Если IP не проходит фильтры, пропускаем его для asn_group_map
        if skip_filtered:
            continue

        # Определяет префикс (/24 для IPv4)
        ip_obj = ipaddress.IPv4Address(ip)
        prefix = ipaddress.IPv4Network(f"{ip_obj}/24", strict=False)

        # Группирует по ASN, Org, Country (только IP, прошедшие фильтры)
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
    list_name: str,
    prefix_threshold: int,
    logger=None
) -> str:
    """Генерирует содержимое .rsc файла"""
    if logger is None:
        logger = logging.getLogger(__name__)

    lines = ['/ip firewall address-list']
    threshold = prefix_threshold

    # Функция для проверки приватных адресов
    def is_private_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
        except:
            return True

    # Обрабатывает IP с ASN информацией
    for (asn, org, country), data in asn_group_map.items():
        comment_base = f"{asn}:{org}:{country}"

        for prefix, ips in data['prefixes'].items():
            if len(ips) >= threshold:
                # Добавляет префикс
                lines.append(
                    f'add address={prefix} list={list_name} '
                    f'comment="{comment_base} -> IP={len(ips)}"'
                )
            else:
                # Добавляет отдельные IP
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
        logger.info(f"Отфильтровано приватных адресов без ASN: {private_ip_count}")

    return '\n'.join(lines)

def print_detailed_asn_statistics(
    asn_counter_all: Dict[str, int],
    asn_group_map: Dict[Tuple[str, str, str], Dict[str, Any]],
    total_ips_processed: int,
    asn_filter: Optional[List[str]] = None,
    logger=None
) -> None:
    """
    Выводит детальную статистику по ASN с количеством и процентами
    в формате: {ASN}:{Организация}:{Страна} -> {Количество} (%)
    Использует ВСЕ IP (asn_counter_all), а не только отфильтрованные
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if not asn_counter_all:
        logger.info("Нет данных по ASN для статистики")
        return

    logger.info("\n=== ДЕТАЛЬНАЯ СТАТИСТИКА ПО ASN ===")

    # Создание списка для сортировки с информацией об организации и стране
    stats_list = []
    total_counted_ips = 0

    for asn, count in asn_counter_all.items():
        if asn == 'ASUNKNOWN':
            org, country = "Unknown", "XX"
        else:
            org, country = get_asn_info_from_map(asn, asn_group_map)
        stats_list.append((asn, org, country, count))
        total_counted_ips += count

    # Сортирует по количеству IP
    stats_list.sort(key=lambda x: x[3], reverse=True)

    # Фильтрует только указанные ASN, если фильтр активен
    if asn_filter:
        stats_list = [(asn, org, country, count) for asn, org, country, count in stats_list if asn in asn_filter]
        logger.info(f"Показаны только ASN из фильтра ({len(asn_filter)} шт.):")

    # Выводит статистику
    total_shown = sum(count for _, _, _, count in stats_list)

    for asn, org, country, count in stats_list:
        percentage = (count / total_ips_processed) * 100 if total_ips_processed > 0 else 0
        org_short = org[:50] + "..." if len(org) > 50 else org

        # Поиск данных в asn_group_map (только для ASN, прошедших фильтрацию)
        prefix_count = 0
        total_ips_in_map = 0
        for (map_asn, _, _), data in asn_group_map.items():
            if map_asn == asn:
                prefix_count = len(data['prefixes'])
                total_ips_in_map = data['total_ips']
                break

        if prefix_count > 0:
            avg_per_prefix = total_ips_in_map / prefix_count
            logger.info(
                f"  {asn}:{org_short}:{country} -> {count} IP ({percentage:.2f}%) | "
                f"Префиксы: {prefix_count} (в среднем: {avg_per_prefix:.2f} IP на префикс)"
            )
        else:
            logger.info(f"  {asn}:{org_short}:{country} -> {count} IP ({percentage:.2f}%)")

    # Если есть ASN не показанные из-за фильтра
    if asn_filter and total_shown < total_ips_processed:
        other_count = total_ips_processed - total_shown
        other_percentage = (other_count / total_ips_processed) * 100
        logger.info(f"  Остальные ASN: {other_count} IP ({other_percentage:.2f}%)")

    logger.info(f"Всего обработано IP: {total_ips_processed}")
    logger.info(f"Всего учтено в статистике ASN: {total_counted_ips} IP")

def print_geo_statistics(
    asn_counter_all: Dict[str, int],
    asn_group_map: Dict[Tuple[str, str, str], Dict[str, Any]],
    total_ips_processed: int,
    logger=None
) -> None:
    """
    Выводит статистику по геолокациям (странам) на основе ВСЕХ IP
    """
    if logger is None:
        logger = logging.getLogger(__name__)

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

    logger.info("\n=== ДЕТАЛЬНАЯ СТАТИСТИКА ASN GEO ===")

    for country in country_stats:
        country_stats[country]['asn_count'] = len(country_stats[country]['asn_set'])

    # Сортирует по количеству IP (по убыванию)
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

        logger.info(
            f"  {country}: {stats['asn_count']} ASN "
            f"({stats['ip_count']} IP, {ip_percentage:.1f}% от IP) "
            f"[{asn_percentage:.1f}% от ASN]"
        )

    logger.info(f"Всего стран: {len(country_stats)}")
    logger.info(f"Всего уникальных ASN: {total_unique_asn}")

def calculate_recommended_thresholds(
    asn_group_map: Dict[Tuple[str, str, str], Dict[str, Any]]
) -> Dict[str, int]:
    """
    Рассчитывает адаптивные рекомендации для prefix_threshold:
    - compact: 25-й процентиль, но минимум 2
    - precise: 75-й процентиль, но минимум на 2 больше compact и минимум 3
    - balance: округлённая медиана между compact и precise
    """
    prefix_counts = []
    for data in asn_group_map.values():
        for ips in data['prefixes'].values():
            prefix_counts.append(len(ips))

    if not prefix_counts:
        return {"compact": 2, "balance": 3, "precise": 5}

    arr = np.array(prefix_counts)
    p25 = int(np.percentile(arr, 25))
    p50 = int(np.percentile(arr, 50))
    p75 = int(np.percentile(arr, 75))
    p90 = int(np.percentile(arr, 90))

    # Минимальная агрегация: хотя бы 2 IP
    compact = max(2, p25)

    # Precise: используем p75 или p90, но c гарантией выше compact
    precise_candidate = max(p75, p90)
    precise = max(compact + 2, precise_candidate, 3)  # минимум на 2 больше compact

    mean_ips = round(float(np.mean(arr)))
    balance = max(compact + 1, min(precise - 1, mean_ips))
    if balance == compact:
        balance = compact + 1 if precise > compact + 1 else compact

    return {
        "compact": compact,
        "balance": balance,
        "precise": precise
    }

def generate_json_report(
    asn_group_map: Dict[Tuple[str, str, str], Dict[str, Any]],
    no_asn_ips: List[str],
    asn_counter_all: Dict[str, int],
    config: Dict[str, Any],
    script_name: str,
    output_filename_base: str,
    prefix_threshold: int,
    logger=None
) -> Dict[str, Any]:
    """
    Генерация детального JSON отчета со всей иерархией данных
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    try:
        meta = {
            "generated_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "script_name": script_name,
            "output_filename": f"{output_filename_base}-ipv4.rsc",
            "report_filename": f"{output_filename_base}-report.json",
            "parameters": {
                "ip_list_dir": config.get('ip_list_dir'),
                "dns_file_filter": config.get('dns_file_filter'),
                "remove_last_seen": config.get('remove_last_seen'),
                "asn_filter": config.get('asn_filter'),
                "country_filter": config.get('country_filter'),
                "prefix_threshold": prefix_threshold,
                "report_generation": config.get('report_generation', False)
            }
        }

        total_ips_in_map = sum(data['total_ips'] for data in asn_group_map.values())
        aggregated_prefixes = sum(
            1 for data in asn_group_map.values()
            for ips in data['prefixes'].values()
            if len(ips) >= prefix_threshold
        )
        individual_prefixes = sum(
            1 for data in asn_group_map.values()
            for ips in data['prefixes'].values()
            if len(ips) < prefix_threshold
        )

        statistics = {
            "total_ips_processed": total_ips_in_map + len(no_asn_ips),
            "ips_with_asn_processed": total_ips_in_map,
            "ips_no_asn": len(no_asn_ips),
            "unique_asns": len(asn_group_map),
            "total_prefixes": aggregated_prefixes + individual_prefixes,
            "aggregated_prefixes": aggregated_prefixes,
            "individual_prefixes": individual_prefixes,
            "prefix_threshold_applied": prefix_threshold
        }

        # Подготовка GEO распределения с детализацией по ASN
        geo_distribution = {}
        for (asn, org, country), data in asn_group_map.items():
            if country not in geo_distribution:
                geo_distribution[country] = {
                    "asn_count": 0,
                    "ip_count": 0,
                    "prefix_count": 0,
                    "asns": []
                }

            prefix_count = len(data['prefixes'])
            ip_count = data['total_ips']

            geo_distribution[country]["asn_count"] += 1
            geo_distribution[country]["ip_count"] += ip_count
            geo_distribution[country]["prefix_count"] += prefix_count

            # Детальная информация по каждому ASN в стране
            asn_info = {
                "asn": asn,
                "org": org,
                "ip_count": ip_count,
                "prefix_count": prefix_count,
                "prefixes": []
            }

            # Информация о префиксах конкретного ASN
            for prefix, ips in data['prefixes'].items():
                prefix_info = {
                    "network": str(prefix),
                    "ip_count": len(ips),
                    "aggregated": len(ips) >= prefix_threshold,
                    "ips": sorted(ips)  # Все IP адреса в префиксе
                }
                asn_info["prefixes"].append(prefix_info)

            geo_distribution[country]["asns"].append(asn_info)

        # Сортировка ASN внутри каждой страны по количеству IP
        for country in geo_distribution:
            geo_distribution[country]["asns"].sort(key=lambda x: x["ip_count"], reverse=True)

        # Иерархия данных (ASN → Prefixes → IPs)
        asn_hierarchy = []
        for (asn, org, country), data in asn_group_map.items():
            asn_entry = {
                "asn": asn,
                "org": org,
                "country": country,
                "total_ips": data['total_ips'],
                "prefix_count": len(data['prefixes']),
                "prefixes": []
            }

            for prefix, ips in data['prefixes'].items():
                prefix_entry = {
                    "network": str(prefix),
                    "ip_count": len(ips),
                    "aggregated": len(ips) >= prefix_threshold,
                    "ips": sorted(ips)
                }
                asn_entry["prefixes"].append(prefix_entry)

            # Сортировка префиксов по количеству IP
            asn_entry["prefixes"].sort(key=lambda x: x["ip_count"], reverse=True)
            asn_hierarchy.append(asn_entry)

        # Сортировка ASN по количеству IP
        asn_hierarchy.sort(key=lambda x: x["total_ips"], reverse=True)

        # Необработанные IP (без ASN)
        unprocessed_ips = {
            "no_asn": sorted(no_asn_ips),
            "count": len(no_asn_ips)
        }

        # Сводка по всем ASN (включая отфильтрованные)
        all_asn_summary = []
        for asn, count in asn_counter_all.items():
            org = "Unknown"
            country = "XX"
            for (map_asn, map_org, map_country), _ in asn_group_map.items():
                if map_asn == asn:
                    org = map_org
                    country = map_country
                    break

            all_asn_summary.append({
                "asn": asn,
                "org": org,
                "country": country,
                "total_ips": count,
                "in_final_rsc": asn in [a for (a, _, _) in asn_group_map.keys()]
            })

        # Сортировка по количеству IP
        all_asn_summary.sort(key=lambda x: x["total_ips"], reverse=True)

        # === ПОДГОТОВКА СВОДНОЙ СТАТИСТИКИ (из логов) ===
        summary = {
            "detailed_asn_statistics": [],
            "geo_statistics": [],
            "key_metrics": {}
        }

        # 1. Детальная статистика по ASN (аналогично логам)
        if asn_counter_all:
            # Фильтруем только ASN из asn_group_map (которые попали в RSC)
            filtered_asn_stats = []
            for (asn, org, country), data in asn_group_map.items():
                total_count = asn_counter_all.get(asn, 0)
                prefix_count = len(data['prefixes'])
                ip_count_in_map = data['total_ips']

                # Рассчет среднего IP на префикс
                avg_per_prefix = ip_count_in_map / prefix_count if prefix_count > 0 else 0

                asn_stat = {
                    "asn": asn,
                    "org": org[:50] + "..." if len(org) > 50 else org,  # Обрезка длинных названия
                    "country": country,
                    "total_ips": total_count,
                    "prefixes_in_rsc": prefix_count,
                    "avg_ips_per_prefix": round(avg_per_prefix, 2),
                    "in_final_rsc": True
                }
                filtered_asn_stats.append(asn_stat)

            # Сортирует по количеству IP
            filtered_asn_stats.sort(key=lambda x: x["total_ips"], reverse=True)
            summary["detailed_asn_statistics"] = filtered_asn_stats

        # 2. Статистика по странам (GEO)
        if geo_distribution:
            geo_stats = []
            for country, data in geo_distribution.items():
                # Получает список ASN для этой страны
                asn_list = [asn_info["asn"] for asn_info in data["asns"]]

                geo_stat = {
                    "country": country,
                    "asn_count": data["asn_count"],
                    "ip_count": data["ip_count"],
                    "prefix_count": data["prefix_count"],
                    "asns": asn_list[:10],  # Только первые 10 ASN
                    "total_asns": len(asn_list)
                }
                geo_stats.append(geo_stat)

            # Сортировка по количеству IP
            geo_stats.sort(key=lambda x: x["ip_count"], reverse=True)
            summary["geo_statistics"] = geo_stats

        # 3. Ключевые метрики
        summary["key_metrics"] = {
            "total_ips_processed": statistics["total_ips_processed"],
            "ips_in_final_rsc": statistics["ips_with_asn_processed"] + statistics["ips_no_asn"],
            "unique_asns_in_rsc": statistics["unique_asns"],
            "unique_countries": len(geo_distribution),
            "aggregation_efficiency": {
                "total_prefixes": statistics["total_prefixes"],
                "aggregated_prefixes": statistics["aggregated_prefixes"],
                "aggregation_ratio": round(statistics["aggregated_prefixes"] / statistics["total_prefixes"] * 100, 1)
                    if statistics["total_prefixes"] > 0 else 0,
                "prefix_threshold": prefix_threshold
            }
        }

        # Сборка финального отчета:
        report = {
            "meta": meta,
            "summary": summary,
            "statistics": statistics,
            "geo_distribution": geo_distribution,
            "asn_hierarchy": asn_hierarchy,
            "unprocessed_ips": unprocessed_ips,
            "all_asn_summary": all_asn_summary,
            "aggregation_info": {
                "threshold": prefix_threshold,
                "description": f"Префиксы с {prefix_threshold}+ IP агрегируются в /24 сети"
            }
        }

        return report

    except Exception as e:
        logger.error(f"Ошибка при генерации JSON отчета: {e}")
        raise

def save_json_report(report_data: Dict[str, Any], output_path: Path, logger=None):
    """Сохранение JSON отчета в файл"""
    if logger is None:
        logger = logging.getLogger(__name__)

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)
        logger.info(f"JSON отчет сохранен: {output_path}")
    except Exception as e:
        logger.error(f"Ошибка при сохранении JSON отчета: {e}")
        raise

class IpAnalystCore:
    def __init__(self, config: Dict[str, Any], script_name: str = None):
       self.config = config
       self.script_name = script_name if script_name else Path(__file__).stem

       # Получаем логгер для ядра
       self.logger = logging.getLogger(self.script_name)

    def run(self) -> None:
        """Основной метод, который выполняет всю логику"""
        self.logger.info(f"\n=== Запуск {self.script_name} - генератор RSC из MMDB ASN ===")

        try:
            # Получаем все значения из конфига
            config = self.config

            ip_list_dir = config['ip_list_dir']
            dns_yaml_path = config['dns_file_filter']
            as_mmdb_path = config['asn_db_file']
            output_dir = config['output_dir']
            remove_last_seen = config['remove_last_seen']
            country_filter_raw = config['country_filter']
            output_filename_config = config['output_filename']
            asn_filter_raw = config['asn_filter']
            prefix_threshold = config['prefix_threshold']

            # Преобразование параметров:
            asn_filter = None
            if isinstance(asn_filter_raw, str) and asn_filter_raw.lower() == 'none':
                asn_filter = None
            elif isinstance(asn_filter_raw, list) and len(asn_filter_raw) == 0:
                asn_filter = None
            else:
                asn_filter = asn_filter_raw

            country_filter = None
            if isinstance(country_filter_raw, str) and country_filter_raw.lower() == 'none':
                country_filter = None
            elif isinstance(country_filter_raw, list) and len(country_filter_raw) == 0:
                country_filter = None
            else:
                country_filter = country_filter_raw

            ip_dirs_str = ip_list_dir if isinstance(ip_list_dir, str) else ', '.join(ip_list_dir)
            self.logger.info(f"Используемые пути и параметры:\n"
                           f"- Директории с IP списками: {ip_dirs_str}\n"
                           f"- DNS фильтр: {'Отключен' if dns_yaml_path.lower() == 'none' else dns_yaml_path}\n"
                           f"- ASN MMDB база: {as_mmdb_path}\n"
                           f"- Выходная директория: {output_dir}\n"
                           f"- Имя выходного файла/листа: {output_filename_config if output_filename_config != 'none' else 'По имени директории'}\n"
                           f"- Фильтр ASN: {asn_filter if asn_filter else 'Отключен'}\n"
                           f"- Фильтр стран: {country_filter if country_filter else 'Отключен'}\n"
                           f"- Фильтр по времени: {f'{remove_last_seen} дней (применяется к JSON/YAML файлам)' if remove_last_seen is not None else 'Отключен'}\n"
                           f"- Генерация отчета: {'Включена' if config.get('report_generation', False) else 'Отключена'}\n")
            # Загрузка данных из одного или нескольких путей
            self.logger.info("Загрузка исходных IP-адресов...")

            dir_name, all_source_ips = self.load_ip_lists_from_paths(ip_list_dir)

            if not all_source_ips:
                self.logger.warning("Нет IP-адресов для обработки")
                return

            self.logger.info(f"Всего загружено IP-адресов из всех файлов: {len(all_source_ips)}")

            self.logger.info("Загрузка MMDB базы ASN...")
            mmdb_reader = self.load_asn_mmdb(as_mmdb_path)

            # Логика фильтрации DNS
            if dns_yaml_path.lower() == 'none':
                self.logger.info("DNS фильтрация отключена - используются все исходные IP-адреса")
                unique_ips = all_source_ips
            else:
                self.logger.info("Загрузка DNS записей...")
                dns_ips = self.load_dns_ips(dns_yaml_path)
                unique_ips = all_source_ips - dns_ips
                self.logger.info(f"Найдено {len(unique_ips)} уникальных IP-адресов")

            if not unique_ips:
                self.logger.warning("Нет уникальных IP-адресов для обработки")
                return

            # Обработка IP с MMDB
            self.logger.info("Обработка IP-адресов с MMDB...")
            asn_group_map, no_asn_ips, asn_counter = self.process_ips_with_mmdb(
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
                if len(ips) >= prefix_threshold
            )

            self.logger.info(
                f"Итоговая статистика:\n"
                f"- IP с найденной ASN информацией: {total_with_asn}\n"
                f"- IP без ASN информации: {len(no_asn_ips)}\n"
                f"- Уникальных ASN: {len(asn_group_map)}\n"
                f"- Префиксов для агрегации (>= {prefix_threshold} IP): {common_prefixes}"
            )

            # Вызов функций статистики:
            self.print_detailed_asn_statistics(
                asn_counter_all=asn_counter,
                asn_group_map=asn_group_map,
                total_ips_processed=len(unique_ips),
                asn_filter=asn_filter
            )

            self.print_geo_statistics(
                asn_counter_all=asn_counter,
                asn_group_map=asn_group_map,
                total_ips_processed=len(unique_ips)
            )

            recommended = self.calculate_recommended_thresholds(asn_group_map)

            # Сбор всех prefix_counts для распределения
            prefix_counts = []
            for _, data in asn_group_map.items():
                for ips in data['prefixes'].values():
                    prefix_counts.append(len(ips))

            self.logger.info(f"=== РЕКОМЕНДАЦИИ ПО АГРЕГАЦИИ ===")
            self.logger.info(f"Проанализировано префиксов /24: {len(prefix_counts)}")

            if prefix_counts:
                avg_per_prefix = sum(prefix_counts) / len(prefix_counts)
                self.logger.info(f"Среднее количество IP в префиксе /24: {avg_per_prefix:.2f}")

                # Вывод рекомендаций
                self.logger.info(f"Баланс (компактность + точность): {recommended['balance']}")
                self.logger.info(f"Макс. компактность листа (агрегировать всё возможное): {recommended['compact']}")
                self.logger.info(f"Макс. точность листа (только насыщенные префиксы): {recommended['precise']}")

                distr_info = []
                for threshold in [1, 2, 3, 5, 10]:
                    count_above = sum(1 for c in prefix_counts if c >= threshold)
                    percentage = (count_above / len(prefix_counts)) * 100
                    distr_info.append(f"{threshold}+: {count_above} преф. ({percentage:.1f}%)")
                self.logger.debug(f"Распределение префиксов по количеству IP: {', '.join(distr_info)}")

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
            output_path = os.path.join(self.validate_directory(output_dir, "Выходная директория"), output_filename)

            self.logger.info(f"Имя листа в RSC: {list_name}")
            self.logger.info(f"Имя выходного файла: {output_filename}")

            self.logger.info(f"Создание файла {output_filename} с листом '{list_name}'...")

            content = self.generate_rsc_content_mmdb(
                asn_group_map,
                no_asn_ips,
                list_name
            )

            mmdb_reader.close()

            with open(output_path, 'w') as f:
                f.write(content)

            self.logger.info(f"Файл {output_path} успешно создан")
            # === ГЕНЕРАЦИЯ ОТЧЕТА (если report_generation: true) ===
            if config.get('report_generation', False):
                try:
                    self.logger.info("Генерация детального JSON отчета...")

                    report_data = generate_json_report(
                        asn_group_map=asn_group_map,
                        no_asn_ips=no_asn_ips,
                        asn_counter_all=asn_counter,
                        config=config,
                        script_name=self.script_name,
                        output_filename_base=output_filename_base,
                        prefix_threshold=prefix_threshold,
                        logger=self.logger
                    )

                    # Сохранение отчета
                    report_filename = f"{output_filename_base}-report.json"
                    report_path = os.path.join(output_dir, report_filename)
                    save_json_report(report_data, Path(report_path), self.logger)

                    # Краткая статистика по отчету
                    stats = report_data['statistics']
                    self.logger.info(
                        f"Отчет создан: {report_path}\n"
                        f"  - Обработано IP: {stats['total_ips_processed']}\n"
                        f"  - Уникальных ASN: {stats['unique_asns']}\n"
                        f"  - Префиксов /24: {stats['total_prefixes']}\n"
                        f"  - Агрегировано префиксов: {stats['aggregated_prefixes']}"
                    )

                except Exception as e:
                    self.logger.warning(f"Не удалось сгенерировать отчет: {e}")

            self.logger.info("=== Скрипт успешно завершен ===")

        except Exception as e:
            self.logger.error(f"Критическая ошибка: {e}", exc_info=True)
            raise

    def load_asn_mmdb(self, file_path: str) -> maxminddb.Reader:
        return load_asn_mmdb(file_path, self.logger)

    def load_dns_ips(self, file_path: str) -> Set[str]:
        return load_dns_ips(file_path, self.logger)

    def process_ips_with_mmdb(self, ips, mmdb_reader, asn_filter=None, country_filter=None):
        return process_ips_with_mmdb(ips, mmdb_reader, asn_filter, country_filter, self.logger)

    def validate_directory(self, dir_path: str, dir_description: str) -> str:
        return validate_directory(dir_path, dir_description, self.logger)

    def load_ip_lists_from_paths(self, paths_input):
        days_threshold = self.config.get('remove_last_seen')
        return load_ip_lists_from_paths(paths_input, days_threshold, self.logger)

    def generate_rsc_content_mmdb(self, asn_group_map, no_asn_ips, list_name):
        prefix_threshold = self.config['prefix_threshold']
        return generate_rsc_content_mmdb(
            asn_group_map, no_asn_ips, list_name, prefix_threshold, self.logger
        )

    def print_detailed_asn_statistics(self, asn_counter_all, asn_group_map,
                                     total_ips_processed, asn_filter=None):
        return print_detailed_asn_statistics(
            asn_counter_all, asn_group_map, total_ips_processed, asn_filter, self.logger
        )

    def print_geo_statistics(self, asn_counter_all, asn_group_map, total_ips_processed):
        return print_geo_statistics(asn_counter_all, asn_group_map, total_ips_processed, self.logger)

    def calculate_recommended_thresholds(self, asn_group_map):
        return calculate_recommended_thresholds(asn_group_map)
