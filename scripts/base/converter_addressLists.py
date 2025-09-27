"""
Скрипт для обработки DNS и ASN данных с генерацией конфигурационных файлов для MikroTik.
"""

import yaml
import logging
import re
import json
import shutil
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from ipaddress import ip_address, AddressValueError

# Создание директории logs/main_start
log_path = Path('logs/base/converter_addressLists/converter_addressLists.log')
log_path.parent.mkdir(parents=True, exist_ok=True)

def setup_logging(config):
    """Настройка логирования из конфига"""
    log_level = config.get("log_level", "INFO").upper()
    numeric_level = getattr(logging, log_level, logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def load_comment_cache(list_name):
    """Загружает кэш комментариев для каждого списка с проверкой TTL"""
    cache_file = Path(f"cache/converter_addressLists/{list_name}.json")

    # Загрузка конфига для получения TTL
    config = load_config()
    ttl_days = config.get("cache_sett", {}).get("ttl", 7)

    # Проверка срока жизни кэша
    if not cache_file.exists():
        return {"dns": {"domains_v4": {}, "domains_v6": {}, "ips_v4": {}, "ips_v6": {}},
                "asn": {"ips_v4": {}, "ips_v6": {}}}

    try:
        # Чтение метаинформации из кэша
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)

        # Проверка наличия timestamp и TTL
        if ('meta' not in cache_data or
            'timestamp' not in cache_data['meta']):
            logger.warning(f"Кэш {list_name} не содержит метаинформации, будет пересоздан")
            cache_file.unlink()
            return {"dns": {"domains_v4": {}, "domains_v6": {}, "ips_v4": {}, "ips_v6": {}},
                    "asn": {"ips_v4": {}, "ips_v6": {}}}

        # Проверка срока жизни
        cache_time = datetime.fromisoformat(cache_data['meta']['timestamp'])
        expiration_time = cache_time + timedelta(days=ttl_days)

        if datetime.now() > expiration_time:
            logger.info(f"Кэш для {list_name} устарел (TTL: {ttl_days} дней), будет создан новый")
            cache_file.unlink()
            return {"dns": {"domains_v4": {}, "domains_v6": {}, "ips_v4": {}, "ips_v6": {}},
                    "asn": {"ips_v4": {}, "ips_v6": {}}}

        # Возвращаем данные из кэша
        return cache_data.get("data", {"dns": {"domains_v4": {}, "domains_v6": {}, "ips_v4": {}, "ips_v6": {}},
                                      "asn": {"ips_v4": {}, "ips_v6": {}}})

    except Exception as e:
        logger.warning(f"Ошибка загрузки кэша для {list_name}: {e}")
        try:
            if cache_file.exists():
                cache_file.unlink()
        except:
            pass
        return {"dns": {"domains_v4": {}, "domains_v6": {}, "ips_v4": {}, "ips_v6": {}},
                "asn": {"ips_v4": {}, "ips_v6": {}}}

def save_comment_cache(list_name, cache_data):
    """Сохраняет обновлённый кэш комментариев с метаинформацией"""
    cache_dir = Path("cache/converter_addressLists")
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"{list_name}.json"

    # Загрузка конфига для получения TTL
    config = load_config()
    ttl_days = config.get("cache_sett", {}).get("ttl", 7)

    try:
        if cache_file.exists():
            with open(cache_file, 'r') as f:
                existing_data = json.load(f)

            # Сохранение оригинальных метаданных (timestamp создание)
            meta = existing_data.get("meta", {})
            if not meta:
                meta = {
                    "timestamp": datetime.now().isoformat(),
                    "ttl_days": ttl_days,
                    "expires": (datetime.now() + timedelta(days=ttl_days)).isoformat()
                }
        else:
            meta = {
                "timestamp": datetime.now().isoformat(),
                "ttl_days": ttl_days,
                "expires": (datetime.now() + timedelta(days=ttl_days)).isoformat()
            }

        # Обновление данных, без изменения метаинформации
        cache_with_meta = {
            "meta": meta,
            "data": cache_data
        }

        with open(cache_file, 'w') as f:
            json.dump(cache_with_meta, f, indent=2)
    except Exception as e:
        logger.error(f"Ошибка сохранения кэша для {list_name}: {e}")

def load_config():
    """Загрузка конфигурации с значениями по умолчанию"""
    default_config = {
        "logging": {"log_level": "INFO"},
        "settings_gen": {
            "skip_domains": False,
            "skip_ips": {
                "ipv4": False,
                "ipv6": False
            },
            "skip_asn": False
        }
    }
    try:
        with open("configs/config.yaml", "r") as f:
            user_config = yaml.safe_load(f).get("converter_add_list", {})
        if "settings_gen" in user_config:
            if "skip_ips" in user_config["settings_gen"]:
                if isinstance(user_config["settings_gen"]["skip_ips"], bool):
                    skip_value = user_config["settings_gen"]["skip_ips"]
                    user_config["settings_gen"]["skip_ips"] = {
                        "ipv4": skip_value,
                        "ipv6": skip_value
                    }
                elif isinstance(user_config["settings_gen"]["skip_ips"], dict):
                    ips_config = user_config["settings_gen"]["skip_ips"]
                    if "ipv4" not in ips_config:
                        ips_config["ipv4"] = False
                    if "ipv6" not in ips_config:
                        ips_config["ipv6"] = False
        return {**default_config, **user_config}
    except Exception as e:
        logging.error(f"Ошибка загрузки конфига: {e}")
        return default_config

def is_valid_ip(address):
    """Проверяет валидность IP-адреса"""
    try:
        ip_address(address)
        return True
    except (ValueError, AddressValueError):
        return False

def is_valid_cidr(prefix):
    try:
        if ':' in prefix:  # IPv6
            ipaddress.IPv6Network(prefix)
        else:  # IPv4
            ipaddress.IPv4Network(prefix)
        return True
    except ValueError:
        return False

def transliterate_idn_comment(idn_str):
    """Заменяет кириллицу на латиницу + оставляет Punycode в скобках"""
    # Таблица замен (можно расширить)
    cyr_to_lat = {
        'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e',
        'ё': 'yo', 'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'y', 'к': 'k',
        'л': 'l', 'м': 'm', 'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r',
        'с': 's', 'т': 't', 'у': 'u', 'ф': 'f', 'х': 'kh', 'ц': 'ts',
        'ч': 'ch', 'ш': 'sh', 'щ': 'sch', 'ъ': '', 'ы': 'y', 'ь': '',
        'э': 'e', 'ю': 'yu', 'я': 'ya',
        'рф': 'rf'  # Специально для .рф
    }
    result = []
    for char in idn_str.lower():
        result.append(cyr_to_lat.get(char, char))
    return ''.join(result)

def process_dns_file(results_path, config):
    """Обрабатывает файл results-dns.yaml и генерирует .rsc файлов"""
    try:
        with open(results_path, "r") as f:
            data = yaml.safe_load(f)
        list_name = results_path.parent.parent.name
        rsc_dir = Path(f"output-data/{list_name}/DNS")
        rsc_dir.mkdir(parents=True, exist_ok=True)

        # Загрузка кэша комментариев
        cache = load_comment_cache(list_name)
        new_cache = {
            "domains_v4": {},
            "domains_v6": {},
            "ips_v4": {},
            "ips_v6": {}
        }

        stats = {
            'categories': 0,
            'domains_total': 0,
            'ipv4_count': 0,
            'ipv6_count': 0,
            'invalid_ips': 0,
            'idn_converted': 0,
            'cached_comments_used': 0
        }
        skip_ipv4 = config["settings_gen"]["skip_ips"].get("ipv4", False)
        skip_ipv6 = config["settings_gen"]["skip_ips"].get("ipv6", False)

        # Сбор всех IP и доменов в словарь для обработки дубликатов
        all_ips_v4 = {}
        all_ips_v6 = {}
        all_domains_v4 = {}
        all_domains_v6 = {}

        for category, domains in data.get("categories", {}).items():
            stats['categories'] += 1
            stats['domains_total'] += len(domains)

            for domain, info in domains.items():
                # Определение отображаемоого имени домена
                if domain.startswith('xn--') or 'idn_name' in info:
                    idn_name = info.get('idn_name', domain)
                    domain_display = transliterate_idn_comment(idn_name)
                else:
                    domain_display = domain

                # Обработка IPv4 - совместимость со старым и новым форматом
                if not skip_ipv4 and 'ipv4' in info:
                    ipv4_data = info['ipv4']

                    # Определение формата данных
                    if isinstance(ipv4_data, list):
                        # Старый формат: список IP
                        ips_to_process = ipv4_data
                    elif isinstance(ipv4_data, dict):
                        # Новый формат: словарь с current и historical
                        # Берем все IP из historical
                        ips_to_process = list(ipv4_data.get('historical', {}).keys())
                    else:
                        ips_to_process = []

                    for ip in ips_to_process:
                        if is_valid_ip(ip):
                            cached_comment = cache["dns"]["ips_v4"].get(ip)
                            new_comment = f"{category} -> {domain_display}"
                            comment_to_use = cached_comment if cached_comment else new_comment
                            all_ips_v4[ip] = comment_to_use

                # Обработка IPv6 - совместимость со старым и новым форматом
                if not skip_ipv6 and 'ipv6' in info:
                    ipv6_data = info['ipv6']

                    # Определение формата данных
                    if isinstance(ipv6_data, list):
                        # Старый формат: список IP
                        ips_to_process = ipv6_data
                    elif isinstance(ipv6_data, dict):
                        # Новый формат: словарь с current и historical
                        # Берем все IP из historical
                        ips_to_process = list(ipv6_data.get('historical', {}).keys())
                    else:
                        ips_to_process = []

                    for ip in ips_to_process:
                        if is_valid_ip(ip):
                            cached_comment = cache["dns"]["ips_v6"].get(ip)
                            new_comment = f"{category} -> {domain_display}"
                            comment_to_use = cached_comment if cached_comment else new_comment
                            all_ips_v6[ip] = comment_to_use

                # Обработка доменов - совместимость со старым и новым форматом
                if not config["settings_gen"]["skip_domains"]:
                    # Проверяем наличие IPv4
                    has_ipv4 = False
                    if 'ipv4' in info:
                        if isinstance(info['ipv4'], list) and info['ipv4']:
                            has_ipv4 = True
                        elif isinstance(info['ipv4'], dict) and (info['ipv4'].get('current') or info['ipv4'].get('historical')):
                            has_ipv4 = True

                    if has_ipv4:
                        cached_comment = cache["dns"]["domains_v4"].get(domain)
                        if domain.startswith('xn--') or 'idn_name' in info:
                            new_comment = f"{category} -> {domain_display}"
                        else:
                            new_comment = category
                        comment_to_use = cached_comment if cached_comment else new_comment
                        all_domains_v4[domain] = comment_to_use

                    # Проверяем наличие IPv6
                    has_ipv6 = False
                    if 'ipv6' in info:
                        if isinstance(info['ipv6'], list) and info['ipv6']:
                            has_ipv6 = True
                        elif isinstance(info['ipv6'], dict) and (info['ipv6'].get('current') or info['ipv6'].get('historical')):
                            has_ipv6 = True

                    if has_ipv6:
                        cached_comment = cache["dns"]["domains_v6"].get(domain)
                        if domain.startswith('xn--') or 'idn_name' in info:
                            new_comment = f"{category} -> {domain_display}"
                        else:
                            new_comment = category
                        comment_to_use = cached_comment if cached_comment else new_comment
                        all_domains_v6[domain] = comment_to_use

        # Генерация RSC файлов (DNS)
        for category, domains in data.get("categories", {}).items():
            # Создание файлов *-domains-v4.rsc
            if not config["settings_gen"]["skip_domains"]:
                ipv4_domains = {}
                for domain, info in domains.items():
                    has_ipv4 = False
                    if 'ipv4' in info:
                        if isinstance(info['ipv4'], list) and info['ipv4']:
                            has_ipv4 = True
                        elif isinstance(info['ipv4'], dict) and (info['ipv4'].get('current') or info['ipv4'].get('historical')):
                            has_ipv4 = True
                    if has_ipv4:
                        ipv4_domains[domain] = info

                if ipv4_domains:
                    domain_file = rsc_dir / f"{category}-domains-v4.rsc"
                    with open(domain_file, 'w') as f:
                        f.write("/ip firewall address-list\n")
                        for domain in ipv4_domains:
                            if domain in all_domains_v4:
                                f.write(f'add address={domain} list={list_name} comment="{all_domains_v4[domain]}"\n')
                                new_cache["domains_v4"][domain] = all_domains_v4[domain]
                                if domain in cache["dns"]["domains_v4"]:
                                    stats['cached_comments_used'] += 1

                    logger.info(f"Создан {domain_file} ({len(ipv4_domains)} доменов с IPv4)")

                # Создание файлов *-domains-v6.rsc
                ipv6_domains = {}
                for domain, info in domains.items():
                    has_ipv6 = False
                    if 'ipv6' in info:
                        if isinstance(info['ipv6'], list) and info['ipv6']:
                            has_ipv6 = True
                        elif isinstance(info['ipv6'], dict) and (info['ipv6'].get('current') or info['ipv6'].get('historical')):
                            has_ipv6 = True
                    if has_ipv6:
                        ipv6_domains[domain] = info

                if ipv6_domains:
                    domain_v6_file = rsc_dir / f"{category}-domains-v6.rsc"
                    with open(domain_v6_file, 'w') as f:
                        f.write("/ipv6 firewall address-list\n")
                        for domain in ipv6_domains:
                            if domain in all_domains_v6:
                                f.write(f'add address={domain} list={list_name} comment="{all_domains_v6[domain]}"\n')
                                new_cache["domains_v6"][domain] = all_domains_v6[domain]
                                if domain in cache["dns"]["domains_v6"]:
                                    stats['cached_comments_used'] += 1

                    logger.info(f"Создан {domain_v6_file} ({len(ipv6_domains)} доменов с IPv6)")

            # Генерация файлов IP доменов (IPv4 и IPv6)
            if domains and not skip_ipv4:
                ipv4_file = rsc_dir / f"{category}-ipv4.rsc"
                ipv4_written = 0
                with open(ipv4_file, 'w') as f:
                    f.write("/ip firewall address-list\n")
                    for domain, info in domains.items():
                        if 'ipv4' in info:
                            ipv4_data = info['ipv4']

                            # Определение формата данных
                            if isinstance(ipv4_data, list):
                                # Старый формат: список IP
                                ips_to_process = ipv4_data
                            elif isinstance(ipv4_data, dict):
                                # Новый формат: словарь с current и historical
                                # Берем все IP из historical
                                ips_to_process = list(ipv4_data.get('historical', {}).keys())
                            else:
                                ips_to_process = []

                            for ip in ips_to_process:
                                if ip in all_ips_v4:
                                    f.write(f'add address={ip} list={list_name} comment="{all_ips_v4[ip]}"\n')
                                    new_cache["ips_v4"][ip] = all_ips_v4[ip]
                                    if ip in cache["dns"]["ips_v4"]:
                                        stats['cached_comments_used'] += 1
                                    ipv4_written += 1
                                    stats['ipv4_count'] += 1
                                elif is_valid_ip(ip):
                                    stats['invalid_ips'] += 1

                if ipv4_written > 0:
                    logger.info(f"Создан {ipv4_file} ({ipv4_written} IPv4)")

            if domains and not skip_ipv6:
                ipv6_file = rsc_dir / f"{category}-ipv6.rsc"
                ipv6_written = 0
                with open(ipv6_file, 'w') as f:
                    f.write("/ipv6 firewall address-list\n")
                    for domain, info in domains.items():
                        if 'ipv6' in info:
                            ipv6_data = info['ipv6']

                            # Определение формата данных
                            if isinstance(ipv6_data, list):
                                # Старый формат: список IP
                                ips_to_process = ipv6_data
                            elif isinstance(ipv6_data, dict):
                                # Новый формат: словарь с current и historical
                                # Берем все IP из historical
                                ips_to_process = list(ipv6_data.get('historical', {}).keys())
                            else:
                                ips_to_process = []

                            for ip in ips_to_process:
                                if ip in all_ips_v6:
                                    f.write(f'add address={ip} list={list_name} comment="{all_ips_v6[ip]}"\n')
                                    new_cache["ips_v6"][ip] = all_ips_v6[ip]
                                    if ip in cache["dns"]["ips_v6"]:
                                        stats['cached_comments_used'] += 1
                                    ipv6_written += 1
                                    stats['ipv6_count'] += 1
                                elif is_valid_ip(ip):
                                    stats['invalid_ips'] += 1

                if ipv6_written > 0:
                    logger.info(f"Создан {ipv6_file} ({ipv6_written} IPv6)")

        # Сохранение обновленного кэша
        save_comment_cache(list_name, {"dns": new_cache, "asn": cache.get("asn", {})})
        logger.debug(f"Использовано кэшированных комментариев: {stats['cached_comments_used']}")
        return stats

    except Exception as e:
        logger.error(f"Ошибка обработки {results_path}: {e}")
        return None

def process_asn_file(asn_path, list_name, config):
    """Обработка файла results-as.json и генерация .rsc файлов"""
    if config["settings_gen"].get("skip_asn", False):
        logger.debug(f"Пропуск ASN по конфигу (skip_asn=True)")
        return None

    try:
        with open(asn_path, 'r') as f:
            data = json.load(f)
        as_data = data.get('as_data', {})
        if not as_data:
            logger.warning(f"Нет данных ASN в файле {asn_path}")
            return None

        # Загрузка кэша комментариев
        cache = load_comment_cache(list_name)
        new_cache = {
            "ips_v4": {},
            "ips_v6": {}
        }

        output_dir = Path(f"output-data/{list_name}/AS")
        output_dir.mkdir(parents=True, exist_ok=True)

        stats = {
            'as_count': 0,
            'ipv4_prefixes': 0,
            'ipv6_prefixes': 0,
            'cached_comments_used': 0
        }

        # Сбор всех префиксов в словари для обработки дубликатов
        all_prefixes_v4 = {}
        all_prefixes_v6 = {}

        for as_number, as_info in as_data.items():
            stats['as_count'] += 1

            # Обработка IPv4
            for prefix in as_info.get('prefixes_v4', []):
                if '/' in prefix:  # Валидация префикса
                    cached_comment = cache["asn"]["ips_v4"].get(prefix)
                    comment_to_use = cached_comment if cached_comment else as_number
                    all_prefixes_v4[prefix] = comment_to_use

            # Обработка IPv6
            for prefix in as_info.get('prefixes_v6', []):
                if ':' in prefix:  # Валидация префикса
                    cached_comment = cache["asn"]["ips_v6"].get(prefix)
                    comment_to_use = cached_comment if cached_comment else as_number
                    all_prefixes_v6[prefix] = comment_to_use

        # Генерация RSC файлов (AS)
        for as_number, as_info in as_data.items():
            # Обработка IPv4
            if as_info.get('prefixes_v4'):
                ipv4_file = output_dir / f"{as_number}-ipv4.rsc"
                with open(ipv4_file, 'w') as f:
                    f.write("/ip firewall address-list\n")
                    for prefix in as_info['prefixes_v4']:
                        if prefix in all_prefixes_v4:
                            f.write(f'add address={prefix} list={list_name} comment="{all_prefixes_v4[prefix]}"\n')
                            new_cache["ips_v4"][prefix] = all_prefixes_v4[prefix]
                            if prefix in cache["asn"]["ips_v4"]:
                                stats['cached_comments_used'] += 1
                            stats['ipv4_prefixes'] += 1

                logger.info(f"Создан {ipv4_file} ({len(as_info['prefixes_v4'])} IPv4 префиксов)")

            # Обработка IPv6
            if as_info.get('prefixes_v6'):
                ipv6_file = output_dir / f"{as_number}-ipv6.rsc"
                with open(ipv6_file, 'w') as f:
                    f.write("/ipv6 firewall address-list\n")
                    for prefix in as_info['prefixes_v6']:
                        if prefix in all_prefixes_v6:
                            f.write(f'add address={prefix} list={list_name} comment="{all_prefixes_v6[prefix]}"\n')
                            new_cache["ips_v6"][prefix] = all_prefixes_v6[prefix]
                            if prefix in cache["asn"]["ips_v6"]:
                                stats['cached_comments_used'] += 1
                            stats['ipv6_prefixes'] += 1

                logger.info(f"Создан {ipv6_file} ({len(as_info['prefixes_v6'])} IPv6 префиксов)")

        # Сохранение обновленного кэша (объединяется с DNS кэшем)
        full_cache = {
            "dns": cache.get("dns", {}),  # Сохраняем существующие DNS данные
            "asn": new_cache              # Обновляем только ASN часть
        }
        save_comment_cache(list_name, full_cache)
        logger.debug(f"Использовано кэшированных комментариев ASN: {stats['cached_comments_used']}")
        return stats

    except Exception as e:
        logger.error(f"Ошибка обработки ASN файла {asn_path}: {e}")
        return None

def remove_duplicates_from_rsc(list_name):
    """
    Удаляет дубликаты в пределах одного списка, раздельно по типам файлов:
    *-domains-v4.rsc, *-domains-v6.rsc, *-ipv4.rsc, *-ipv6.rsc
    Сохраняя первое вхождение.
    """
    dns_dir = Path(f"output-data/{list_name}/DNS")
    if not dns_dir.exists():
        # Проверка наличия директории AS
        as_dir = Path(f"output-data/{list_name}/AS")
        if not as_dir.exists():
            return None
        pass

    stats = {
        'duplicate_domains': {},
        'duplicate_ips': {},
        'total_domains_before': 0,
        'total_domains_after': 0,
        'total_ips_before': 0,
        'total_ips_after': 0
    }

    # 1. Обработка *-domains-v4.rsc
    domain_v4_files = list(dns_dir.glob("*-domains-v4.rsc"))
    if domain_v4_files:
        unique_domains_v4 = set()
        stats_v4 = {'before': 0, 'after': 0, 'dups': {}}
        for domain_file in domain_v4_files:
            lines_to_keep = []
            with open(domain_file, 'r') as f:
                for line in f:
                    if not line.startswith("add address="):
                        lines_to_keep.append(line)
                        continue
                    stats_v4['before'] += 1
                    stats['total_domains_before'] += 1
                    domain = line.split("add address=")[1].split(" ")[0]
                    if domain in unique_domains_v4:
                        # Фиксирование дубликатов для статистики
                        if domain not in stats['duplicate_domains']:
                            stats['duplicate_domains'][domain] = []
                        stats['duplicate_domains'][domain].append(domain_file.name)
                        # Фиксирование дубликатов для локальной статистики
                        if domain not in stats_v4['dups']:
                            stats_v4['dups'][domain] = []
                        stats_v4['dups'][domain].append(domain_file.name)
                        logger.debug(f"Найден дубликат домена (v4): {domain} в файле {domain_file.name}")
                    else:
                        unique_domains_v4.add(domain)
                        lines_to_keep.append(line)
                        stats_v4['after'] += 1
                        stats['total_domains_after'] += 1
            # Перезаписывание файла без дубликатов
            with open(domain_file, 'w') as f:
                f.writelines(lines_to_keep)
        if stats_v4['dups']:
            logger.info(f"Обработка дубликатов доменов v4 для списка '{list_name}':")
            logger.info(f"  Всего доменов v4: {stats_v4['before']} -> Уникальных: {stats_v4['after']}")
            dup_count = len(stats_v4['dups'])
            if dup_count > 0:
                logger.info(f"  Дублирующиеся домены v4: {dup_count}")

    # 2. Обработка *-domains-v6.rsc
    domain_v6_files = list(dns_dir.glob("*-domains-v6.rsc"))
    if domain_v6_files:
        unique_domains_v6 = set()
        stats_v6 = {'before': 0, 'after': 0, 'dups': {}}
        for domain_file in domain_v6_files:
            lines_to_keep = []
            with open(domain_file, 'r') as f:
                for line in f:
                    if not line.startswith("add address="):
                        lines_to_keep.append(line)
                        continue
                    stats_v6['before'] += 1
                    stats['total_domains_before'] += 1
                    domain = line.split("add address=")[1].split(" ")[0]
                    if domain in unique_domains_v6:
                        # Фиксирование дубликатов для статистики
                        if domain not in stats['duplicate_domains']:
                            stats['duplicate_domains'][domain] = []
                        stats['duplicate_domains'][domain].append(domain_file.name)
                        # Фиксирование дубликатов для локальной статистики
                        if domain not in stats_v6['dups']:
                            stats_v6['dups'][domain] = []
                        stats_v6['dups'][domain].append(domain_file.name)
                        logger.debug(f"Найден дубликат домена (v6): {domain} в файле {domain_file.name}")
                    else:
                        unique_domains_v6.add(domain)
                        lines_to_keep.append(line)
                        stats_v6['after'] += 1
                        stats['total_domains_after'] += 1
            # Перезаписывание файла без дубликатов
            with open(domain_file, 'w') as f:
                f.writelines(lines_to_keep)
        if stats_v6['dups']:
             logger.info(f"Обработка дубликатов доменов v6 для списка '{list_name}':")
             logger.info(f"  Всего доменов v6: {stats_v6['before']} -> Уникальных: {stats_v6['after']}")
             dup_count = len(stats_v6['dups'])
             if dup_count > 0:
                 logger.info(f"  Дублирующиеся домены v6: {dup_count}")

    # 3. Обработка *-ipv4.rsc (включая AS)
    ipv4_files_dns = list(dns_dir.glob("*-ipv4.rsc"))
    ipv4_files_as = []
    as_dir = Path(f"output-data/{list_name}/AS")
    if as_dir.exists():
        ipv4_files_as = list(as_dir.glob("*-ipv4.rsc"))
    ipv4_files = ipv4_files_dns + ipv4_files_as

    if ipv4_files:
        unique_ips_v4 = set()
        stats_ipv4 = {'before': 0, 'after': 0, 'dups': {}}
        for ip_file in ipv4_files:
            lines_to_keep = []
            with open(ip_file, 'r') as f:
                for line in f:
                    if not line.startswith("add address="):
                        lines_to_keep.append(line)
                        continue
                    stats_ipv4['before'] += 1
                    stats['total_ips_before'] += 1
                    ip = line.split("add address=")[1].split(" ")[0]
                    if ip in unique_ips_v4:
                        if ip not in stats['duplicate_ips']:
                            stats['duplicate_ips'][ip] = []
                        comment = line.split("comment=")[1].strip('"\n')
                        stats['duplicate_ips'][ip].append(comment)
                        if ip not in stats_ipv4['dups']:
                            stats_ipv4['dups'][ip] = []
                        stats_ipv4['dups'][ip].append(comment)
                        logger.debug(f"Найден дубликат IP (v4): {ip} в файле {ip_file.name}")
                    else:
                        unique_ips_v4.add(ip)
                        lines_to_keep.append(line)
                        stats_ipv4['after'] += 1
                        stats['total_ips_after'] += 1
            with open(ip_file, 'w') as f:
                f.writelines(lines_to_keep)
        if stats_ipv4['dups']:
            logger.info(f"Обработка дубликатов IP v4 для списка '{list_name}' (DNS+AS):")
            logger.info(f"  Всего IP v4: {stats_ipv4['before']} -> Уникальных: {stats_ipv4['after']}")
            dup_count = len(stats_ipv4['dups'])
            if dup_count > 0:
                logger.info(f"  Дублирующиеся IP v4: {dup_count}")

    # 4. Обработка *-ipv6.rsc (включая AS)
    ipv6_files_dns = list(dns_dir.glob("*-ipv6.rsc"))
    ipv6_files_as = []
    if as_dir.exists():
        ipv6_files_as = list(as_dir.glob("*-ipv6.rsc"))
    ipv6_files = ipv6_files_dns + ipv6_files_as

    if ipv6_files:
        unique_ips_v6 = set()
        stats_ipv6 = {'before': 0, 'after': 0, 'dups': {}}
        for ip_file in ipv6_files:
            lines_to_keep = []
            with open(ip_file, 'r') as f:
                for line in f:
                    if not line.startswith("add address="):
                        lines_to_keep.append(line)
                        continue
                    stats_ipv6['before'] += 1
                    stats['total_ips_before'] += 1
                    ip = line.split("add address=")[1].split(" ")[0]
                    if ip in unique_ips_v6:
                        if ip not in stats['duplicate_ips']:
                            stats['duplicate_ips'][ip] = []
                        comment = line.split("comment=")[1].strip('"\n')
                        stats['duplicate_ips'][ip].append(comment)
                        if ip not in stats_ipv6['dups']:
                            stats_ipv6['dups'][ip] = []
                        stats_ipv6['dups'][ip].append(comment)
                        logger.debug(f"Найден дубликат IP (v6): {ip} в файле {ip_file.name}")
                    else:
                        unique_ips_v6.add(ip)
                        lines_to_keep.append(line)
                        stats_ipv6['after'] += 1
                        stats['total_ips_after'] += 1
            with open(ip_file, 'w') as f:
                f.writelines(lines_to_keep)
        if stats_ipv6['dups']:
            logger.info(f"Обработка дубликатов IP v6 для списка '{list_name}' (DNS+AS):")
            logger.info(f"  Всего IP v6: {stats_ipv6['before']} -> Уникальных: {stats_ipv6['after']}")
            dup_count = len(stats_ipv6['dups'])
            if dup_count > 0:
                logger.info(f"  Дублирующиеся IP v6: {dup_count}")

    # Логирование статистики
    dup_domains_count = len(stats['duplicate_domains'])
    dup_ips_count = len(stats['duplicate_ips'])
    logger.info(f"Обработка дубликатов для списка '{list_name}':")
    logger.info(f"  Всего доменов: {stats['total_domains_before']} -> Уникальных: {stats['total_domains_after']}")
    logger.info(f"  Всего IP: {stats['total_ips_before']} -> Уникальных: {stats['total_ips_after']}")
    if dup_domains_count > 0:
        logger.info(f"  Дублирующиеся домены: {dup_domains_count}")
        sample = list(stats['duplicate_domains'].items())[:3]
        for domain, files in sample:
            logger.debug(f"    Пример дубликата: {domain} (в файлах: {', '.join(files)})")
    if dup_ips_count > 0:
        logger.info(f"  Дублирующиеся IP: {dup_ips_count}")
        sample = list(stats['duplicate_ips'].items())[:3]
        for ip, comments in sample:
            logger.debug(f"    Пример дубликата: {ip} (комментарии: {', '.join(comments[:2])})")
    return stats

def main():
    try:
        start_time = datetime.now()
        config = load_config()
        global logger
        logger = setup_logging(config)
        log_level = config.get("logging", {}).get("log_level", "INFO").upper()
        logger.setLevel(log_level)
        for handler in logger.handlers:
            handler.setLevel(log_level)
        logger.info("\n===== Запуск converter_addressLists.py - генератор RSC файлов для MikroTik =====")
        logger.debug(f"Конфигурация: {config}")
        total_stats = {
            'lists': 0,
            'categories': 0,
            'domains_total': 0,
            'ipv4_count': 0,
            'ipv6_count': 0,
            'invalid_ips': 0,
            'as_count': 0,
            'ipv4_prefixes': 0,
            'ipv6_prefixes': 0,
            'idn_converted': 0,
            'duplicates': {
                'duplicate_domains': {},
                'duplicate_ips': {},
                'total_domains_before': 0,
                'total_domains_after': 0,
                'total_ips_before': 0,
                'total_ips_after': 0
            }
        }
        input_dir = Path("raw-data")
        if not input_dir.exists():
            logger.error(f"Директория {input_dir} не существует!")
            return
        for list_dir in input_dir.iterdir():
            if not list_dir.is_dir():
                continue
            logger.info(f"\n=== Обработка списка: {list_dir.name} ===")
            processed = False
            # Обработка DNS данных
            dns_file = list_dir / "DNS" / "results-dns.yaml"
            if dns_file.exists():
                stats = process_dns_file(dns_file, config)
                if stats:
                    processed = True
                    total_stats['lists'] += 1
                    for key in ['categories', 'domains_total',
                               'ipv4_count', 'ipv6_count', 'invalid_ips', 'idn_converted']:
                        total_stats[key] += stats.get(key, 0)
            else:
                logger.warning(f"DNS файл не найден: {dns_file}")
            # Обработка ASN данных
            asn_file = list_dir / "AS" / "results-as.json"
            if not config["settings_gen"].get("skip_asn", False) and asn_file.exists():
                stats = process_asn_file(asn_file, list_dir.name, config)
                if stats:
                    processed = True
                    for key in ['as_count', 'ipv4_prefixes', 'ipv6_prefixes']:
                        total_stats[key] += stats.get(key, 0)
            elif not config["settings_gen"].get("skip_asn", False):
                logger.warning(f"ASN файл не найден: {asn_file}")
            if not processed:
                logger.warning(f"Нет данных для обработки в {list_dir.name}")
            # Постобработка удаления дубликатов
            dup_stats = remove_duplicates_from_rsc(list_dir.name)
            if dup_stats:
                # Обновление статистики дубликатов
                for key in ['duplicate_domains', 'duplicate_ips']:
                    for item, sources in dup_stats[key].items():
                        if item not in total_stats['duplicates'][key]:
                            total_stats['duplicates'][key][item] = []
                        total_stats['duplicates'][key][item].extend(sources)
                # Суммируем счетчики
                for key in ['total_domains_before', 'total_domains_after',
                          'total_ips_before', 'total_ips_after']:
                    total_stats['duplicates'][key] += dup_stats.get(key, 0)
        # Итоговая статистика
        duration = (datetime.now() - start_time).total_seconds()
        logger.info("\n=== Итоговая статистика ===")
        logger.info(f"Обработано списков: {total_stats['lists']}")
        if total_stats['categories'] > 0:
            logger.info(f"Обработано категорий DNS: {total_stats['categories']}")
            logger.info(f"Всего доменов: {total_stats['domains_total']}")
            if total_stats['idn_converted'] > 0:
                logger.info(f"Конвертировано IDN доменов: {total_stats['idn_converted']}")
            logger.info(f"Всего IPv4 адресов: {total_stats['ipv4_count']}")
            logger.info(f"Всего IPv6 адресов: {total_stats['ipv6_count']}")
            logger.info(f"Пропущено невалидных IP: {total_stats['invalid_ips']}")
        if total_stats['as_count'] > 0:
            logger.info(f"Обработано AS: {total_stats['as_count']}")
            logger.info(f"IPv4 префиксов: {total_stats['ipv4_prefixes']}")
            logger.info(f"IPv6 префиксов: {total_stats['ipv6_prefixes']}")
        logger.info(f"Общее время выполнения: {duration:.2f} секунд")
        logger.info("Генерация завершена успешно!")
        # Вывод статистики дубликатов
        dup_domains_count = len(total_stats['duplicates']['duplicate_domains'])
        dup_ips_count = len(total_stats['duplicates']['duplicate_ips'])
        if dup_domains_count > 0 or dup_ips_count > 0:
            logger.info("\n=== Статистика дубликатов ===")
            logger.info(f"Всего дубликатов доменов: {dup_domains_count}")
            logger.info(f"Всего дубликатов IP: {dup_ips_count}")
            logger.info(f"Удалено доменов: {total_stats['duplicates']['total_domains_before'] - total_stats['duplicates']['total_domains_after']}")
            logger.info(f"Удалено IP: {total_stats['duplicates']['total_ips_before'] - total_stats['duplicates']['total_ips_after']}")
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}", exc_info=True)
        exit(1)

if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    main()
