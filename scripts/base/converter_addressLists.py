"""
Скрипт для обработки DNS и ASN данных с генерацией конфигурационных файлов для MikroTik.
"""

import yaml
import logging
import re
import json
import shutil
import ipaddress
from unidecode import unidecode
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
    try:
        config = load_config()
        ttl_days = config.get("cache_sett", {}).get("ttl", 7)
    except Exception:
        ttl_days = 7  # Значение по умолчанию при ошибке

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

        # Возвращает данные из кэша
        return cache_data.get("data", {"dns": {"domains_v4": {}, "domains_v6": {}, "ips_v4": {}, "ips_v6": {}},
                                      "asn": {"ips_v4": {}, "ips_v6": {}}})

    except json.JSONDecodeError as e:
        logger.warning(f"Ошибка парсинга JSON в кэше для {list_name}: {e}")
        if cache_file.exists():
            cache_file.unlink()
        return {"dns": {"domains_v4": {}, "domains_v6": {}, "ips_v4": {}, "ips_v6": {}},
                "asn": {"ips_v4": {}, "ips_v6": {}}}
    except Exception as e:
        logger.warning(f"Ошибка загрузки кэша для {list_name}: {e}")
        if cache_file.exists():
            cache_file.unlink()
        return {"dns": {"domains_v4": {}, "domains_v6": {}, "ips_v4": {}, "ips_v6": {}},
                "asn": {"ips_v4": {}, "ips_v6": {}}}

def save_comment_cache(list_name, cache_data):
    """Сохраняет обновлённый кэш комментариев с метаинформацией"""
    cache_dir = Path("cache/converter_addressLists")
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / f"{list_name}.json"

    # Загрузка конфига для получения TTL
    try:
        config = load_config()
        ttl_days = config.get("cache_sett", {}).get("ttl", 7)
    except Exception:
        ttl_days = 7

    try:
        existing_data = {}
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    existing_data = json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"Поврежденный кэш для {list_name}, будет создан новый")
                existing_data = {}

        # Сохранение оригинальных метаданных
        if existing_data and 'meta' in existing_data:
            meta = existing_data['meta']
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
    except IOError as e:
        logger.error(f"Ошибка записи кэша для {list_name}: {e}")
    except Exception as e:
        logger.error(f"Неожиданная ошибка сохранения кэша для {list_name}: {e}")

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
            "skip_asn": False,
            "skip_dnsFWD": False,
            "max_private_components": 4,
            "merge_private_suffixes": False
        },
        "list_name": [],
        "path_to_public_suffix": ""
    }
    try:
        with open("configs/config.yaml", "r") as f:
            user_config = yaml.safe_load(f).get("converter_add_list", {})

        # Обработка list_name
        if "list_name" not in user_config:
            user_config["list_name"] = []
        elif isinstance(user_config["list_name"], str):
            user_config["list_name"] = [user_config["list_name"]]

        # Обработка path_to_public_suffix
        if "path_to_public_suffix" not in user_config:
            user_config["path_to_public_suffix"] = ""

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
            if "skip_dnsFWD" not in user_config["settings_gen"]:
                user_config["settings_gen"]["skip_dnsFWD"] = False
            if "max_private_components" not in user_config["settings_gen"]:
                user_config["settings_gen"]["max_private_components"] = 4
            if "merge_private_suffixes" not in user_config["settings_gen"]:
                user_config["settings_gen"]["merge_private_suffixes"] = False
        return {**default_config, **user_config}
    except FileNotFoundError:
        logging.warning("Файл configs/config.yaml не найден, используются настройки по умолчанию")
        return default_config
    except yaml.YAMLError as e:
        logging.error(f"Ошибка парсинга YAML в config.yaml: {e}")
        return default_config
    except Exception as e:
        logging.error(f"Неожиданная ошибка загрузки конфига: {e}")
        return default_config

def load_public_suffix_list(config):
    """
    Загружает публичный суффикс-лист из файла, указанного в конфиге.
    Возвращает tuple (icann_suffixes, private_suffixes) или None в случае ошибки.
    """
    path_to_suffix = config.get("path_to_public_suffix", "")

    if not path_to_suffix:
        logger.debug("Параметр path_to_public_suffix не указан в конфиге")
        return None

    suffix_file = Path(path_to_suffix)
    if not suffix_file.exists():
        logger.warning(f"Файл public_suffix_list.dat не найден: {path_to_suffix}")
        return None

    try:
        icann_suffixes = set()
        private_suffixes = set()
        current_section = None

        with open(suffix_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Определение секции
                if line.startswith('// ===BEGIN ICANN DOMAINS==='):
                    current_section = 'ICANN'
                    continue
                elif line.startswith('// ===BEGIN PRIVATE DOMAINS==='):
                    current_section = 'PRIVATE'
                    continue
                elif line.startswith('// ===END'):
                    current_section = None
                    continue

                # Пропуск комментариев и правил
                if line.startswith('//') or line.startswith('#') or line.startswith('!') or line.startswith('*.'):
                    continue

                # Добавляет суффикс в соответствующую секцию
                if current_section == 'ICANN':
                    icann_suffixes.add(line.lower())
                elif current_section == 'PRIVATE':
                    private_suffixes.add(line.lower())

        if not icann_suffixes and not private_suffixes:
            logger.warning(f"Файл {path_to_suffix} не содержит валидных суффиксов")
            return None

        logger.info(f"Загружено ICANN суффиксов: {len(icann_suffixes)}, PRIVATE суффиксов: {len(private_suffixes)}")
        return (icann_suffixes, private_suffixes)

    except Exception as e:
        logger.error(f"Ошибка загрузки public_suffix_list.dat: {e}")
        return None

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
    """
    Заменяет кириллицу и другие нелатинские символы на латиницу.

    Сначала пытается использовать unidecode, далее очищает результат от недопустимых символов.
    """
    try:
        # Используем unidecode для транслитерации
        transliterated = unidecode(idn_str)

        # Оставляет только допустимые символы для комментариев
        # (буквы, цифры, точки, дефисы, пробелы и скобки)
        transliterated = re.sub(r'[^a-zA-Z0-9\.\-\s\(\)]', '', transliterated)

        return transliterated

    except Exception as e:
        logging.warning(f"Ошибка транслитерации: {e}")
        return manual_transliterate(idn_str)

def manual_transliterate(idn_str):
    """Ручная транслитерация"""
    cyr_to_lat = {
        'а': 'a', 'б': 'b', 'в': 'v', 'г': 'g', 'д': 'd', 'е': 'e',
        'ё': 'yo', 'ж': 'zh', 'з': 'z', 'и': 'i', 'й': 'y', 'к': 'k',
        'л': 'l', 'м': 'm', 'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r',
        'с': 's', 'т': 't', 'у': 'u', 'ф': 'f', 'х': 'kh', 'ц': 'ts',
        'ч': 'ch', 'ш': 'sh', 'щ': 'sch', 'ъ': '', 'ы': 'y', 'ь': '',
        'э': 'e', 'ю': 'yu', 'я': 'ya',
        'є': 'ye', 'і': 'i', 'ї': 'yi', 'ґ': 'g',  # Украинские
        'ў': 'u',  # Белорусские
        'рф': 'rf', 'ком': 'com', 'орг': 'org', 'нет': 'net' # ICANN
    }

    result = []
    i = 0
    while i < len(idn_str):
        # Проверяе двухбуквенные сочетания
        if i + 1 < len(idn_str) and idn_str[i:i+2].lower() in cyr_to_lat:
            result.append(cyr_to_lat[idn_str[i:i+2].lower()])
            i += 2
        elif idn_str[i].lower() in cyr_to_lat:
            result.append(cyr_to_lat[idn_str[i].lower()])
            i += 1
        else:
            result.append(idn_str[i])
            i += 1

    return ''.join(result)

def extract_second_level_domain(domain, public_suffixes=None, max_private_components=4, merge_private_suffixes=False):
    """
    Извлекает домен для DNS Forwarder с учетом ICANN и PRIVATE секций.

    Для ICANN: берет 1 компонент перед суффиксом
    Для PRIVATE:
        - если merge_private_suffixes=True: берет только суффикс
        - если merge_private_suffixes=False: берет все компоненты до суффикса
    """
    parts = domain.lower().split('.')

    if public_suffixes:
        icann_suffixes, private_suffixes = public_suffixes

        # Проверяет PRIVATE суффиксы (длинный суффикс)
        best_private_suffix = None
        best_private_len = 0
        for i in range(len(parts)):
            candidate = '.'.join(parts[i:])
            if candidate in private_suffixes:
                current_len = len(candidate.split('.'))
                if current_len > best_private_len:
                    best_private_suffix = candidate
                    best_private_len = current_len

        if best_private_suffix:
            suffix_parts = best_private_suffix.split('.')

            if merge_private_suffixes:
                # Суффикс для объединения
                return '.'.join(suffix_parts)
            else:
                # Все компоненты до суффикса
                suffix_start = len(parts) - len(suffix_parts)
                if suffix_start > 0:
                    components_before = parts[:suffix_start]
                    # Применяет max_private_components только если не включено объединение
                    if len(components_before) > max_private_components:
                        components_before = components_before[-max_private_components:]
                    return '.'.join(components_before + suffix_parts)
                else:
                    return domain

        # Проверяет ICANN суффиксы (короткий суффикс)
        best_icann_suffix = None
        best_icann_len = 0
        for i in range(len(parts)):
            candidate = '.'.join(parts[i:])
            if candidate in icann_suffixes:
                current_len = len(candidate.split('.'))
                if current_len > best_icann_len:
                    best_icann_suffix = candidate
                    best_icann_len = current_len

        if best_icann_suffix:
            suffix_parts = best_icann_suffix.split('.')
            suffix_start = len(parts) - len(suffix_parts)
            if suffix_start > 0:
                # Берем 1 компонент перед суффиксом
                second_level_start = suffix_start - 1
                if second_level_start >= 0:
                    return '.'.join(parts[second_level_start:])
                else:
                    return domain
            else:
                return domain

    # Fallback: логика для совместимости
    two_level_zones = {
        'com.au', 'com.br', 'com.cn', 'com.co', 'com.hk', 'com.my',
        'com.ru', 'com.sg', 'com.tr', 'com.tw', 'com.ua', 'com.uy',
        'co.uk', 'co.in', 'co.jp', 'co.kr', 'co.nz', 'co.za',
        'net.au', 'net.br', 'net.cn', 'net.ru', 'net.ua',
        'org.au', 'org.br', 'org.cn', 'org.ru', 'org.ua',
        'gov.uk', 'gov.in', 'gov.ru',
        'ac.uk', 'ac.in', 'ac.jp', 'ac.ru',
        'edu.au', 'edu.cn', 'edu.ru', 'edu.ua',
    }

    if len(parts) >= 3:
        last_two = '.'.join(parts[-2:])
        if last_two in two_level_zones:
            return '.'.join(parts[-3:])

    if len(parts) >= 2:
        return '.'.join(parts[-2:])

    return domain

def process_dns_file(results_path, config):
    """Обрабатывает файл results-dns.yaml и генерирует .rsc файлов"""
    try:
        with open(results_path, "r") as f:
            data = yaml.safe_load(f)
        list_name = results_path.parent.parent.name
        rsc_dir = Path(f"output-data/{list_name}/DNS")
        rsc_dir.mkdir(parents=True, exist_ok=True)

        # Загрузка public_suffix_list
        public_suffixes = load_public_suffix_list(config)

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
            'cached_comments_used': 0,
            'dns_forwarders': 0
        }

        # Параметры конвертирования
        skip_ipv4 = config["settings_gen"]["skip_ips"].get("ipv4", False)
        skip_ipv6 = config["settings_gen"]["skip_ips"].get("ipv6", False)
        skip_dnsFWD = config["settings_gen"].get("skip_dnsFWD", False)
        max_private_components = config.get("settings_gen", {}).get("max_private_components", 4)
        merge_private_suffixes = config.get("settings_gen", {}).get("merge_private_suffixes", False)

        # Сбор всех данных в одном проходе
        all_data = {
            'ips_v4': {},
            'ips_v6': {},
            'domains_v4': {},
            'domains_v6': {},
            'categories_domains': {},
            'second_level_domains': set()
        }

        for category, domains in data.get("categories", {}).items():
            stats['categories'] += 1
            stats['domains_total'] += len(domains)
            all_data['categories_domains'][category] = {}

            # Сбор доменов 2-го уровня для DNS Forwarder
            if not skip_dnsFWD:
                for domain in domains.keys():
                    second_level = extract_second_level_domain(
                        domain,
                        public_suffixes,
                        max_private_components,
                        merge_private_suffixes
                    )
                    all_data['second_level_domains'].add(second_level)

            # Обработка каждого домена
            for domain, info in domains.items():
                # Определение отображаемого имени домена
                if domain.startswith('xn--') or 'idn_name' in info:
                    idn_name = info.get('idn_name', domain)
                    domain_display = transliterate_idn_comment(idn_name)
                    stats['idn_converted'] += 1
                else:
                    domain_display = domain

                # Сохраняет данные для категории
                all_data['categories_domains'][category][domain] = {
                    'display': domain_display,
                    'info': info
                }

                # Обработка IPv4
                if not skip_ipv4 and 'ipv4' in info:
                    ipv4_data = info['ipv4']
                    if isinstance(ipv4_data, list):
                        ips_to_process = ipv4_data
                    elif isinstance(ipv4_data, dict):
                        ips_to_process = list(ipv4_data.get('historical', {}).keys())
                    else:
                        ips_to_process = []

                    for ip in ips_to_process:
                        if is_valid_ip(ip):
                            cached_comment = cache["dns"]["ips_v4"].get(ip)
                            new_comment = f"{category} -> {domain_display}"
                            comment_to_use = cached_comment if cached_comment else new_comment
                            if ip not in all_data['ips_v4']:
                                all_data['ips_v4'][ip] = comment_to_use
                            if cached_comment:
                                stats['cached_comments_used'] += 1

                # Обработка IPv6
                if not skip_ipv6 and 'ipv6' in info:
                    ipv6_data = info['ipv6']
                    if isinstance(ipv6_data, list):
                        ips_to_process = ipv6_data
                    elif isinstance(ipv6_data, dict):
                        ips_to_process = list(ipv6_data.get('historical', {}).keys())
                    else:
                        ips_to_process = []

                    for ip in ips_to_process:
                        if is_valid_ip(ip):
                            cached_comment = cache["dns"]["ips_v6"].get(ip)
                            new_comment = f"{category} -> {domain_display}"
                            comment_to_use = cached_comment if cached_comment else new_comment
                            if ip not in all_data['ips_v6']:
                                all_data['ips_v6'][ip] = comment_to_use
                            if cached_comment:
                                stats['cached_comments_used'] += 1

                # Обработка доменов
                if not config["settings_gen"]["skip_domains"]:
                    # Проверяет наличие IPv4
                    has_ipv4 = False
                    if 'ipv4' in info:
                        if isinstance(info['ipv4'], list) and info['ipv4']:
                            has_ipv4 = True
                        elif isinstance(info['ipv4'], dict) and (info['ipv4'].get('current') or info['ipv4'].get('historical')):
                            has_ipv4 = True

                    if has_ipv4:
                        cached_comment = cache["dns"]["domains_v4"].get(domain)
                        new_comment = f"{category} -> {domain_display}" if domain.startswith('xn--') or 'idn_name' in info else category
                        comment_to_use = cached_comment if cached_comment else new_comment
                        if domain not in all_data['domains_v4']:
                            all_data['domains_v4'][domain] = comment_to_use
                        if cached_comment:
                            stats['cached_comments_used'] += 1

                    # Проверяет наличие IPv6
                    has_ipv6 = False
                    if 'ipv6' in info:
                        if isinstance(info['ipv6'], list) and info['ipv6']:
                            has_ipv6 = True
                        elif isinstance(info['ipv6'], dict) and (info['ipv6'].get('current') or info['ipv6'].get('historical')):
                            has_ipv6 = True

                    if has_ipv6:
                        cached_comment = cache["dns"]["domains_v6"].get(domain)
                        new_comment = f"{category} -> {domain_display}" if domain.startswith('xn--') or 'idn_name' in info else category
                        comment_to_use = cached_comment if cached_comment else new_comment
                        if domain not in all_data['domains_v6']:
                            all_data['domains_v6'][domain] = comment_to_use
                        if cached_comment:
                            stats['cached_comments_used'] += 1

        # Генерация DNS Forwarder файлов
        if not skip_dnsFWD and all_data['second_level_domains']:
            for category in data.get("categories", {}).keys():
                # Сбор доменов категории
                category_domains = set()
                for domain in data.get("categories", {}).get(category, {}).keys():
                    second_level = extract_second_level_domain(
                        domain,
                        public_suffixes,
                        max_private_components,
                        merge_private_suffixes
                    )
                    category_domains.add(second_level)

                if category_domains:
                    fwd_file = rsc_dir / f"{category}-dnsForward.rsc"
                    try:
                        with open(fwd_file, 'w') as f:
                            f.write("/ip dns static\n")
                            for domain in sorted(category_domains):
                                comment_escaped = category.replace('"', '\\"')
                                f.write(f'add address-list={list_name} comment="{comment_escaped}" forward-to=DNS-to-{list_name} match-subdomain=yes name={domain} type=FWD\n')
                                stats['dns_forwarders'] += 1
                        logger.info(f"Создан {fwd_file} ({len(category_domains)} DNS Forwarders)")
                    except IOError as e:
                        logger.error(f"Ошибка записи {fwd_file}: {e}")

        # Генерация RSC файлов из собранных данных
        for category, domains in all_data['categories_domains'].items():
            if not config["settings_gen"]["skip_domains"]:
                # Создание *-domains-v4.rsc
                ipv4_domains = {domain: info for domain, info in domains.items()
                               if info['info'].get('ipv4') and (
                                   (isinstance(info['info']['ipv4'], list) and info['info']['ipv4']) or
                                   (isinstance(info['info']['ipv4'], dict) and
                                    (info['info']['ipv4'].get('current') or info['info']['ipv4'].get('historical')))
                               )}

                if ipv4_domains:
                    domain_file = rsc_dir / f"{category}-domains-v4.rsc"
                    try:
                        with open(domain_file, 'w') as f:
                            f.write("/ip firewall address-list\n")
                            for domain in ipv4_domains:
                                if domain in all_data['domains_v4']:
                                    f.write(f'add address={domain} list={list_name} comment="{all_data["domains_v4"][domain]}"\n')
                                    new_cache["domains_v4"][domain] = all_data["domains_v4"][domain]
                        logger.info(f"Создан {domain_file} ({len(ipv4_domains)} доменов с IPv4)")
                    except IOError as e:
                        logger.error(f"Ошибка записи {domain_file}: {e}")

                # Создание *-domains-v6.rsc
                ipv6_domains = {domain: info for domain, info in domains.items()
                               if info['info'].get('ipv6') and (
                                   (isinstance(info['info']['ipv6'], list) and info['info']['ipv6']) or
                                   (isinstance(info['info']['ipv6'], dict) and
                                    (info['info']['ipv6'].get('current') or info['info']['ipv6'].get('historical')))
                               )}

                if ipv6_domains:
                    domain_v6_file = rsc_dir / f"{category}-domains-v6.rsc"
                    try:
                        with open(domain_v6_file, 'w') as f:
                            f.write("/ipv6 firewall address-list\n")
                            for domain in ipv6_domains:
                                if domain in all_data['domains_v6']:
                                    f.write(f'add address={domain} list={list_name} comment="{all_data["domains_v6"][domain]}"\n')
                                    new_cache["domains_v6"][domain] = all_data["domains_v6"][domain]
                        logger.info(f"Создан {domain_v6_file} ({len(ipv6_domains)} доменов с IPv6)")
                    except IOError as e:
                        logger.error(f"Ошибка записи {domain_v6_file}: {e}")

            # Генерация IP файлов
            if not skip_ipv4:
                ipv4_data = {}
                for domain, info in domains.items():
                    if 'ipv4' in info['info']:
                        ipv4_info = info['info']['ipv4']
                        if isinstance(ipv4_info, list):
                            ips = ipv4_info
                        elif isinstance(ipv4_info, dict):
                            ips = list(ipv4_info.get('historical', {}).keys())
                        else:
                            ips = []
                        for ip in ips:
                            if ip in all_data['ips_v4']:
                                ipv4_data[ip] = all_data['ips_v4'][ip]

                if ipv4_data:
                    ipv4_file = rsc_dir / f"{category}-ipv4.rsc"
                    try:
                        with open(ipv4_file, 'w') as f:
                            f.write("/ip firewall address-list\n")
                            for ip, comment in ipv4_data.items():
                                f.write(f'add address={ip} list={list_name} comment="{comment}"\n')
                                new_cache["ips_v4"][ip] = comment
                                stats['ipv4_count'] += 1
                        logger.info(f"Создан {ipv4_file} ({len(ipv4_data)} IPv4)")
                    except IOError as e:
                        logger.error(f"Ошибка записи {ipv4_file}: {e}")

            if not skip_ipv6:
                ipv6_data = {}
                for domain, info in domains.items():
                    if 'ipv6' in info['info']:
                        ipv6_info = info['info']['ipv6']
                        if isinstance(ipv6_info, list):
                            ips = ipv6_info
                        elif isinstance(ipv6_info, dict):
                            ips = list(ipv6_info.get('historical', {}).keys())
                        else:
                            ips = []
                        for ip in ips:
                            if ip in all_data['ips_v6']:
                                ipv6_data[ip] = all_data['ips_v6'][ip]

                if ipv6_data:
                    ipv6_file = rsc_dir / f"{category}-ipv6.rsc"
                    try:
                        with open(ipv6_file, 'w') as f:
                            f.write("/ipv6 firewall address-list\n")
                            for ip, comment in ipv6_data.items():
                                f.write(f'add address={ip} list={list_name} comment="{comment}"\n')
                                new_cache["ips_v6"][ip] = comment
                                stats['ipv6_count'] += 1
                        logger.info(f"Создан {ipv6_file} ({len(ipv6_data)} IPv6)")
                    except IOError as e:
                        logger.error(f"Ошибка записи {ipv6_file}: {e}")

        # Сохранение обновленного кэша
        save_comment_cache(list_name, {"dns": new_cache, "asn": cache.get("asn", {})})
        logger.debug(f"Использовано кэшированных комментариев: {stats['cached_comments_used']}")
        return stats

    except FileNotFoundError:
        logger.error(f"Файл {results_path} не найден")
        return None
    except yaml.YAMLError as e:
        logger.error(f"Ошибка парсинга YAML в {results_path}: {e}")
        return None
    except Exception as e:
        logger.error(f"Ошибка обработки {results_path}: {e}", exc_info=True)
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
            "dns": cache.get("dns", {}),  # Сохраняет существующие DNS данные
            "asn": new_cache              # Обновляет только ASN часть
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
        as_dir = Path(f"output-data/{list_name}/AS")
        if not as_dir.exists():
            return None

    stats = {
        'duplicate_domains': {},
        'duplicate_ips': {},
        'total_domains_before': 0,
        'total_domains_after': 0,
        'total_ips_before': 0,
        'total_ips_after': 0
    }

    # Функция для обработки группы файлов
    def process_file_group(file_pattern, unique_set, stats_key, is_ip=False):
        files = list(dns_dir.glob(file_pattern))

        # Добавляет файлы из AS директории для IP
        if is_ip:
            as_dir = Path(f"output-data/{list_name}/AS")
            if as_dir.exists():
                files.extend(list(as_dir.glob(file_pattern)))

        if not files:
            return

        stats_local = {'before': 0, 'after': 0, 'dups': {}}

        for file_path in files:
            lines_to_keep = []
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        if not line.startswith("add address="):
                            lines_to_keep.append(line)
                            continue

                        stats_local['before'] += 1
                        stats[stats_key + '_before'] += 1

                        # Извлекает адрес
                        address = line.split("add address=")[1].split(" ")[0]

                        if address in unique_set:
                            # Дубликат найден
                            if address not in stats['duplicate_' + ('ips' if is_ip else 'domains')]:
                                stats['duplicate_' + ('ips' if is_ip else 'domains')][address] = []

                            if is_ip:
                                comment = line.split("comment=")[1].strip('"\n')
                                stats['duplicate_ips'][address].append(comment)
                                if address not in stats_local['dups']:
                                    stats_local['dups'][address] = []
                                stats_local['dups'][address].append(comment)
                            else:
                                stats['duplicate_domains'][address].append(file_path.name)
                                if address not in stats_local['dups']:
                                    stats_local['dups'][address] = []
                                stats_local['dups'][address].append(file_path.name)

                            logger.debug(f"Найден дубликат {'IP' if is_ip else 'домена'} ({'v4/v6'}): {address} в файле {file_path.name}")
                        else:
                            unique_set.add(address)
                            lines_to_keep.append(line)
                            stats_local['after'] += 1
                            stats[stats_key + '_after'] += 1

                # Перезаписывает файл без дубликатов
                if lines_to_keep:
                    with open(file_path, 'w') as f:
                        f.writelines(lines_to_keep)

            except IOError as e:
                logger.error(f"Ошибка обработки файла {file_path}: {e}")
                continue

        # Логирование статистики для группы
        if stats_local['dups']:
            logger.info(f"Обработка дубликатов для списка '{list_name}':")
            logger.info(f"  Всего: {stats_local['before']} -> Уникальных: {stats_local['after']}")
            dup_count = len(stats_local['dups'])
            if dup_count > 0:
                logger.info(f"  Дублирующихся записей: {dup_count}")

    # Обработка всех групп файлов
    process_file_group("*-domains-v4.rsc", set(), 'total_domains', is_ip=False)
    process_file_group("*-domains-v6.rsc", set(), 'total_domains', is_ip=False)
    process_file_group("*-ipv4.rsc", set(), 'total_ips', is_ip=True)
    process_file_group("*-ipv6.rsc", set(), 'total_ips', is_ip=True)

    # Логирование итоговой статистики
    dup_domains_count = len(stats['duplicate_domains'])
    dup_ips_count = len(stats['duplicate_ips'])

    if dup_domains_count > 0 or dup_ips_count > 0:
        logger.info(f"Итоговая статистика дубликатов для списка '{list_name}':")
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
            'dns_forwarders': 0,
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

        # Получение списка имён для обработки из конфига
        target_lists = config.get("list_name", [])

        for list_dir in input_dir.iterdir():
            if not list_dir.is_dir():
                continue

            # Фильтрация по list_name из конфига
            if target_lists and list_dir.name not in target_lists:
                logger.debug(f"Пропуск директории {list_dir.name} (не в списке обработки)")
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
                               'ipv4_count', 'ipv6_count', 'invalid_ips', 'idn_converted', 'dns_forwarders']:
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
            if total_stats['dns_forwarders'] > 0:
                logger.info(f"Создано DNS Forwarders: {total_stats['dns_forwarders']}")
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
