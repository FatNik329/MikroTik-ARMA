"""
Скрипт для анализа DNS-запросов (dnscrypt-proxy), поиска активных доменов по шаблонам.
"""

# 1. Импорты
import os
import yaml
import logging
import dns.resolver
import mmap
import time
import requests
from glob import glob
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import OrderedDict

# 2. Глобальные переменные
# Глобальный логгер, резолвер, кэш
logger = logging.getLogger(__name__)
resolver = dns.resolver.Resolver()
failed_cache = {}

# 3. Вспомогательные функции
def convert_ordered_dict(obj):
    """Рекурсивно преобразует OrderedDict в обычные dict"""
    if isinstance(obj, OrderedDict):
        return {k: convert_ordered_dict(v) for k, v in obj.items()}
    elif isinstance(obj, dict):
        return {k: convert_ordered_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_ordered_dict(item) for item in obj]
    else:
        return obj

def validate_log_format(log_file):
    """Проверяет соответствие формата лога (dnscrypt-proxy) ожидаемому шаблону"""
    try:
        with open(log_file, 'r') as f:
            # Проверяет первые 10 строк или весь файл, если меньше
            for i, line in enumerate(f):
                if i >= 10:
                    break

                line = line.strip()
                if not line:
                    continue

                # Проверка базового формата строки:
                # [дата] IP домен тип_запроса статус время сервер
                if not (line.startswith('[') and ']' in line):
                    return False

                parts = line.split(']', 1)[1].strip().split()
                if len(parts) < 6:  # Минимальное количество частей
                    return False

                # Проверка формата даты
                date_part = line.split(']')[0][1:]
                try:
                    datetime.strptime(date_part, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    return False

        return True
    except Exception as e:
        logger.error(f"Ошибка проверки формата лога: {e}")
        return False

def parse_timedelta(time_str):
    """Конвертирует строку типа '1d'/'2w'"""
    units = {
        'd': 'days',
        'w': 'weeks',
        'm': 'days'
    }
    num = int(time_str[:-1])
    unit = time_str[-1].lower()

    if unit == 'm':
        return timedelta(days=num*30)
    return timedelta(**{units[unit]: num})

# Создание директории logs/dns_fwd
log_path = Path('logs/base/dns_fwd/dns_fwd.log')
log_path.parent.mkdir(parents=True, exist_ok=True)

def setup_logging(config):
    """Настройка логирования из конфига."""
    log_level = config["dns_fwd"]["logging"].get("log_level", "INFO").upper()
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

def load_failed_cache(config):
    """Загружает кэш неудачных резолвингов"""
    cache_file = "cache/dns_fwd/failed_cache.yaml"
    cache = {}

    try:
        cache_dir = os.path.dirname(cache_file)
        if cache_dir and not os.path.exists(cache_dir):
            os.makedirs(cache_dir, exist_ok=True)
            logger.debug(f"Создана директория для кэша: {cache_dir}")

        if os.path.exists(cache_file):
            with open(cache_file, "r") as f:
                data = yaml.safe_load(f) or {}
                now = datetime.now()

                for domain, expiry_str in data.items():
                    try:
                        expiry = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
                        if expiry > now:
                            cache[domain] = expiry
                    except Exception as e:
                        logger.warning(f"Ошибка обработки записи кэша {domain}: {e}")
        else:
            logger.debug(f"Файл кэша не найден, будет создан новый: {cache_file}")

    except Exception as e:
        logger.error(f"Ошибка загрузки кэша: {e}")

    logger.info(f"Загружено {len(cache)} доменов в кэше неудачных запросов")
    return cache

def save_failed_cache(cache, config):
    """Сохранение кэша неудачных запросов с созданием директории при необходимости"""
    try:
        cache_file = "cache/dns_fwd/failed_cache.yaml"
        cache_dir = os.path.dirname(cache_file)

        if cache_dir and not os.path.exists(cache_dir):
            os.makedirs(cache_dir, exist_ok=True)
            logger.debug(f"Создана директория для кэша: {cache_dir}")

        cache_data = {domain: expiry.strftime("%Y-%m-%d %H:%M:%S")
                     for domain, expiry in cache.items()}

        with open(cache_file, "w") as f:
            yaml.dump(cache_data, f)

        logger.debug(f"Сохранено {len(cache_data)} записей в кэш")
    except Exception as e:
        logger.error(f"Ошибка сохранения кэша: {e}")

# 4. Основные функции

def load_configs():
    """Загрузка всех конфигурации с конвертацией IDN и валидацией wildcards"""
    def convert_to_punycode(domain):
        """Конвертирует домен/подстроку в Punycode, если содержит не-ASCII символы"""
        try:
            if domain and any(ord(char) > 127 for char in domain):
                return domain.encode('idna').decode('ascii')
        except Exception as e:
            logger.warning(f"Ошибка конвертации '{domain}': {e}")
        return domain

    def validate_domain(domain):
        """Проверяет и нормализует домен/wildcard-шаблон"""
        if not isinstance(domain, str):
            return None
        # Удаляет кавычки и комментария
        domain = domain.split('#')[0].strip().strip('"\'')
        if not domain:
            return None

        # Обработка wildcards
        if '*' in domain:
            if domain.count('*') > 2:
                logger.warning(f"Слишком много wildcards в шаблоне: {domain}")
                return None
            if domain.startswith('*'):
                return domain.lstrip('.').lower()
            return domain.lower()

        # Обработка IDN и корневых доменов
        if domain.startswith('.'):
            rest = domain[1:]
            if not rest:
                return None
            try:
                if any(ord(c) > 127 for c in rest):
                    converted = rest.encode('idna').decode('ascii')
                    return f'.{converted}'.lower()
                else:
                    return domain.lower()
            except Exception as e:
                logger.warning(f"Ошибка конвертации IDN в корневом домене '{domain}': {e}")
                return domain.lower()

        # Обычный домен
        try:
            return convert_to_punycode(domain).lower()
        except Exception as e:
            logger.warning(f"Ошибка конвертации домена '{domain}': {e}")
            return domain.lower()

    logger.info("Загрузка конфигурации configs/config.yaml...")
    try:
        with open("configs/config.yaml", "r") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Ошибка загрузки config.yaml: {e}")
        raise

    logger.info("Загрузка списков из configs/address_lists.yaml...")
    try:
        with open("configs/address_lists.yaml", "r") as f:
            address_lists = yaml.safe_load(f)["addressList"]
        logger.info(f"Обнаружены списки: {', '.join(address_lists)}")
    except Exception as e:
        logger.error(f"Ошибка загрузки address_lists.yaml: {e}")
        raise

    domain_configs = {}
    domain_records = {}
    lists_without_templates = []

    for list_name in address_lists:
        domain_configs[list_name] = {}
        config_dir = f"configs/AddressLists/{list_name}/DNS"
        if not os.path.exists(config_dir):
            lists_without_templates.append(list_name)
            logger.warning(f"Директория с шаблонами не найдена для списка {list_name}: {config_dir}")
            continue

        yaml_files = glob(f"{config_dir}/*.yaml") + glob(f"{config_dir}/*.yml")
        if not yaml_files:
            lists_without_templates.append(list_name)
            logger.warning(f"Не найдено YAML файлов в директории {config_dir}")
            continue

        for yaml_file in yaml_files:
            try:
                category = os.path.splitext(os.path.basename(yaml_file))[0]
                with open(yaml_file, "r") as f:
                    lines = f.readlines()

                raw_domains = []
                for line in lines:
                    line = line.strip()
                    if line.startswith('- '):
                        domain = line[2:].split('#')[0].strip().strip('"\'')
                        if domain:
                            raw_domains.append(domain)

                if not raw_domains:
                    logger.warning(f"Файл {yaml_file} не содержит target_domains")
                    continue

                valid_domains = []
                for line_num, domain in enumerate(raw_domains, 1):
                    file_info = {
                        "file": yaml_file,
                        "line": line_num,
                        "list": list_name,
                        "category": category
                    }
                    if domain not in domain_records:
                        domain_records[domain] = []
                    domain_records[domain].append(file_info)

                    normalized = validate_domain(domain)
                    if normalized:
                        valid_domains.append(normalized)
                        if normalized != domain:
                            logger.debug(f"Нормализовано: {domain} → {normalized}")

                if valid_domains:
                    domain_configs[list_name][category] = valid_domains
                    logger.info(f"Загружено {len(valid_domains)} доменов для {list_name}/{category}")
                else:
                    logger.warning(f"Нет валидных доменов в {yaml_file}")
            except Exception as e:
                logger.error(f"Ошибка загрузки {yaml_file}: {e}")

    if lists_without_templates:
        logger.warning(
            "Следующие списки обнаружены, но не имеют шаблонов для обработки:\n" +
            "\n".join(f"  - {list_name}" for list_name in lists_without_templates)
        )

    return config, address_lists, domain_configs, domain_records

def is_domain_match(domain: str, pattern: str) -> bool:
    """Сравнение доменов с wildcards и корневых доменов"""
    if not isinstance(domain, str) or not isinstance(pattern, str):
        return False

    domain = domain.lower().rstrip('.')
    pattern = pattern.lower().rstrip('.')

    if not domain or not pattern:
        return False

    # Точное совпадение
    if domain == pattern:
        return True

    # Корневой домен (например .ru, .рф → .xn--p1ai, .com)
    if pattern.startswith('.'):
        tld = pattern[1:]
        return domain.endswith('.' + tld) or domain == tld

    # Wildcard
    if '*' in pattern:
        domain_parts = domain.split('.')
        pattern_parts = pattern.split('.')
        min_parts = len([p for p in pattern_parts if p != '*'])
        if len(domain_parts) < min_parts:
            return False
        domain_idx = len(domain_parts) - 1
        pattern_idx = len(pattern_parts) - 1
        while domain_idx >= 0 and pattern_idx >= 0:
            if pattern_parts[pattern_idx] == '*':
                pattern_idx -= 1
                domain_idx -= 1
            elif domain_parts[domain_idx] == pattern_parts[pattern_idx]:
                domain_idx -= 1
                pattern_idx -= 1
            else:
                return False
        return pattern_idx == -1

    # Проверка на подстроку (если pattern не содержит точек и не wildcard)
    if '.' not in pattern and '*' not in pattern:
        return pattern in domain

    # Обычное совпадение (домен содержит pattern)
    return domain == pattern or domain.endswith('.' + pattern)

def analyze_duplicates(domain_records):
    """Анализирует и логирует информацию о дубликатах доменов"""
    duplicates = {domain: records for domain, records in domain_records.items()
                 if len(records) > 1}

    if not duplicates:
        logger.info("✓ Дубликаты не обнаружены")
        return duplicates

    total_duplicates = len(duplicates)
    duplicate_entries = sum(len(r) for r in duplicates.values())
    affected_files = set(
        record["file"] for records in duplicates.values() for record in records
    )

    logger.warning(f"Обнаружено {total_duplicates} дубликатов ({duplicate_entries} вхождений)")
    logger.warning(f"Затронуто файлов: {len(affected_files)}")

   # Вывод примеров дубликатов
   # for domain, records in list(duplicates.items())[:5]:  # Ограниченный вывода дубликатов (только первые 5)
    for domain, records in duplicates.items():             # Полный вывод списка дубликатов
        logger.warning(f"  '{domain}' встречается в:")
        for record in records[:3]:
            logger.warning(f"    - {record['file']} (строка {record['line']})")
        if len(records) > 3:
            logger.warning(f"    + ещё {len(records)-3} вхождения...")

    return duplicates

def resolve_domains_parallel(domains: list, dns_servers: list, timeout: float, config: dict) -> dict:
    """Резолвинг доменов с учетом параметров параллельного режима"""
    global failed_cache
    resolved = {}
    parallel_config = config["dns_fwd"]["resolver"].get("parallel", {})

    # Фильтрация доменов (с исключением кэшированных)
    domains_to_resolve = [
        domain for domain in domains
        if domain not in failed_cache or failed_cache[domain] <= datetime.now()
    ]

    total_domains = len(domains_to_resolve)

    # Параллельный режим отключен -> выполняется последовательный резолвинг
    if not parallel_config.get("enabled", False):
        logger.debug(f"Параллельный режим отключен, последовательный резолвинг {total_domains} доменов")
        for domain in domains_to_resolve:
            try:
                ips = resolve_domain(
                    domain=domain,
                    dns_servers=dns_servers,
                    timeout=timeout,
                    config=config
                )
                if ips:
                    resolved[domain] = {"ipv4": ips.get("ipv4", []), "ipv6": ips.get("ipv6", [])}
            except Exception as e:
                logger.debug(f"Ошибка резолвинга {domain}: {str(e)}")
        return resolved
        return resolved

    # Параллельный режим включен -> настройка параметров
    max_workers = parallel_config.get("max_workers", 4)
    batch_size = parallel_config.get("batch_size", 20)
    delay = parallel_config.get("delay", 0.3)

    # Определение размера пачки
    if total_domains <= batch_size:
        actual_batch_size = total_domains
        num_batches = 1
    else:
        actual_batch_size = batch_size
        num_batches = (total_domains + batch_size - 1) // batch_size

    logger.info(f"Параллельный резолвинг: {total_domains} доменов, "
                f"потоков: {max_workers}, "
                f"пачек: {num_batches} по ~{actual_batch_size} доменов")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for i in range(0, total_domains, batch_size):
            batch = domains_to_resolve[i:i + batch_size]
            batch_num = i // batch_size + 1

            if num_batches > 1:
                logger.debug(f"Пачка {batch_num}/{num_batches}: {len(batch)} доменов")

            futures = {}

            # Отправка пачки DNS запросов (резолвинг)
            for domain in batch:
                future = executor.submit(
                    resolve_domain,
                    domain=domain,
                    dns_servers=dns_servers,
                    timeout=timeout,
                    config=config
                )
                futures[future] = domain

            # Обработка результатов
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    ips = future.result()
                    if ips:
                        resolved[domain] = ips
                except Exception as e:
                    logger.debug(f"Ошибка резолвинга {domain}: {str(e)}")

            # Задержка между пачками
            if i + batch_size < total_domains:
                time.sleep(delay)

    logger.debug(f"Успешно разрешено: {len(resolved)}/{total_domains}")
    return resolved

def resolve_domain(domain: str, dns_servers: list, timeout: float, config: dict) -> dict:
    """Резолвит домен с кэшированием неудачных запросов, возвращает словарь с ipv4/ipv6"""
    global failed_cache

    # Проверка кэша
    if domain in failed_cache:
        if failed_cache[domain] > datetime.now():
            logger.debug(f"Домен {domain} в кэше неудачных запросов (пропускаем)")
            return {}
        del failed_cache[domain]  # Удаление просроченной записи

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    result = {}

    logger.debug(f"Попытка разрешить домен: {domain} (IDN: {'xn--' in domain})")

    for server in dns_servers:
        try:
            resolver.nameservers = [server]

            if config["dns_fwd"]["resolver"]["ip_type"]["ipv4"]:
                try:
                    answers = resolver.resolve(domain, "A")
                    result['ipv4'] = [str(ip) for ip in answers]
                    logger.debug(f"Успешный резолвинг IPv4 {domain} через {server}: {result['ipv4']}")
                except dns.resolver.NoAnswer:
                    logger.debug(f"DNS {server}: нет IPv4 ответа для {domain}")
                except Exception as e:
                    logger.debug(f"DNS {server} IPv4 ошибка для {domain}: {str(e)}")

            if config["dns_fwd"]["resolver"]["ip_type"]["ipv6"]:
                try:
                    answers = resolver.resolve(domain, "AAAA")
                    result['ipv6'] = [str(ip) for ip in answers]
                    logger.debug(f"Успешный резолвинг IPv6 {domain} через {server}: {result['ipv6']}")
                except dns.resolver.NoAnswer:
                    logger.debug(f"DNS {server}: нет IPv6 ответа для {domain}")
                except Exception as e:
                    logger.debug(f"DNS {server} IPv6 ошибка для {domain}: {str(e)}")

            if result:
                return result

        except dns.resolver.NXDOMAIN:
            logger.debug(f"DNS {server}: домен {domain} не существует")
        except dns.resolver.Timeout:
            logger.debug(f"DNS {server}: таймаут для {domain}")
        except Exception as e:
            logger.debug(f"DNS {server} общая ошибка для {domain}: {str(e)}")

    # Не удалось разрешить домен -> добавление в failed_cache
    cache_duration = config["dns_fwd"]["resolver"].get("ttl_failed_resolve", "1d")
    expiry = datetime.now() + parse_timedelta(cache_duration)
    failed_cache[domain] = expiry
    logger.debug(f"Добавлен в кэш неудачных запросов: {domain} (до {expiry})")
    return {}

def parse_query_log(log_path, domain_configs):
    """Парсинг лога или всех логов в директории (без загрузки всего файла)"""
    results = {list_name: {} for list_name in domain_configs}
    total_line_count = 0
    total_match_count = 0
    total_wildcard_matches = 0
    total_malformed_lines = 0

    logger.info("Активные шаблоны поиска:")
    for list_name, categories in domain_configs.items():
        for category, targets in categories.items():
            has_wildcards = any('*' in t for t in targets)
            logger.info(f"  {list_name}/{category}: {len(targets)} шаблонов (wildcards: {has_wildcards})")

    # Определение файлов для обработки
    if os.path.isdir(log_path):
        log_files = [os.path.join(log_path, f) for f in os.listdir(log_path)
                    if f.endswith('.log') and os.path.isfile(os.path.join(log_path, f))]
        logger.info(f"Обнаружена директория логов. Файлы для обработки: {len(log_files)}")

        # Вывод списка файлов журналов
        for log_file in log_files:
            logger.debug(f"  - {log_file} ({os.path.getsize(log_file)} байт)")
    else:
        log_files = [log_path]
        logger.info(f"Обработка одиночного файла: {log_path}")

    for log_file in log_files:
        if not os.path.exists(log_file):
            logger.warning(f"Файл лога не найден, пропускаем: {log_file}")
            continue

        logger.info(f"Старт обработки файла: {log_file}")

        file_line_count = 0
        file_match_count = 0
        file_wildcard_matches = 0
        file_malformed_lines = 0

        try:
            with open(log_file, "r") as f:
                logger.debug(f"Открыт файл {log_file}")
                mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

                logger.debug(f"Чтение строк из {log_file}")

                for line in iter(mmapped_file.readline, b""):
                    file_line_count += 1
                    total_line_count += 1

                    # Вывод прочитанных строк, каждые 1000
                    if file_line_count % 1000 == 0:
                        logger.debug(f"Обработано {file_line_count} строк в файле {log_file}")

                    line = line.decode("utf-8").strip()

                    try:
                        if not line.startswith('['):
                            file_malformed_lines += 1
                            total_malformed_lines += 1
                            continue

                        # Разделяет строку на части
                        parts = line.split(']', 1)
                        if len(parts) < 2:
                            file_malformed_lines += 1
                            total_malformed_lines += 1
                            continue

                        # Получает оставшуюся часть строки после даты
                        rest = parts[1].strip().split()
                        if len(rest) < 3:
                            file_malformed_lines += 1
                            total_malformed_lines += 1
                            continue

                        domain = rest[1].lower()
                        record_type = rest[2].upper()

                        if record_type not in ('A', 'AAAA'):
                            continue

                        # Обработка матчинга доменов
                        for list_name, categories in domain_configs.items():
                            for category, targets in categories.items():
                                for target in targets:
                                    if is_domain_match(domain, target):
                                        is_wildcard = '*' in target

                                        # Инициализация структуры результатов
                                        if category not in results[list_name]:
                                            results[list_name][category] = {
                                                'domains': {},
                                                'wildcards': set() if any('*' in t for t in targets) else None
                                            }

                                        # Сохраняет домен и шаблон, по которому он был обнаружен
                                        if domain not in results[list_name][category]['domains']:
                                            results[list_name][category]['domains'][domain] = {
                                                'target_template': f"{category} -> {target}"
                                            }

                                        if is_wildcard:
                                            file_wildcard_matches += 1
                                            total_wildcard_matches += 1
                                            if results[list_name][category]['wildcards'] is not None:
                                                results[list_name][category]['wildcards'].add(domain)
                                        file_match_count += 1
                                        total_match_count += 1
                                        break

                    except Exception as e:
                        logger.warning(f"Ошибка строки {file_line_count} в файле {log_file}: {e}")
                        file_malformed_lines += 1
                        total_malformed_lines += 1

                mmapped_file.close()
                logger.info(f"Файл {log_file} обработан: строк={file_line_count}, совпадений={file_match_count}, wildcards={file_wildcard_matches}")

        except Exception as e:
            logger.error(f"Критическая ошибка при обработке файла {log_file}: {e}")
            continue

    logger.info(f"Итого обработано файлов: {len(log_files)}")
    logger.info(f"Всего строк: {total_line_count}")
    logger.info(f"Всего совпадений: {total_match_count} (из них wildcards: {total_wildcard_matches})")
    if total_malformed_lines > 0:
        logger.warning(f"Всего строк с неверным форматом: {total_malformed_lines}")

    return results

def get_recent_queries(config):
    """Получает запросы из metrics API dnscrypt-proxy"""
    metrics_config = config["dns_fwd"]["metrics"]
    url = metrics_config["url"]
    timeout = metrics_config.get("timeout", 10)
    count = metrics_config.get("recent_count", 100)

    # Аутентификация (опционально)
    auth = None
    if metrics_config.get("auth_user") and metrics_config.get("auth_pass"):
        auth = (metrics_config["auth_user"], metrics_config["auth_pass"])

    try:
        response = requests.get(url, auth=auth, timeout=timeout)
        response.raise_for_status()
        data = response.json()

        # Последние N записей
        recent = data.get("recent_queries", [])
        if not recent:
            logger.warning("API metrics вернул пустой список recent_queries")
            return []

        # Ограничение количества
        recent = recent[:count]

        filtered = []
        for q in recent:
            query_type = q.get("type", "").upper()
            if query_type in ("A", "AAAA"):
                filtered.append({
                    "domain": q.get("domain", "").lower(),
                    "type": query_type,
                    "timestamp": q.get("timestamp", "")
                })

        logger.info(f"Получено {len(filtered)} запросов из metrics API")
        return filtered

    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка подключения к API metrics: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка парсинга JSON из API: {e}")
    except Exception as e:
        logger.error(f"Неожиданная ошибка при получении метрик: {e}")

    return []

def process_queries_from_api(queries, domain_configs):
    """Обрабатывает запросы из metrics API (аналогично parse_query_log)"""
    results = {list_name: {} for list_name in domain_configs}
    total_queries = len(queries)
    total_matches = 0

    if not queries:
        return results

    logger.info(f"Обработка {total_queries} запросов из metrics API...")

    for query in queries:
        domain = query["domain"]
        query_type = query["type"]

        for list_name, categories in domain_configs.items():
            for category, targets in categories.items():
                for target in targets:
                    if is_domain_match(domain, target):
                        is_wildcard = '*' in target

                        # Инициализация структуры результатов
                        if category not in results[list_name]:
                            results[list_name][category] = {
                                'domains': {},
                                'wildcards': set() if any('*' in t for t in targets) else None
                            }

                        # Сохраняет домен и шаблон
                        if domain not in results[list_name][category]['domains']:
                            results[list_name][category]['domains'][domain] = {
                                'target_template': f"{category} -> {target}"
                            }

                        if is_wildcard:
                            if results[list_name][category]['wildcards'] is not None:
                                results[list_name][category]['wildcards'].add(domain)

                        total_matches += 1
                        break

    logger.info(f"Найдено совпадений: {total_matches}")
    return results

def load_existing_results(file_path):
    """Загружает существующие результаты или возвращает пустую структуру"""
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return yaml.safe_load(f) or {}
    return {
        "meta": {},
        "categories": {}
    }

def save_results(results, dns_servers, timeout, config, domain_records):
    """Сохраняет статистику и дубликаты"""
    def decode_idn(domain):
        if domain and 'xn--' in domain:
            try:
                return domain.encode('ascii').decode('idna')
            except Exception as e:
                logger.debug(f"Ошибка декодирования IDN {domain}: {e}")
        return None

    def is_idn_domain(domain):
        if not isinstance(domain, str):
            return False
        if any(ord(char) > 127 for char in domain):
            return True
        if 'xn--' in domain:
            return True
        return False

    retention_days_domain = parse_timedelta(config["dns_fwd"]["storage_raw_data"]["retention_days_domain"]).days
    retention_days_ips = parse_timedelta(config["dns_fwd"]["storage_raw_data"]["retention_days_ips"]).days
    backup_files = config["dns_fwd"]["storage_raw_data"]["backup_files"]
    skip_duplicates = config["dns_fwd"]["storage_raw_data"].get("skip_duplicates", False)

    duplicates = {domain: records for domain, records in domain_records.items()
                 if len(records) > 1}

    total_stats = {
        'lists': 0,
        'domains': 0,
        'idn': 0,
        'wildcards': 0,
        'removed_domains': 0,
        'removed_ips': 0
    }

    # Вывод информации о дубликатах
    if not duplicates:
        logger.info("✔ Дубликатов не обнаружено.")
    else:
        total_duplicates = len(duplicates)
        duplicate_entries = sum(len(records) for records in duplicates.values())
        affected_files = set(
            record["file"] for records in duplicates.values() for record in records
        )
        logger.warning(
            f"Всего дубликатов: {total_duplicates} (в {len(affected_files)} файлах)"
        )
        if skip_duplicates:
            logger.warning("[!] Режим skip_duplicates=True - дубликаты исключены из результатов (в пределах конкретного Address List)")
        else:
            logger.info("[✓] Режим skip_duplicates=False - дубликаты включены в результаты")

    for list_name, categories in results.items():
        list_stats = {
            'domains': 0,
            'idn': 0,
            'wildcards': 0,
            'removed_domains': 0,
            'removed_ips': 0,
            'skipped_duplicates': 0
        }

        processed_domains_in_current_list = {}

        output_dir = Path("raw-data") / list_name / ("DNS")
        output_dir.mkdir(parents=True, exist_ok=True)
        result_file = output_dir / "results-dns.yaml"

        # Загружает существующие данные
        existing_data = load_existing_results(result_file)
        now = datetime.now()

        # Инициализирует new_data с метаданными
        new_data = OrderedDict([
            ("meta", {
                "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
                "dns_servers": dns_servers,
                "timeout": timeout,
                "update_mode": "incremental",
                "skip_duplicates": skip_duplicates
            }),
            ("categories", {})
        ])

        # 1. Копируем все старые категории (даже, если их нет в новых результатах)
        if "categories" in existing_data:
            for old_category, old_domains in existing_data["categories"].items():
                if old_category not in new_data["categories"]:
                    new_data["categories"][old_category] = {}

                # Копирует старые домены с проверкой retention
                for domain, old_domain_data in old_domains.items():
                    try:
                        last_seen = old_domain_data.get("last_seen")
                        if last_seen:
                            last_date = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                            days_passed = (now - last_date).days

                            if days_passed <= retention_days_domain:
                                # Копирует старый домен, с пометкой неактивный
                                domain_data_copy = dict(old_domain_data)
                                domain_data_copy["active"] = False
                                new_data["categories"][old_category][domain] = domain_data_copy
                            else:
                                # Устарел - удалить
                                list_stats['removed_domains'] += 1
                                total_stats['removed_domains'] += 1
                                logger.debug(f"Устаревший домен удалён: {domain} (прошло {days_passed} дней)")
                        else:
                            # Если нет last_seen, сохраняет с текущим временем
                            domain_data_copy = dict(old_domain_data)
                            domain_data_copy["last_seen"] = now.strftime("%Y-%m-%d %H:%M:%S")
                            domain_data_copy["active"] = False
                            new_data["categories"][old_category][domain] = domain_data_copy
                    except Exception as e:
                        logger.warning(f"Ошибка обработки старого домена {domain}: {e}")

        # 2. Обрабатывает новые результаты (если имеются)
        if categories:
            logger.debug(f"Обработка новых результатов для списка {list_name}")

            for category, data in categories.items():
                if not data or not data.get('domains'):
                    logger.debug(f"Категория {category} пустая, пропускаем")
                    continue

                # Инициализирует категорию, если новая
                if category not in new_data["categories"]:
                    new_data["categories"][category] = {}

                merged_domains = {}
                wildcards_in_category = data.get('wildcards', set()) or set()

                # Собирает домены для обрабатываемой категории из новых результатов
                all_domains_in_category = list(data['domains'].keys())

                # Фильтрация доменов с учетом skip_duplicates
                filtered_domains = []
                for domain in all_domains_in_category:
                    if skip_duplicates and domain in processed_domains_in_current_list:
                        list_stats['skipped_duplicates'] += 1
                        continue
                    processed_domains_in_current_list[domain] = True
                    filtered_domains.append(domain)

                if skip_duplicates and list_stats['skipped_duplicates'] > 0:
                    logger.info(f"Список {list_name}/{category}: пропущено {list_stats['skipped_duplicates']} дубликатов")

                # Если нет доменов после фильтрации - перейти к следующей категории
                if not filtered_domains:
                    continue

                # Резолвинг отфильтрованных доменов
                resolved_ips = resolve_domains_parallel(
                    domains=filtered_domains,
                    dns_servers=dns_servers,
                    timeout=timeout,
                    config=config
                )

                # Обрабатывает отфильтрованные домены
                for domain in filtered_domains:
                    try:
                        is_wildcard = domain in wildcards_in_category if wildcards_in_category is not None else False
                        is_idn = is_idn_domain(domain)

                        current_ips = resolved_ips.get(domain, {})
                        if current_ips:
                            # Формирует данные домена
                            domain_data = {
                                "active": True,
                                "last_seen": now.strftime("%Y-%m-%d %H:%M:%S"),
                                "target_template": data['domains'][domain]['target_template']
                            }

                            current_time = now.strftime("%Y-%m-%d %H:%M:%S")

                            # Обработка IPv4
                            if current_ips.get('ipv4'):
                                domain_data["ipv4"] = {
                                    "current": current_ips['ipv4'],
                                    "historical": {}
                                }
                                for ip in current_ips['ipv4']:
                                    domain_data["ipv4"]["historical"][ip] = current_time

                            # Обработка IPv6
                            if current_ips.get('ipv6'):
                                domain_data["ipv6"] = {
                                    "current": current_ips['ipv6'],
                                    "historical": {}
                                }
                                for ip in current_ips['ipv6']:
                                    domain_data["ipv6"]["historical"][ip] = current_time

                            if is_idn:
                                idn_name = decode_idn(domain)
                                if idn_name:
                                    domain_data["idn_name"] = idn_name
                                    list_stats['idn'] += 1

                            if is_wildcard:
                                list_stats['wildcards'] += 1

                            merged_domains[domain] = domain_data
                            list_stats['domains'] += 1

                    except Exception as e:
                        logger.error(f"Ошибка обработки {domain}: {e}")

                # 3. Объединяет с существующими данными для обрабатываемой категории
                if category in new_data["categories"]:
                    # Обновляет существующие домены
                    for domain, new_domain_data in merged_domains.items():
                        new_data["categories"][category][domain] = new_domain_data

                    # Обновляет historical IP доменов
                    for domain, domain_data in new_data["categories"][category].items():
                        if domain in merged_domains:
                            new_domain_data = merged_domains[domain]

                            # Обновляет historical IP из старых данных
                            if domain in existing_data.get("categories", {}).get(category, {}):
                                old_domain_data = existing_data["categories"][category][domain]

                                # Объединяет historical IPv4
                                if old_domain_data.get("ipv4") and new_domain_data.get("ipv4"):
                                    if "historical" not in new_domain_data["ipv4"]:
                                        new_domain_data["ipv4"]["historical"] = {}

                                    # Копирует старые historical IP
                                    if "historical" in old_domain_data["ipv4"]:
                                        for ip, timestamp in old_domain_data["ipv4"]["historical"].items():
                                            if ip not in new_domain_data["ipv4"]["historical"]:
                                                new_domain_data["ipv4"]["historical"][ip] = timestamp

                                    # Добавляет текущие IP
                                    for ip in new_domain_data["ipv4"]["current"]:
                                        new_domain_data["ipv4"]["historical"][ip] = current_time

                                    # Удаляет устаревшие IP (IPv4, IPv6)
                                    ips_to_remove = []
                                    for ip, timestamp in new_domain_data["ipv4"]["historical"].items():
                                        try:
                                            ip_date = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                                            if (now - ip_date).days > retention_days_ips:
                                                ips_to_remove.append(ip)
                                                list_stats['removed_ips'] += 1
                                        except Exception:
                                            ips_to_remove.append(ip)

                                    for ip in ips_to_remove:
                                        new_domain_data["ipv4"]["historical"].pop(ip, None)

                                if old_domain_data.get("ipv6") and new_domain_data.get("ipv6"):
                                    if "historical" not in new_domain_data["ipv6"]:
                                        new_domain_data["ipv6"]["historical"] = {}

                                    if "historical" in old_domain_data["ipv6"]:
                                        for ip, timestamp in old_domain_data["ipv6"]["historical"].items():
                                            if ip not in new_domain_data["ipv6"]["historical"]:
                                                new_domain_data["ipv6"]["historical"][ip] = timestamp

                                    for ip in new_domain_data["ipv6"]["current"]:
                                        new_domain_data["ipv6"]["historical"][ip] = current_time

                                    ips_to_remove = []
                                    for ip, timestamp in new_domain_data["ipv6"]["historical"].items():
                                        try:
                                            ip_date = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                                            if (now - ip_date).days > retention_days_ips:
                                                ips_to_remove.append(ip)
                                                list_stats['removed_ips'] += 1
                                        except Exception:
                                            ips_to_remove.append(ip)

                                    for ip in ips_to_remove:
                                        new_domain_data["ipv6"]["historical"].pop(ip, None)

                else:
                    new_data["categories"][category] = merged_domains

        # 4. Сохраняем данные
        if new_data["categories"]:
            # Ротация бэкапов
            if backup_files > 0 and result_file.exists():
                backup_dir = output_dir / "backups"
                backup_dir.mkdir(exist_ok=True)
                backups = sorted(backup_dir.glob("results_*.yaml"), key=os.path.getmtime)
                for old_backup in backups[:-backup_files+1]:
                    old_backup.unlink()
                backup_file = backup_dir / f"results_{now.strftime('%Y%m%d_%H%M%S')}.yaml"
                with open(backup_file, "w") as f:
                    backup_data = convert_ordered_dict(existing_data)
                    yaml.dump(backup_data, f, sort_keys=False, allow_unicode=True)

            # Сохранение новых данных
            with open(result_file, "w") as f:
                data_to_save = convert_ordered_dict(new_data)
                yaml.dump(data_to_save, f, sort_keys=False, allow_unicode=True)

            total_stats['lists'] += 1
            total_stats['domains'] += list_stats['domains']
            total_stats['idn'] += list_stats['idn']
            total_stats['wildcards'] += list_stats['wildcards']
            total_stats['removed_ips'] += list_stats['removed_ips']

            logger.info(
                f"\nИтоги списка {list_name}: "
                f"{list_stats['domains']} доменов | "
                f"IDN: {list_stats['idn']} | "
                f"Wildcards: {list_stats['wildcards']} "
            )
        else:
            logger.warning(f"Список {list_name}: нет данных для сохранения")

    # Итоговый отчет
    logger.info("\n=== Итоговая статистика ===")
    logger.info(f"Обработано списков: {total_stats['lists']}")
    logger.info(f"Всего доменов: {total_stats['domains']}")
    logger.info(f"Из них IDN: {total_stats['idn']}")
    logger.info(f"Из них Wildcards: {total_stats['wildcards']}")
    logger.info(f"Удалено устаревших доменов: {total_stats['removed_domains']}")
    logger.info(f"Удалено устаревших IP: {total_stats['removed_ips']}")

    if not skip_duplicates:
        logger.info("\n=== Дублирующиеся шаблоны ===")
        if not duplicates:
            logger.info("✔ Дубликатов не обнаружено.")

    if total_stats['lists'] == 0:
        logger.warning("Нет данных для сохранения! Проверьте шаблоны поиска.")
    else:
        logger.info("\n=== Обработка завершена успешно! ===")

# 5. Точка входа
def main():
    try:
        config, address_lists, domain_configs, domain_records = load_configs()
        global logger, failed_cache

        logger = setup_logging(config)
        logger.info("\n===== Запуск dns_fwd.py - поиск доменов =====")

        # Проверка DNS-серверов
        dns_servers = config["dns_fwd"]["resolver"]["dns_servers"]
        timeout = config["dns_fwd"]["resolver"]["timeout"]

        logger.info("Проверка DNS-серверов...")
        available_servers = []
        for server in dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [server]
                resolver.timeout = 2
                resolver.lifetime = 4
                resolver.resolve("google.com", "A")
                available_servers.append(server)
                logger.info(f"DNS сервер {server} доступен")
            except Exception as e:
                logger.warning(f"DNS сервер {server} недоступен: {type(e).__name__}")

        if not available_servers:
            logger.error("Нет доступных DNS-серверов!")
            return

        # Загрузка кэша
        failed_cache = load_failed_cache(config)

        # Определяем источник данных
        data_source = config["dns_fwd"].get("data_source", "logs")
        logger.info(f"Источник данных: {data_source}")

        if data_source == "metrics":
            # Данные из API
            queries = get_recent_queries(config)
            if not queries:
                logger.warning("Не удалось получить данные из metrics, завершение работы")
                return
            results = process_queries_from_api(queries, domain_configs)
        else:
            # Данные из лог журналов
            log_path = config["dns_fwd"]["logging"]["query_log_path"]

            if not os.path.exists(log_path):
                logger.error(f"Путь не найден: {log_path}")
                return

            if os.path.isfile(log_path):
                if not validate_log_format(log_path):
                    logger.error("Файл лога не соответствует ожидаемому формату!")
                    return
            else:
                # Проверка формата для директории
                log_files = [os.path.join(log_path, f) for f in os.listdir(log_path)
                            if f.endswith('.log') and os.path.isfile(os.path.join(log_path, f))]
                if log_files:
                    sample_file = log_files[0]
                    if not validate_log_format(sample_file):
                        logger.error(f"Файл лога {sample_file} не соответствует формату!")
                        return
                else:
                    logger.error(f"В директории {log_path} не найдено .log файлов")
                    return

            results = parse_query_log(log_path, domain_configs)

        # Анализ дубликатов
        logger.info("\n=== Анализ дубликатов шаблонов ===")
        duplicates = analyze_duplicates(domain_records)

        # Сохранение результатов
        save_results(
            results=results,
            dns_servers=available_servers,
            timeout=timeout,
            config=config,
            domain_records=domain_records
        )

        # Сохранение кэша при успешном завершении
        save_failed_cache(failed_cache, config)

    except Exception as e:
        logger.error(f"Критическая ошибка: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    main()
