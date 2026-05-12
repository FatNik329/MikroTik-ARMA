import requests
import os
import json
import json5
import time
from pathlib import Path
import hashlib
import logging
from collections import Counter
import argparse
import sys
import yaml
import shutil
from datetime import datetime

# Создание директории logs/fetch_as_prefixes
log_path = Path('logs/base/fetch_as_prefixes/fetch_as_prefixes.log')
log_path.parent.mkdir(parents=True, exist_ok=True)

# Настройка логгера
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def parse_args():
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--name-list", help="Обработать конкретную AddressList (по умолчанию обрабатываются все)")
    return parser.parse_args()

def load_config():
    """Загрузка конфигурации"""
    config_path = Path("configs/config.yaml")
    with open(config_path) as f:
        config = yaml.safe_load(f)
    fetch_config = config["fetch_as_prefixes"]
    if 'mode' not in fetch_config:
        fetch_config['mode'] = 'api'
    return fetch_config

def get_address_lists(name_list=None):
    """Получает список AddressLists для обработки"""
    lists_path = Path("configs/address_lists.yaml")
    try:
        with open(lists_path) as f:
            lists = yaml.safe_load(f)

            if isinstance(lists, dict) and "addressList" in lists:
                lists = lists["addressList"]

            if not lists:
                raise ValueError("Файл address_lists.yaml пуст или имеет неверный формат")

            if name_list:
                if name_list not in lists:
                    raise ValueError(f"AddressList {name_list} не найдена")
                return [name_list]
            return lists

    except Exception as e:
        logging.error(f"Ошибка чтения address_lists.yaml: {e}")
        raise

def get_paths(list_name):
    """Возвращает пути к файлам"""
    return {
        "as_list": Path(f"configs/AddressLists/{list_name}/AS/as_list.json5"),
        "cache_dir": Path(f"cache/fetch_as/{list_name}"),
        "output": Path(f"raw-data/{list_name}/AS"),
        "ripe_cache": Path(f"cache/fetch_as/{list_name}/ripe_cache.json"),
        "bgptools_cache": Path(f"cache/fetch_as/{list_name}/bgptools_cache.json"),
        "raw_data": Path(f"raw-data/{list_name}/AS/results-as.json")
    }

def parse_as_list_with_markers(as_list: list, asns_mapping: dict, config: dict) -> list:
    """
    Парсит список AS с поддержкой специальных маркеров.

    Маркеры:
    - "!AS<number>" - исключить конкретный AS
    - "!CC_<code>" - исключить все AS из указанной страны (code - двухбуквенный код)
    - "__ALL_AS__" - включить все AS из table.jsonl

    Args:
        as_list: Исходный список из as_list.json5
        asns_mapping: Словарь {ASN: {'name': ..., 'cc': ...}}
        config: Конфигурация (для получения ip_type фильтров)

    Returns:
        list: Отфильтрованный список ASN для обработки
    """
    include_all = False
    exclude_asns = set()
    exclude_countries = set()
    explicit_asns = set()

    for item in as_list:
        if not isinstance(item, str):
            logging.warning(f"Игнорирует нестроковый элемент: {item}")
            continue

        item = item.strip()

        # Маркер "все AS"
        if item == "__ALL_AS__":
            include_all = True
            logging.info("Обнаружен маркер __ALL_AS__: будут обработаны все AS из table.jsonl")

        # Маркер исключения конкретного AS
        elif item.startswith("!AS"):
            asn = item[1:]
            exclude_asns.add(asn)
            logging.debug(f"Исключает AS: {asn}")

        # Маркер исключения страны
        elif item.startswith("!CC_"):
            country_code = item[4:]
            exclude_countries.add(country_code.upper())
            logging.info(f"Исключает страну: {country_code}")

        # Обычный AS (только если не включен режим __ALL_AS__)
        elif not include_all:
            # Проверяет формат ASN
            if item.startswith("AS"):
                explicit_asns.add(item)
            else:
                logging.warning(f"Неверный формат ASN (должен начинаться с AS): {item}")

    # Формирует финальный список
    if include_all:
        # Берет все AS из mapping
        all_asns = set(asns_mapping.keys())

        # Применяет исключения
        result_asns = all_asns - exclude_asns

        # Исключает по странам
        if exclude_countries:
            country_excluded_asns = {
                asn for asn, data in asns_mapping.items()
                if data.get('cc', '').upper() in exclude_countries
            }
            result_asns -= country_excluded_asns
            logging.info(f"Исключено AS по странам {exclude_countries}: {len(country_excluded_asns)} шт")

        logging.info(f"Итоговое количество AS для обработки: {len(result_asns)} (из {len(all_asns)} всего)")
        return sorted(list(result_asns))
    else:
        # Использует только явно указанные AS
        result_asns = explicit_asns - exclude_asns

        # Исключает по странам
        if exclude_countries:
            country_excluded = {
                asn for asn in result_asns
                if asns_mapping.get(asn, {}).get('cc', '').upper() in exclude_countries
            }
            result_asns -= country_excluded
            if country_excluded:
                logging.info(f"Исключено AS по странам {exclude_countries}: {', '.join(sorted(country_excluded))}")

        logging.info(f"Итоговое количество AS для обработки: {len(result_asns)} (из {len(explicit_asns)} указанных)")
        return sorted(list(result_asns))

def main():
    args = parse_args()
    config = load_config()

    logging.info("\n===== Запуск fetch_as_prefixes.py - получение префиксов ASN  =====")
    logging.info(f"Режим работы: {config.get('mode', 'api')}")

    # Получение списков для обработки
    try:
        lists = get_address_lists(args.name_list)
        logging.info(f"Найдены списки для обработки: {lists}")

    except Exception as e:
        logging.error(f"Ошибка получения списка AddressLists: {e}")
        sys.exit(1)

    # Обработка каждого AddressList
    for list_name in lists:
        logging.info(f"\n=== Начало обработки AddressList: {list_name} ===")
        process_list(list_name, config)

    logging.info("===== Скрипт успешно выполнен! =====")

def check_duplicates(as_list: list) -> list:
    """Проверяет и удаляет дубликаты AS номеров"""
    duplicates = {k: v for k, v in Counter(as_list).items() if v > 1}
    if duplicates:
        for asn, count in duplicates.items():
            logging.warning(f"Найден дубликат: {asn} (количество: {count})")
        return list(dict.fromkeys(as_list))  # Удаляет дубли с сохранениет порядка
    return as_list

def get_hash(data: list) -> str:
    """Возвращает SHA-256 хеш списка префиксов"""
    return hashlib.sha256("\n".join(data).encode()).hexdigest()

def load_cache(cache_file: Path) -> dict:
    """Загружает кеш-файл"""
    try:
        if cache_file.exists():
            with open(cache_file) as f:
                return json.load(f)
        return {}
    except json.JSONDecodeError:
        logging.warning(f"Ошибка чтения кеша {cache_file}, создание нового.")
        return {}

def save_cache(cache_file: Path, data: dict):
    """Сохраняет данные в кеш-файл"""
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_file, "w") as f:
        json.dump(data, f, indent=2)

def fetch_api(asn: str, cache_file: Path, url: str, api_name: str, config, **kwargs):
    cache = load_cache(cache_file)
    start_time = time.time()

    if asn in cache and (time.time() - cache[asn]["timestamp"] < config['cache_raw_results']['ttl']):
        logging.info(f"Кэш сервиса {api_name} для {asn} актуален (вретя в кэше: {time.time() - cache[asn]['timestamp']:.2f} сек)")
        return cache[asn]["prefixes"]

    for attempt in range(config['settings_api']['max_retries']):
        try:
            logging.info(f"Запрос к {api_name} для {asn} (попытка {attempt + 1}, URL: {url})")
            response = requests.get(url, headers={"User-Agent": config['settings_api']['user_agent']}, timeout=15)
            response.raise_for_status()
            response_time = time.time() - start_time
            logging.info(f"Время ответа: {response_time:.2f} сек, код ответа: {response.status_code}")

            if kwargs.get('is_json', True):
                data = response.json()
                if "status" in data and data["status"] == "error":
                    error_message = data.get("status_message", "Неизвестная ошибка")
                    logging.error(f"{api_name}: Ошибка от API: {error_message}")
                    raise ValueError(f"Ошибка от API: {error_message}")
                prefixes = kwargs['parser_func'](data) if kwargs.get('parser_func') else []
            else:
                prefixes = kwargs['parser_func'](response.text) if kwargs.get('parser_func') else []

            if not prefixes:
                logging.warning(f"{api_name}: Пустой ответ для {asn}")
                return []

            cache[asn] = {"prefixes": prefixes, "timestamp": time.time()}
            save_cache(cache_file, cache)
            return prefixes

        except requests.exceptions.RequestException as e:
            logging.error(f"{api_name}: Попытка {attempt + 1}: Ошибка сети: {e}")
        except json.JSONDecodeError as e:
            logging.error(f"{api_name}: Попытка {attempt + 1}: Ошибка парсинга JSON: {e}")
        except ValueError as e:
            logging.error(f"{api_name}: Попытка {attempt + 1}: Пустой ответ или ошибка от API: {e}")
        except Exception as e:
            logging.exception(f"{api_name}: Попытка {attempt + 1}: Неизвестная ошибка: {e}")

        time.sleep(config['settings_api']['delay'] * (attempt + 1))

    return [] # Возвращение пустого списка, если все попытки неудачны

def fetch_ripe_stat(asn: str, cache_file: Path, config, **kwargs) -> list:
    """Получает префиксы через RIPE Stat API."""
    url_template = config.get('url_service', {}).get('ripe_stat', "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}")
    url = url_template.format(asn=asn)

    def parse_ripe(data: dict, config: dict) -> list:
        """Парсит ответ от RIPE Stat API. Обрабатывает ошибки."""
        try:
            if data["status"] == "error":
                raise ValueError(f"Ошибка от RIPE Stat: {data.get('status_message', 'Неизвестная ошибка')}")

            prefixes = []
            for p in data["data"].get("prefixes", []):
                prefix = p["prefix"]
                if ("." in prefix and config['ip_type']['ipv4']) or (":" in prefix and config['ip_type']['ipv6']):
                    prefixes.append(prefix)

            if not prefixes:
                raise ValueError("RIPE Stat вернул пустой список префиксов")
            return prefixes
        except (KeyError, TypeError) as e:
            logging.error(f"Ошибка парсинга ответа RIPE Stat: {e}. Данные: {data}")
            raise ValueError("Ошибка парсинга ответа RIPE Stat") from e

    return fetch_api(
        asn=asn,
        cache_file=cache_file,
        url=url,
        api_name="RIPE Stat",
        parser_func=lambda data: parse_ripe(data, config),
        config=config,
        **kwargs
    )

def fetch_bgptools(asn: str, cache_file: Path, config, **kwargs) -> list:
    """Получает префиксы через bgp.tools."""
    url = config.get('url_service', {}).get('bgp_tools', "https://bgp.tools/table.txt")

    def parse_bgptools(response_text: str, config: dict) -> list:
        """Парсит ответ от bgp.tools."""
        prefixes = []
        for line in response_text.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[-1] == asn.lstrip("AS"):
                prefix = parts[0]
                if ("." in prefix and config['ip_type']['ipv4']) or (":" in prefix and config['ip_type']['ipv6']):
                    prefixes.append(prefix)
        return prefixes

    return fetch_api(
        asn=asn,
        cache_file=cache_file,
        url=url,
        parser_func=lambda text: parse_bgptools(text, config),
        api_name="bgp.tools",
        is_json=False,
        config=config,
        **kwargs
    )

def load_asns_mapping(asns_file: Path) -> dict:
    """
    Загружает CSV с соответствием ASN -> информация.

    Returns:
        dict: {ASN: {'name': str, 'cc': str, 'class': str}}
    """
    asn_mapping = {}
    try:
        with open(asns_file, 'r', encoding='utf-8') as f:
            # Читает заголовок
            header = f.readline().strip().split(',')
            # Определяет индексы колонок
            col_index = {col: idx for idx, col in enumerate(header)}

            for line in f:
                line = line.strip()
                if not line:
                    continue

                parts = line.split(',')
                if not parts or not parts[0].startswith('AS'):
                    continue

                asn = parts[0]

                # Извлекает данные с проверкой наличия колонок
                asn_mapping[asn] = {
                    'name': parts[col_index.get('name', 1)] if len(parts) > col_index.get('name', 1) else "",
                    'class': parts[col_index.get('class', 2)] if len(parts) > col_index.get('class', 2) else "",
                    'cc': parts[col_index.get('cc', 3)] if len(parts) > col_index.get('cc', 3) else ""
                }

        logging.info(f"Загружено {len(asn_mapping)} ASN из {asns_file}")
        return asn_mapping

    except Exception as e:
        logging.error(f"Ошибка загрузки ASN mapping: {e}")
        return {}

def should_update(asn: str, prefixes: list, output_dir: Path) -> bool:
    """Определяет, нужно ли обновлять файл"""
    file_path = output_dir / f"{asn}.txt"
    if not file_path.exists():
        return True

    try:
        with open(file_path) as f:
            old_content = f.read().splitlines()
        return get_hash(prefixes) != get_hash(old_content)
    except Exception as e:
        logging.warning(f"Ошибка чтения файла {file_path}: {e}")
        return True

def save_as_file(asn: str, prefixes: list, output_dir: Path, list_name: str = None, config: dict = None, default_output_dir: Path = None):
    """
    Сохраняет префиксы в файл ТОЛЬКО если указан пользовательский путь.

    Args:
        asn: Номер AS
        prefixes: Список префиксов
        output_dir: Путь по умолчанию (не используется)
        list_name: Имя AddressList (для получения пользовательского пути)
        config: Конфигурация (для получения настроек путей)
        default_output_dir: Стандартный путь raw-data (для проверки дублей)
    """
    # Если генерация отключена - выход
    if not config or not config.get('enable_gen_asn_txt', False):
        logging.debug(f"Генерация TXT файлов отключена в конфиге для {asn}")
        return

    # Получает пользовательский путь из конфига
    custom_paths = config.get('path_save_asn_txt', {})

    if list_name not in custom_paths:
        logging.debug(f"Для листа {list_name} не указан пользовательский путь в path_save_asn_txt - TXT файл не создаётся")
        return

    custom_path = Path(custom_paths[list_name])

    # Преобразует в абсолютный путь
    if not custom_path.is_absolute():
        custom_path = Path.cwd() / custom_path

    # Проверка на совпадение пользовательского пути
    if default_output_dir and custom_path.resolve() == default_output_dir.resolve():
        logging.warning(f"Пользовательский путь для {list_name} совпадает со стандартным ({default_output_dir}).")
        return

    # Проверяет доступность директории
    try:
        custom_path.mkdir(parents=True, exist_ok=True)
        logging.debug(f"Для листа {list_name} используется пользовательский путь для TXT файлов: {custom_path}")
    except Exception as e:
        logging.error(f"Не удалось создать пользовательскую директорию {custom_path}: {e}")
        return

    # Сохраняет файл
    file_path = custom_path / f"{asn}.txt"

    try:
        with open(file_path, "w") as f:
            f.write("\n".join(prefixes) + "\n")
        logging.debug(f"Сохранён TXT файл (пользовательский путь): {file_path}")
    except Exception as e:
        logging.error(f"Ошибка сохранения TXT файла {file_path}: {e}")

def save_results(list_name, data, config):
    """Сохранение результатов в raw-data"""
    output_dir = Path(f"raw-data/{list_name}/AS")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Рассчет статистики
    total_v4 = sum(len(v["prefixes_v4"]) for v in data["as_data"].values())
    total_v6 = sum(len(v["prefixes_v6"]) for v in data["as_data"].values())

    data["metadata"].update({
        "total_as": len(data["as_data"]),
        "total_prefixes_v4": total_v4,
        "total_prefixes_v6": total_v6
    })

    # Основной файл и директория для бэкапов
    output_file = output_dir / "results-as.json"
    backup_dir = output_dir / "backups"
    backup_dir.mkdir(exist_ok=True)

    # Создание бэкапа если файл существует
    if output_file.exists():
        try:
            # Получение настроек из конфига
            max_backups = int(config.get('storage_raw_data', {}).get('backup_files', 3))

            # Создание нового бэкапа
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = backup_dir / f"results_{timestamp}.json"
            shutil.copy(output_file, backup_file)
            logging.info(f"Создан бэкап: {backup_file.name}")

            # Ротация бэкапов
            backups = sorted(backup_dir.glob("results_*.json"), key=os.path.getmtime)
            if len(backups) > max_backups:
                for old_backup in backups[:-max_backups]:
                    try:
                        old_backup.unlink()
                        logging.info(f"Удалён старый бэкап: {old_backup.name}")
                    except Exception as e:
                        logging.warning(f"Ошибка удаления {old_backup}: {e}")

        except Exception as e:
            logging.error(f"Ошибка при создании бэкапа: {e}")

    # Сохранение новых данных
    try:
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logging.info(f"Сохранены результаты: {output_file}")
    except Exception as e:
        logging.error(f"Ошибка сохранения результатов: {e}")
        raise

def process_list(list_name, config):
    """Обработка одного AddressList"""
    paths = get_paths(list_name)

    mode = config.get('mode', 'api')

    # Загрузка AS номеров из конфига AS
    try:
        json5_path = paths["as_list"].with_suffix('.json5')
        with open(json5_path, 'r', encoding='utf-8') as f:
            raw_as_list = json5.load(f)  # Сохраняет исходный список для маркеров

    except FileNotFoundError:
        logging.error(f"Файл {json5_path} не найден!")
        return
    except json5.JSONDecodeError as e:
        logging.error(f"Ошибка разбора JSON5 в файле {json5_path}: {e}")
        return
    except Exception as e:
        logging.exception(f"Непредвиденная ошибка при загрузке списка AS: {e}")
        return

    # Проверка данных
    if not isinstance(raw_as_list, list):
        logging.error(f"Неверный формат AS номеров в {list_name}")
        return

    unique_as = check_duplicates(raw_as_list)

    if not unique_as and mode == 'api':
        logging.error("Список AS пуст после проверки дубликатов!")
        return

    # Ветвление по режиму работы
    if mode == 'api':
        process_api_mode(list_name, unique_as, paths, config)
    elif mode == 'file':
        process_file_mode(list_name, raw_as_list, paths, config)
    else:
        logging.error(f"Неизвестный режим работы: {mode}")

def process_api_mode(list_name, unique_as, paths, config):
    """Обработка через API (существующая логика)"""
    results = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "ipv4_enabled": config['ip_type']['ipv4'],
            "ipv6_enabled": config['ip_type']['ipv6'],
            "sources_used": []
        },
        "as_data": {}
    }

    stats = {'total': len(unique_as), 'updated': 0, 'skipped': 0, 'failed': 0}
    processed_as = set()

    for asn in unique_as:
        if asn in processed_as:
            continue

        logging.info(f"Обработка {asn} ({len(processed_as) + 1}/{len(unique_as)})")
        processed_as.add(asn)

        all_prefixes = []
        sources = []
        need_data = config['ip_type']['ipv4'] or config['ip_type']['ipv6']

        source_order = config.get('source_priority', ['ripe_stat', 'bgp_tools'])
        source_dispatcher = {
            'ripe_stat': {
                'fetch_func': fetch_ripe_stat,
                'cache_file': paths["ripe_cache"],
                'source_name': 'ripe_stat'
            },
            'bgp_tools': {
                'fetch_func': fetch_bgptools,
                'cache_file': paths["bgptools_cache"],
                'source_name': 'bgp_tools'
            }
        }

        for source_key in source_order:
            if not need_data:
                break
            source_config = source_dispatcher.get(source_key)
            if not source_config:
                logging.warning(f"Указан неизвестный источник '{source_key}' в конфиге source_priority.")
                continue
            prefixes = source_config['fetch_func'](asn, source_config['cache_file'], config)
            if prefixes:
                all_prefixes.extend(prefixes)
                sources.append(source_config['source_name'])
                need_data = False

        if not all_prefixes:
            stats['failed'] += 1
            continue

        prefixes_v4 = [p for p in all_prefixes if "." in p]
        prefixes_v6 = [p for p in all_prefixes if ":" in p]

        results["as_data"][asn] = {
            "prefixes_v4": list(dict.fromkeys(prefixes_v4)),
            "prefixes_v6": list(dict.fromkeys(prefixes_v6)),
            "sources": sources,
            "last_updated": datetime.now().isoformat()
        }

        # Сохраняет TXT файл с учетом пользовательских путей
        all_prefixes_list = prefixes_v4 + prefixes_v6
        save_as_file(asn, all_prefixes_list, paths["output"], list_name, config)

        if should_update(asn, all_prefixes_list, paths["output"]):
            stats['updated'] += 1
        else:
            stats['skipped'] += 1

        time.sleep(2)

    # Обновление источников в метаданных
    used_sources = set()
    for asn_data in results["as_data"].values():
        used_sources.update(asn_data.get("sources", []))
    results["metadata"]["sources_used"] = list(used_sources)

    save_results(list_name, results, config)

    logging.info("\n=== Статистика обработки ===")
    logging.info(f"Всего AS: {stats['total']}")
    logging.info(f"Обновлено: {stats['updated']}")
    logging.info(f"Пропущено: {stats['skipped']}")
    logging.info(f"Ошибок: {stats['failed']}")
    logging.info(f"=== Обработка {list_name} завершена ===")

def process_file_mode(list_name, raw_as_list, paths, config):
    """
    Обработка через чтение локальных файлов с поддержкой маркеров.

    Args:
        list_name: Имя AddressList
        raw_as_list: Исходный список из as_list.json5 (с маркерами)
        paths: Словарь с путями к файлам
        config: Конфигурация
    """
    logging.info(f"Режим file: чтение данных для {list_name}")

    # Получает путь к директории с файлами из конфига
    storage_path = config.get('storage_raw_data', {}).get('path_external_data')
    if not storage_path:
        logging.error("В конфиге отсутствует параметр storage_raw_data.path_external_data")
        return

    data_dir = Path(storage_path)
    if not data_dir.is_absolute():
        data_dir = Path.cwd() / data_dir

    table_file = data_dir / "table.jsonl"
    asns_file = data_dir / "asns.csv"

    logging.info(f"Директория с данными: {data_dir}")
    logging.info(f"Файл префиксов: {table_file}")
    logging.info(f"Файл ASN mapping: {asns_file}")

    try:
        # Проверяет существование файлов
        if not table_file.exists():
            raise FileNotFoundError(f"Файл {table_file} не найден")
        if not asns_file.exists():
            raise FileNotFoundError(f"Файл {asns_file} не найден")

        # Загружает ASN mapping (с данными о странах)
        asn_mapping = load_asns_mapping(asns_file)
        if not asn_mapping:
            raise ValueError("Не удалось загрузить ASN mapping")

        # Применяет маркеры из raw_as_list
        filtered_as_list = parse_as_list_with_markers(raw_as_list, asn_mapping, config)

        if not filtered_as_list:
            logging.error("После применения маркеров не осталось AS для обработки.")
            return

        # Загружает префиксы из table.jsonl только для отфильтрованных AS
        prefixes_data = load_prefixes_from_table(table_file, filtered_as_list, config)

        # Формирует результаты
        results = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "ipv4_enabled": config['ip_type']['ipv4'],
                "ipv6_enabled": config['ip_type']['ipv6'],
                "sources_used": ["bgp_tools_file"],
                "source_mode": "file",
                "markers_processed": True
            },
            "as_data": {}
        }

        stats = {'total': len(filtered_as_list), 'updated': 0, 'skipped': 0, 'failed': 0}

        for asn in filtered_as_list:
            if asn not in prefixes_data:
                logging.warning(f"ASN {asn} не найден в {table_file.name}")
                stats['failed'] += 1
                continue

            asn_data = prefixes_data[asn]
            prefixes_v4 = asn_data['prefixes_v4']
            prefixes_v6 = asn_data['prefixes_v6']

            if not prefixes_v4 and not prefixes_v6:
                logging.warning(f"ASN {asn} не имеет префиксов (или фильтры IP отключены)")
                stats['failed'] += 1
                continue

            # Добавляет информацию об AS из mapping
            as_info = asn_mapping.get(asn, {})

            results["as_data"][asn] = {
                "prefixes_v4": prefixes_v4,
                "prefixes_v6": prefixes_v6,
                "sources": ["bgp_tools_file"],
               # "last_updated": datetime.now().isoformat(),
                "as_name": as_info.get('name', ''),
                "as_class": as_info.get('class', ''),
                "as_cc": as_info.get('cc', '')
            }

            # Сохраняет TXT файл с учетом пользовательских путей
            all_prefixes = prefixes_v4 + prefixes_v6
            save_as_file(asn, all_prefixes, paths["output"], list_name, config, paths["output"])

            # Проверяет необходимость обновления
            output_dir = paths["output"]
            if not output_dir.exists() or should_update(asn, all_prefixes, output_dir):
                stats['updated'] += 1
            else:
                stats['skipped'] += 1

        stats['failed'] = len(filtered_as_list) - len(results["as_data"])

        # Сохраняет общий результат
        save_results(list_name, results, config)

        # Логирует статистику с деталями по маркерам
        logging.info("\n=== Статистика обработки (file mode) ===")
        logging.info(f"Всего AS после фильтрации: {stats['total']}")
        logging.info(f"Обновлено: {stats['updated']}")
        logging.info(f"Пропущено: {stats['skipped']}")
        logging.info(f"Не найдено/Ошибок: {stats['failed']}")

        # Логирует информацию об исключенных AS, если были маркеры
        if any(isinstance(x, str) and (x.startswith('!') or x == '__ALL_AS__') for x in raw_as_list):
            logging.info("Были применены маркеры фильтрации из as_list.json5")

        logging.info(f"=== Обработка {list_name} завершена ===")

    except Exception as e:
        logging.error(f"Ошибка в file mode: {e}")
        raise

def load_prefixes_from_table(table_file: Path, asn_list: list, config: dict) -> dict:
    """Загружает префиксы из table.jsonl для указанных ASN"""
    as_set = set(asn_list)
    result = {asn: {'prefixes_v4': [], 'prefixes_v6': []} for asn in as_set}

    try:
        with open(table_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    asn_value = data.get('ASN')
                    cidr = data.get('CIDR', '')

                    # Формирует ключ ASN
                    asn_key = f"AS{asn_value}" if not str(asn_value).startswith('AS') else str(asn_value)

                    if asn_key in as_set:
                        # Фильтрует по типу IP
                        if '.' in cidr and config['ip_type']['ipv4']:
                            result[asn_key]['prefixes_v4'].append(cidr)
                        elif ':' in cidr and config['ip_type']['ipv6']:
                            result[asn_key]['prefixes_v6'].append(cidr)

                except json.JSONDecodeError as e:
                    logging.warning(f"Ошибка парсинга строки {line_num}: {e}")
                    continue

    except Exception as e:
        logging.error(f"Ошибка чтения {table_file}: {e}")
        raise

    # Удаляет дубликаты
    for asn in result:
        result[asn]['prefixes_v4'] = list(dict.fromkeys(result[asn]['prefixes_v4']))
        result[asn]['prefixes_v6'] = list(dict.fromkeys(result[asn]['prefixes_v6']))

    return result

def main():
    args = parse_args()
    config = load_config()

    logging.info("\n===== Запуск fetch_as_prefixes.py - получение префиксов ASN  =====")
    logging.info(f"Режим работы: {config.get('mode', 'api')}")

    # Получение списков для обработки
    try:
        lists = get_address_lists(args.name_list)
        logging.info(f"Найдены списки для обработки: {lists}")
    except Exception as e:
        logging.error(f"Ошибка получения списка AddressLists: {e}")
        sys.exit(1)

    # Обработка каждого AddressList
    for list_name in lists:
        logging.info(f"\n=== Начало обработки AddressList: {list_name} ===")
        process_list(list_name, config)

    logging.info("===== Скрипт успешно выполнен! =====")

if __name__ == "__main__":
    start_time = time.time()
    main()
    logging.info(f"Выполнено за {time.time() - start_time:.2f} секунд")
