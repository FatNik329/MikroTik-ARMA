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
    return config["fetch_as_prefixes"]

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

def check_duplicates(as_list: list) -> list:
    """Проверяет и удаляет дубликаты AS номеров"""
    duplicates = {k: v for k, v in Counter(as_list).items() if v > 1}
    if duplicates:
        for asn, count in duplicates.items():
            logging.warning(f"Найден дубликат: {asn} (количество: {count})")
        return list(dict.fromkeys(as_list))  # Удаляет дубли с сохранением порядка
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
        logging.warning(f"Ошибка чтения кеша {cache_file}, создаём новый")
        return {}

def save_cache(cache_file: Path, data: dict):
    """Сохраняет данные в кеш-файл"""
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_file, "w") as f:
        json.dump(data, f, indent=2)

def fetch_api(asn: str, cache_file: Path, url: str, api_name: str, config, **kwargs):
    cache = load_cache(cache_file)
    start_time = time.time()

    if asn in cache and (time.time() - cache[asn]["timestamp"] < config['cache_serv']['ttl']):
        logging.info(f"Кэш сервиса {api_name} для {asn} актуален (время в кэше: {time.time() - cache[asn]['timestamp']:.2f} сек)")
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

def should_update(asn: str, prefixes: list, output_dir: Path) -> bool:
    """Определяет, нужно ли обновлять файл"""
    file_path = output_dir / f"{asn}.txt"
    if not file_path.exists():
        return True

    with open(file_path) as f:
        old_content = f.read().splitlines()

    return get_hash(prefixes) != get_hash(old_content)

def save_as_file(asn: str, prefixes: list, output_dir: Path):
    """Сохраняет префиксы в файл"""
    output_dir.mkdir(parents=True, exist_ok=True)
    file_path = output_dir / f"{asn}.txt"

    with open(file_path, "w") as f:
        f.write("\n".join(prefixes) + "\n")
    logging.info(f"Сохранён файл: {file_path}")

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

    # Загрузка AS номеров из конфига AS
    try:
        json5_path = paths["as_list"].with_suffix('.json5')
        with open(json5_path, 'r', encoding='utf-8') as f:
            as_list = json5.load(f)

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
    if not isinstance(as_list, list):
        logging.error(f"Неверный формат AS номеров в {list_name}")
        return

    unique_as = check_duplicates(as_list)
    if not unique_as:
        logging.error("Список AS пуст после проверки дубликатов!")
        return

    results = {
        "metadata": {
            "version": "1.1",
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

        # Получение порядка источников загрузки из общего конфига
        source_order = config.get('source_priority', ['ripe_stat', 'bgp_tools'])

        # Сопоставление имен источников из конфига
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
                logging.warning(f"Указан неизвестный источник '{source_key}' в конфиге source_priority. Пропускаем.")
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

        # Сохранение в структуре результатов
        results["as_data"][asn] = {
            "prefixes_v4": list(dict.fromkeys(prefixes_v4)),
            "prefixes_v6": list(dict.fromkeys(prefixes_v6)),
            "sources": sources,
            "last_updated": datetime.now().isoformat()
        }

        file_path = paths["output"] / f"{asn}.txt"
        if not file_path.exists() or should_update(asn, prefixes_v4 + prefixes_v6, paths["output"]):
            stats['updated'] += 1
        else:
            stats['skipped'] += 1

        time.sleep(2)  # Задержка между запросами

    # Обновление источников в метаданных
    used_sources = set()
    if any("ripe_stat" in asn_data.get("sources", []) for asn_data in results["as_data"].values()):
        used_sources.add("ripe_stat")
    if any("bgp_tools" in asn_data.get("sources", []) for asn_data in results["as_data"].values()):
        used_sources.add("bgp_tools")
    results["metadata"]["sources_used"] = list(used_sources)

    # Сохранение результатов
    save_results(list_name, results, config)

    # Итоговая статистика (без изменений)
    logging.info("\n=== Статистика обработки ===")
    logging.info(f"Всего AS: {stats['total']}")
    logging.info(f"Обновлено: {stats['updated']}")
    logging.info(f"Пропущено: {stats['skipped']}")
    logging.info(f"Ошибок: {stats['failed']}")
    logging.info(f"=== Обработка {list_name} завершена ===")

def main():
    args = parse_args()
    config = load_config()

    logging.info("\n===== Запуск fetch_as_prefixes.py - получение префиксов ASN  =====")

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
