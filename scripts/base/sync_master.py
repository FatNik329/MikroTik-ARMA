import os
import time
import logging
import argparse
import json
from pathlib import Path
from routeros_api import RouterOsApiPool
from routeros_api.exceptions import RouterOsApiConnectionError
import ssl
import yaml

# Режимы синхронизации
VALID_MODES = ["domains", "ips", "asn", "dom-asn", "ips-asn"]

# Маппинг режимов и обрабатываемых файлов
MODE_FILE_PATTERNS = {
    "domains": {
        "ipv4": ["DNS/*-domains-v4.rsc"],
        "ipv6": ["DNS/*-domains-v6.rsc"]
    },
    "dom-asn": {
        "ipv4": ["DNS/*-domains-v4.rsc", "AS/*-ipv4.rsc"],
        "ipv6": ["DNS/*-domains-v6.rsc", "AS/*-ipv6.rsc"]
    },
    "ips": {
        "ipv4": ["DNS/*-ipv4.rsc"],
        "ipv6": ["DNS/*-ipv6.rsc"]
    },
    "ips-asn": {
        "ipv4": ["DNS/*-ipv4.rsc", "AS/*-ipv4.rsc"],
        "ipv6": ["DNS/*-ipv6.rsc", "AS/*-ipv6.rsc"]
    },
    "asn": {
        "ipv4": ["AS/*-ipv4.rsc"],
        "ipv6": ["AS/*-ipv6.rsc"]
    }
}

def parse_args():
    """Парсинг аргументов командной строки (опциональные)"""
    parser = argparse.ArgumentParser(description='Синхронизация Address Lists MikroTik')
    valid_modes = ["domains", "ips", "asn", "dom-asn", "ips-asn"]
    parser.add_argument("--mode-run",
                       choices=valid_modes,
                       help=f"Режим работы ({'/'.join(valid_modes)})")
    parser.add_argument("--list-name", help="Синхронизировать конкретный AddressList")
    parser.add_argument("--dry-run", action="store_true", help="Тестовый режим без изменений")
    return parser.parse_args()

# Создание директории logs/base/sync_master
log_path = Path('logs/base/sync_master/sync_master.log')
log_path.parent.mkdir(parents=True, exist_ok=True)

def setup_logging(config):
    """Настройка логирования из конфига"""
    log_level = config["sync_master"]["logging"].get("log_level", "INFO").upper()
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler()
        ]
    )

def load_config():
    """Загрузка конфигурационных файлов с валидацией"""
    try:
        with open("configs/config.yaml") as f:
            config = yaml.safe_load(f)

        validate_config(config)

        with open("security/mikrotik.yaml") as f:
            mikrotik_config = yaml.safe_load(f)

        validate_mikrotik_config(mikrotik_config.get("devices", {}))
        return config, mikrotik_config
    except Exception as e:
        logging.error(f"Ошибка загрузки конфигурации: {e}")
        raise

def validate_config(config):
    """Валидация структуры конфигурации sync_master"""
    sync_cfg = config.get("sync_master", {}).get("setting_sync", {})

    # Проверка на включение типов адресов
    if not sync_cfg.get("ipv4_sync", True) and not sync_cfg.get("ipv6_sync", False):
        raise ValueError("ОШИБКА: В конфигурации отключены и IPv4, и IPv6. Включите хотя бы один.")

    # Список допустимых режимов
    valid_modes = ["domains", "ips", "asn", "dom-asn", "ips-asn"]
    current_mode = sync_cfg.get("mode")

    if current_mode not in valid_modes:
        error_msg = (
            f"Недопустимый режим работы: '{current_mode}'. "
            f"Допустимые значения: {', '.join(valid_modes)}"
        )
        logging.error(error_msg)
        raise ValueError(error_msg)

    if not isinstance(sync_cfg.get("ipv4_sync", True), bool):
        raise ValueError("ipv4_sync должен быть true/false")
    if not isinstance(sync_cfg.get("ipv6_sync", False), bool):
        raise ValueError("ipv6_sync должен быть true/false")

    if not 10 <= sync_cfg.get("batch_size", 0) <= 5000:
        raise ValueError("batch_size должен быть между 10 и 5000")

    if not 0 < sync_cfg.get("update_delay", 0) <= 5:
        raise ValueError("update_delay должен быть между 0 и 5")

def validate_mikrotik_config(devices):
    """Валидация конфигурации MikroTik"""
    if not devices:
        raise ValueError("Не найдены устройства в конфигурации")

    seen_hosts = set()
    for device_id, device in devices.items():
        # Проверка обязательных полей
        required = ['name', 'host', 'username', 'password']
        missing = [field for field in required if field not in device]
        if missing:
            raise ValueError(f"Устройство {device_id} не имеет обязательных полей: {', '.join(missing)}")

        # Проверка уникальности host
        if device['host'] in seen_hosts:
            raise ValueError(f"Дублирующийся host {device['host']} в устройстве {device_id}")
        seen_hosts.add(device['host'])

        # Проверка режима устройства (если указан)
        if 'type_mode' in device and device['type_mode'] not in VALID_MODES:
            logging.warning(f"Устройство {device_id} имеет недопустимый режим: {device['type_mode']}. Допустимые режимы: {', '.join(VALID_MODES)}")

        # Проверка list_name в security/mikrotik.yaml (если указан)
        if 'settings' in device and 'list_name' in device['settings']:
            if not isinstance(device['settings']['list_name'], list):
                raise ValueError(f"list_name для устройства {device_id} должен быть списком")
            if not all(isinstance(item, str) for item in device['settings']['list_name']):
                raise ValueError(f"Все элементы list_name для устройства {device_id} должны быть строками")

def check_ipv6_support(api):
    """Проверяет, включен ли пакет IPv6 на устройстве"""
    try:
        package_resource = api.get_resource('/system/package')
        ipv6_package = package_resource.get(name="ipv6")
        if not ipv6_package:
            return False
        return not ipv6_package[0].get('disabled', 'true') == 'true'
    except Exception as e:
        logging.warning(f"Ошибка проверки пакета IPv6: {e}. Предполагаем, что IPv6 отключен")
        return False

def get_rsc_files(list_name, mode, config=None, ipv6_supported=False):
    """Поиск RSC файлов для обработки с учетом ipv4/ipv6 настроек"""
    if config is None:
        config = {
            "sync_master": {
                "setting_sync": {
                    "ipv6_support": False
                }
            }
        }

    base_dir = Path(f"output-data/{list_name}")
    if not base_dir.exists():
        logging.error(f"Директория {base_dir} не существует!")
        return []

    ipv4_enabled = config["sync_master"]["setting_sync"].get("ipv4_sync", True)
    ipv6_enabled = config["sync_master"]["setting_sync"].get("ipv6_sync", False) and ipv6_supported

    # Получение шаблонов файлов для выбранного режима
    mode_patterns = MODE_FILE_PATTERNS.get(mode, {})
    file_patterns = []

    if ipv4_enabled and "ipv4" in mode_patterns:
        file_patterns.extend(mode_patterns["ipv4"])
    if ipv6_enabled and "ipv6" in mode_patterns:
        file_patterns.extend(mode_patterns["ipv6"])

    # Поиск файлов синхронизации
    files = []
    for pattern in file_patterns:
        found_files = list(base_dir.glob(pattern))
        if not found_files:
            logging.debug(f"Файлы по шаблону {pattern} не найдены")
        files.extend(found_files)

    # Поиск кастомных файлов (вне зависимости от режима)
    custom_dir = base_dir / "Custom"
    if custom_dir.exists():
        custom_files = list(custom_dir.glob("*.rsc"))
        if custom_files:
            logging.info(f"Найдены кастомные файлы в {list_name}/Custom/: {[f.name for f in custom_files]}")
            files.extend(custom_files)
        else:
            logging.debug(f"Кастомная директория {list_name}/Custom/ существует, но файлы .rsc не найдены")
    else:
        logging.debug(f"Кастомная директория {list_name}/Custom/ отсутствует")

    logging.info(f"Найдены файлы для {list_name}/{mode}: {[f.name for f in files]}")
    return files

def find_duplicates(entries):
    """Поиск дубликатов адресов"""
    addr_counts = {}
    for addr in entries:
        addr_counts[addr] = addr_counts.get(addr, 0) + 1
    return {addr: cnt for addr, cnt in addr_counts.items() if cnt > 1}

def parse_rsc_file(file_path, config):
    """Парсинг RSC файла с учетом настроек ipv4/ipv6"""
    entries = {}
    try:
        sync_settings = config["sync_master"]["setting_sync"]
        ipv4_enabled = sync_settings.get("ipv4_sync", True)
        ipv6_enabled = sync_settings.get("ipv6_sync", False)

        # Определение типа файла по имени
        filename = str(file_path)
        is_domains_file = 'domains' in filename
        is_ipv6_file = '-v6.rsc' in filename or '-ipv6.rsc' in filename
        is_ipv4_file = '-v4.rsc' in filename or '-ipv4.rsc' in filename
        is_dns_file = 'DNS/' in filename
        is_custom_file = 'Custom/' in filename # Кастомная директория

        # Пропускает файлы, которые не соответствуют указанным настройкам синхронизации
        if (is_ipv6_file and not ipv6_enabled) or (is_ipv4_file and not ipv4_enabled):
            logging.debug(f"Пропускаем файл {file_path.name} - не соответствует текущим настройкам синхронизации")
            return {}

        with open(file_path, 'r') as f:
            for line in f:
                if line.startswith("add address="):
                    address = line.strip().split()[1].split('=')[1]
                    parts = line.strip().split('comment=')
                    comment = parts[1].strip('"') if len(parts) > 1 else ""

                    # Для DNS и Custom файлов оставляем комментарии полностью как есть
                    if is_dns_file or is_custom_file:
                        pass
                    else:
                        # Для остальных файлов убираем дублирование если есть "->"
                        if comment and "->" in comment:
                            comment = comment.split("->")[-1].strip()

                    # Определение типа записи
                    is_ipv6 = is_ipv6_file or ':' in address

                    # Пропуск записей, не соответствующих настройкам
                    if is_ipv6 and not ipv6_enabled:
                        continue
                    if not is_ipv6 and not ipv4_enabled:
                        continue

                    # Нормализация IPv6 адреса (только для IP)
                    if is_ipv6 and not is_domains_file:
                        address = address.replace('/128', '')

                    # Сохранение типа записи для дальнейшей обработки
                    entry_type = 'ipv6-domain' if (is_domains_file and is_ipv6) else ('ipv6' if is_ipv6 else 'ipv4')
                    entries[address] = {
                        'comment': comment,
                        'type': entry_type,
                        'source': file_path.name
                    }

        duplicates = find_duplicates(entries)
        if duplicates:
            logging.warning(f"Найдены дубликаты в {file_path}:")
            for addr, cnt in duplicates.items():
                logging.warning(f"  {addr}: {cnt} повторений")

        return entries
    except Exception as e:
        logging.error(f"Ошибка чтения {file_path}: {e}")
        return {}

def get_current_static_entries(api, list_name, ipv6_supported=True):
    """Получение текущих записей с устройства MikroTik"""
    entries = {}

    # Получение IPv4 записей
    try:
        ipv4_resource = api.get_resource('/ip/firewall/address-list')
        items = ipv4_resource.get(list=list_name, dynamic="no")
        for item in items:
            if 'id' in item and 'address' in item:
                entries[item['address']] = {
                    'id': item['id'],
                    'comment': item.get('comment', '').strip(),
                    'type': 'ipv4'
                }
    except Exception as e:
        logging.error(f"Ошибка получения IPv4 списка: {e}")
        return None

    # Получение IPv6 записей
    if ipv6_supported:
        try:
            ipv6_resource = api.get_resource('/ipv6/firewall/address-list')
            items = ipv6_resource.get(list=list_name, dynamic="no")
            for item in items:
                if 'id' in item and 'address' in item:
                    address = item['address'].replace('/128', '')
                    entries[address] = {
                        'id': item['id'],
                        'comment': item.get('comment', '').strip(),
                        'type': 'ipv6'
                    }
        except Exception as e:
            logging.warning(f"Ошибка получения IPv6 записей: {e}. Продолжаем без IPv6")

    return entries

def check_existing_entries_batch(api, list_name, addresses, ipv6=False):
    """Массовая проверка существующих записей"""
    existing_addresses = set()
    resource = api.get_resource('/ipv6/firewall/address-list' if ipv6 else '/ip/firewall/address-list')

    try:
        batch_size = 100
        for i in range(0, len(addresses), batch_size):
            batch_addresses = addresses[i:i + batch_size]
            query = "|".join([f"address={addr}" for addr in batch_addresses])
            existing = resource.get(list=list_name, address=query)
            existing_addresses.update(item['address'] for item in existing)
    except Exception as e:
        logging.error(f"Ошибка массовой проверки записей: {e}")

    return existing_addresses

def process_batch(api, list_name, batch, operation, delay):
    """Пакетная обработка записей через API"""
    stats = {'processed': 0, 'errors': 0, 'skipped': 0}

    if not batch:
        return stats

    # Разделение записей по типам адресов (IPv4/IPv6)
    ipv4_batch = [item for item in batch if item.get('type') == 'ipv4' or ('.' in item.get('address', '') and ':' not in item.get('address', ''))]
    ipv6_batch = [item for item in batch if item.get('type') == 'ipv6' or ':' in item.get('address', '')]

    # Обработка IPv4 записей
    if ipv4_batch:
        ipv4_resource = api.get_resource('/ip/firewall/address-list')
        try:
            if operation == 'add':
                # Массовая проверка существующих IPv4 записей
                addresses_to_check = [item['address'] for item in ipv4_batch]
                existing_addresses = check_existing_entries_batch(api, list_name, addresses_to_check, False)

                # Фильтрация - только новые адреса
                new_batch = [item for item in ipv4_batch if item['address'] not in existing_addresses]
                stats['skipped'] += len(ipv4_batch) - len(new_batch)

                if new_batch:
                    # Массовое добавление IPv4
                    for item in new_batch:
                        ipv4_resource.add(list=list_name, address=item['address'], comment=item['comment'])
                        stats['processed'] += 1
                        time.sleep(delay)

            elif operation == 'remove':
                # Массовое удаление IPv4
                for item in ipv4_batch:
                    ipv4_resource.remove(id=item['id'])
                    stats['processed'] += 1
                    time.sleep(delay)

            elif operation == 'update':
                # Массовое обновление IPv4
                for item in ipv4_batch:
                    ipv4_resource.set(id=item['id'], address=item['address'], comment=item['comment'])
                    stats['processed'] += 1
                    time.sleep(delay * 2)

        except Exception as e:
            stats['errors'] += len(ipv4_batch)
            logging.error(f"Пакетная ошибка {operation} (IPv4): {str(e)}")

    # Обработка IPv6 записей
    if ipv6_batch:
        ipv6_resource = api.get_resource('/ipv6/firewall/address-list')
        try:
            if operation == 'add':
                # Массовая проверка существующих IPv6 записей
                addresses_to_check = [item['address'] for item in ipv6_batch]
                existing_addresses = check_existing_entries_batch(api, list_name, addresses_to_check, True)

                # Фильтрация - только новые адреса
                new_batch = [item for item in ipv6_batch if item['address'] not in existing_addresses]
                stats['skipped'] += len(ipv6_batch) - len(new_batch)

                if new_batch:
                    # Массовое добавление IPv6
                    for item in new_batch:
                        ipv6_resource.add(list=list_name, address=item['address'], comment=item['comment'])
                        stats['processed'] += 1
                        time.sleep(delay)

            elif operation == 'remove':
                # Массовое удаление IPv6
                for item in ipv6_batch:
                    ipv6_resource.remove(id=item['id'])
                    stats['processed'] += 1
                    time.sleep(delay)

            elif operation == 'update':
                # Массовое обновление IPv6
                for item in ipv6_batch:
                    ipv6_resource.set(id=item['id'], address=item['address'], comment=item['comment'])
                    stats['processed'] += 1
                    time.sleep(delay * 2)

        except Exception as e:
            stats['errors'] += len(ipv6_batch)
            logging.error(f"Пакетная ошибка {operation} (IPv6): {str(e)}")

    return stats

def sync_list(api, list_name, mode, config, device_config, args):
    """Основная функция синхронизации списка"""
    logging.debug(f"Начало обработки списка {list_name} (режим: {mode})")
    sync_start_time = time.time()

    # Получение настроек синхронизации
    sync_settings = config["sync_master"]["setting_sync"]
    ipv4_enabled = sync_settings.get("ipv4_sync", True)
    ipv6_enabled = sync_settings.get("ipv6_sync", False)

    if not ipv4_enabled and not ipv6_enabled:
        logging.error("ОШИБКА: В конфигурации отключены и IPv4, и IPv6. Должен быть хотя бы один раздел для синхронизации.")
        logging.error("Включите хотя бы один параметр в config.yaml:")
        logging.error("  ipv4_sync: true  # или")
        logging.error("  ipv6_sync: true")
        return False

    # Проверка включения IPv6 на устройстве
    ipv6_supported = ipv6_enabled and check_ipv6_support(api)

    rsc_files = get_rsc_files(list_name, mode, config, ipv6_supported)
    if not rsc_files:
        return False

    # Загрузка целевых данных
    target_entries = {}
    for file in rsc_files:
        file_entries = parse_rsc_file(file, config)
        if file_entries:
            target_entries.update(file_entries)
            logging.debug(f"Загружено {len(file_entries)} записей из {file.name}")
            # Логируем первые 3 записи с их типами для проверки
            for addr, data in list(file_entries.items())[:3]:
                logging.debug(f"  Пример записи: {addr} (тип: {data['type']}) -> {data['comment']}")

    if not target_entries:
        logging.error("Нет данных для синхронизации!")
        return False

    # Получение текущих записей с передачей информации о поддержке IPv6
    current_entries = get_current_static_entries(api, list_name, ipv6_supported)
    if current_entries is None:
        return False

    # Разделение текущих записей по типам адресов
    current_ipv4 = {addr: data for addr, data in current_entries.items() if data.get('type') == 'ipv4'}
    current_ipv6 = {addr: data for addr, data in current_entries.items() if data.get('type') in ['ipv6', 'ipv6-domain']}
    current_domains = {addr: data for addr, data in current_entries.items() if not ('.' in addr or ':' in addr)}

    # Разделение целевых записей по типам с учетом типа из parse_rsc_file
    target_ipv4 = {}
    target_ipv6 = {}
    target_domains_v6 = {}

    for addr, data in target_entries.items():
        if data['type'] == 'ipv4':
            target_ipv4[addr] = data['comment']
        elif data['type'] == 'ipv6':
            target_ipv6[addr] = data['comment']
        elif data['type'] == 'ipv6-domain':
            target_domains_v6[addr] = data['comment']

    # Объединяем IPv6 адреса и домены (если IPv6 включен)
    if ipv6_enabled:
        target_ipv6.update(target_domains_v6)

    # Проверка актуальности
    ipv4_up_to_date = not ipv4_enabled or (
        set(target_ipv4.items()) == {(a, c['comment']) for a, c in current_ipv4.items()}
    )
    ipv6_up_to_date = not ipv6_enabled or (
        set(target_ipv6.items()) == {(a, c['comment']) for a, c in current_ipv6.items()}
    )
    is_up_to_date = ipv4_up_to_date and ipv6_up_to_date

    # Дебаг вывод
    logging.debug(f"Целевые записи после разделения: IPv4={len(target_ipv4)}, IPv6={len(target_ipv6)}")
    logging.debug(f"Проверка актуальности IPv4: {ipv4_up_to_date} (целевых: {len(target_ipv4)}, текущих: {len(current_ipv4)})")
    logging.debug(f"Проверка актуальности IPv6: {ipv6_up_to_date} (целевых: {len(target_ipv6)}, текущих: {len(current_ipv6)})")

    # Вывод информации (общий)
    ipv6_status = "не поддерживает" if not ipv6_supported else str(len(current_ipv6))
    logging.info(
        f"Устройство {device_config['name']}, режим обновления {mode}: "
        f"IPv4: {len(current_ipv4)}, IPv6: {ipv6_status}. "
        f"Итого: {'актуально' if is_up_to_date else 'неактуально'}"
    )

    if is_up_to_date:
        return True

    # Вычисление изменений с учетом типа адреса
    to_add = []
    to_update = []
    to_remove = []

    # Обработка IPv4
    if ipv4_enabled:
        for addr, cmt in target_ipv4.items():
            if addr not in current_ipv4:
                to_add.append({'address': addr, 'comment': cmt, 'type': 'ipv4'})
            elif current_ipv4[addr]['comment'] != cmt:
                to_update.append({
                    'id': current_ipv4[addr]['id'],
                    'address': addr,
                    'comment': cmt,
                    'type': 'ipv4'
                })

        for addr in set(current_ipv4) - set(target_ipv4):
            to_remove.append({'id': current_ipv4[addr]['id'], 'type': 'ipv4'})

    # Обработка IPv6
    if ipv6_enabled:
        for addr, cmt in target_ipv6.items():
            if addr not in current_ipv6:
                to_add.append({'address': addr, 'comment': cmt, 'type': 'ipv6'})
            elif current_ipv6[addr]['comment'] != cmt:
                to_update.append({
                    'id': current_ipv6[addr]['id'],
                    'address': addr,
                    'comment': cmt,
                    'type': 'ipv6'
                })

        for addr in set(current_ipv6) - set(target_ipv6):
            to_remove.append({'id': current_ipv6[addr]['id'], 'type': 'ipv6'})

    # Dry-run режим
    if args.dry_run:
        logging.info(f"DRY RUN: Устройство {device_config['name']} требует обновления")
        logging.info(f"  Добавить: {len(to_add)}, Обновить: {len(to_update)}, Удалить: {len(to_remove)}")
        return True

    # Применение изменений
    stats = {'added': 0, 'removed': 0, 'updated': 0, 'errors': 0}
    settings = device_config.get('settings', {})
    delay = settings.get('update_delay', config["sync_master"]["setting_sync"]["update_delay"])
    batch_size = settings.get('batch_size', config["sync_master"]["setting_sync"].get("batch_size", 1500))

    # Удаление
    if to_remove:
        result = process_batch(api, list_name, to_remove, 'remove', delay)
        stats['removed'] += result['processed']
        stats['errors'] += result['errors']

    # Обновление
    if to_update:
        for i in range(0, len(to_update), batch_size):
            result = process_batch(api, list_name, to_update[i:i + batch_size], 'update', delay)
            stats['updated'] += result['processed']
            stats['errors'] += result['errors']

    # Добавление
    if to_add:
        for i in range(0, len(to_add), batch_size):
            result = process_batch(api, list_name, to_add[i:i + batch_size], 'add', delay)
            stats['added'] += result['processed']
            stats['errors'] += result['errors']
            if result['skipped'] > 0:
                logging.info(f"Пропущено {result['skipped']} существующих записей при добавлении")

    logging.info(
        f"Устройство {device_config['name']} обновлено: "
        f"добавлено {stats['added']}, обновлено {stats['updated']}, "
        f"удалено {stats['removed']}, ошибок: {stats['errors']}"
    )

    sync_duration = time.time() - sync_start_time
    logging.info(f"Синхронизация списка {list_name} заняла {sync_duration:.2f} секунд")
    return stats['errors'] == 0

def process_device(device_id, device_config, list_name, config, args):
    """Обработка одного устройства MikroTik"""

    logging.info(f"\n=== Обработка устройства {device_id} ({device_config['name']}) ===")

    # Проверка параметров синхронизации перед подключением
    ipv4_enabled = config["sync_master"]["setting_sync"].get("ipv4_sync", True)
    ipv6_enabled = config["sync_master"]["setting_sync"].get("ipv6_sync", False)

    if not ipv4_enabled and not ipv6_enabled:
        logging.error(f"Устройство {device_id} пропущено: синхронизация отключена для IPv4 и IPv6")
        return False

    # Определяет режим работы для устройства
    mode = (args.mode_run if args.mode_run is not None else
            device_config.get('type_mode') or
            config["sync_master"]["setting_sync"]["mode"])

    # Проверяет валидность режима
    if mode not in VALID_MODES:
        logging.warning(f"Указанный режим '{mode}' не существует, проверьте написание. Допустимые режимы: {', '.join(VALID_MODES)}")
        return False

    logging.debug(f"Используется режим: {mode}")

    # Параметры подключения (use_ssl берём из конфигов)
    use_ssl = False
    if 'sett_auth' in config.get('sync_master', {}):
        use_ssl = config['sync_master']['sett_auth'].get('use_ssl', False)

    if 'type_auth' in device_config:
        use_ssl = device_config['type_auth'].get('use_ssl', use_ssl)

    pool = None
    try:
        ssl_context = None
        if use_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            logging.debug("Используется SSL без проверки сертификата")

        start_time = time.time()
        connection_params = {
            'host': device_config['host'],
            'username': device_config['username'],
            'password': device_config['password'],
            'plaintext_login': True,
            'use_ssl': use_ssl
        }

        if ssl_context:
            connection_params['ssl_context'] = ssl_context

        pool = RouterOsApiPool(**connection_params)
        api = pool.get_api()
        logging.info(f"Успешное подключение (SSL: {use_ssl}, Ping: {time.time()-start_time:.2f}s)")

        # Проверка IPv6 и синхронизация
        ipv6_supported = ipv6_enabled and check_ipv6_support(api)
        if ipv6_enabled and not ipv6_supported:
            logging.warning("IPv6 выключен на устройстве или в конфигурации. Пропускаем IPv6-синхронизацию.")

        return sync_list(api, list_name, mode, config, device_config, args)

    except RouterOsApiConnectionError as e:
        logging.warning(f"Ошибка подключения: {e}")
        return False
    except Exception as e:
        logging.error(f"Критическая ошибка: {e}", exc_info=True)
        return False
    finally:
        if pool:
            pool.disconnect()

def main():
    args = parse_args()
    config, mikrotik_config = load_config()
    setup_logging(config)

    # Получение настроек синхронизации
    sync_settings = config["sync_master"]["setting_sync"]
    ipv4_enabled = sync_settings.get("ipv4_sync", True)
    ipv6_enabled = sync_settings.get("ipv6_sync", False)

    # Проверка и определение режима работы
    valid_modes = ["domains", "ips", "asn", "dom-asn", "ips-asn"]
    mode = args.mode_run if args.mode_run is not None else config["sync_master"]["setting_sync"].get("mode", "domains")

    if mode not in valid_modes:
        logging.error(f"ОШИБКА: Недопустимый режим работы '{mode}'. Допустимые режимы: {', '.join(valid_modes)}")
        exit(1)

    logging.info("\n===== Запуск sync_master.py - синхронизация Master устройств =====")
    logging.info(f"=== Общий режим синхронизации: {mode} {'(DRY RUN)' if args.dry_run else ''} ===")

    # Загрузка и проверка списков
    try:
        with open("configs/address_lists.yaml") as f:
            address_lists = yaml.safe_load(f).get("addressList", [])

        if not address_lists:
            logging.error("Не найдены списки для синхронизации в configs/address_lists.yaml")
            exit(1)

    except Exception as e:
        logging.error(f"Ошибка загрузки списков: {e}")
        exit(1)

    # Проверка наличия устройств в конфиге security/mikrotik.yaml
    devices = mikrotik_config.get('devices', {})
    if not devices:
        logging.error("Не найдены устройства для синхронизации!")
        exit(1)

    devices_info = ', '.join([f"{k} - {v['name']}" for k, v in devices.items()])
    logging.info(f"Доступные AddressList: {', '.join(address_lists)}")
    logging.info(f"Обнаружены Master устройства: {devices_info}")
    logging.info(f"Параметры синхронизации: IPv4: {'включен' if ipv4_enabled else 'отключен'}, "
            f"IPv6: {'включен' if ipv6_enabled else 'отключен'}")


    # Обработка каждого устройства
    success = 0
    total_devices = 0  # Общее количество устройств-списков

    for device_id, device_config in devices.items():
        # Определение списков для синхронизации на устройстве по приоритету:
        # 1. --list-name (аргумент командной строки) - высший приоритет
        # 2. list_name в настройках устройства
        # 3. Все списки из address_lists.yaml

        if args.list_name:
            # Высший приоритет: аргумент командной строки
            device_lists = [args.list_name]
            logging.info(f"Устройство {device_config['name']} будет синхронизировать список из аргумента: {args.list_name}")
        elif 'settings' in device_config and 'list_name' in device_config['settings']:
            # Средний приоритет: list_name из настроек устройства
            device_lists = device_config['settings']['list_name']
            logging.info(f"Устройство {device_config['name']} будет синхронизировать списки из настроек: {', '.join(device_lists)}")
        else:
            # Низший приоритет: все списки
            device_lists = address_lists
            logging.info(f"Устройство {device_config['name']} будет синхронизировать все списки: {', '.join(device_lists)}")

        # Фильтрация - только существующие списки
        existing_lists = [list_name for list_name in device_lists if list_name in address_lists]
        if len(existing_lists) != len(device_lists):
            missing_lists = set(device_lists) - set(address_lists)
            logging.warning(f"Предупреждение: следующие списки не найдены в address_lists.yaml и будут пропущены: {', '.join(missing_lists)}")

        if not existing_lists:
            logging.warning(f"Устройство {device_config['name']} не имеет валидных списков для синхронизации, пропускаем")
            continue

        total_devices += len(existing_lists)

        for list_name in existing_lists:
            logging.info(f"\nОбработка списка: {list_name} на устройстве {device_config['name']}")

            if process_device(device_id, device_config, list_name, config, args):
                success += 1
            else:
                logging.warning(f"Проблемы при обработке {device_config['name']} для списка {list_name}")

    # Итоговый отчёт
    logging.info("\n=== ИТОГИ ===")
    logging.info(f"Успешно обработано: {success}/{total_devices}")

    if success == 0:
        logging.error("=== Синхронизация завершена с ошибками! ===")
        exit(1)
    elif success < total_devices:
        logging.warning("=== Синхронизация завершена с частичными ошибками ===")
    else:
        logging.info("=== Синхронизация успешно завершена ===")

if __name__ == "__main__":
    start_time = time.time()
    main()
    logging.info(f"Выполнено за {time.time()-start_time:.2f} секунд")
