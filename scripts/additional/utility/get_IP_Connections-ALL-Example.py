import logging
import ssl
import os
import ipaddress
import json
import yaml
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Set, Optional, Dict, Any
from routeros_api import RouterOsApiPool
from routeros_api.exceptions import RouterOsApiConnectionError, RouterOsApiCommunicationError

# ===== КОНФИГУРАЦИЯ СКРИПТА =====
# Параметры по умолчанию
DEFAULT_USERNAME = 'MyUsername'
DEFAULT_PASSWORD = 'PasswordUsername'
API_PORT = 8728                  # API port (8728)
API_SSL_PORT = 8729              # API-SSL port (8729)
SSL = True   # Use SSL (True/False)

# Индивидуальные учетные данные и параметры для конкретных устройств
# Формат: "IP": ("username", "password", SSL, API порт)
# Параметры SSL и порт опциональны
SPECIAL_CREDENTIALS = {
    "192.168.0.1": ("User1", "False", "PasswordUser1"),
    "192.168.1.1": ("User2", "PasswordUser2"),
    "192.168.2.1": ("User3", "False", "PasswordUser3"),
}

# Список устройств для получения списка Connection
DEVICES = [
    "192.168.0.1",    # Connect-Example1
    "192.168.1.1",    # Connect-Example2
    "192.168.2.1",    # Connect-Example3
]

# Внешняя фильтрация
## Пути к файлам (можно указать 'none' для отключения фильтрации)
ASN_FILTER = 'none'  # 'none' или 'path/to/results-as.json'
DNS_FILTER = 'none' # 'none' или 'path/to/results-dns.yaml'
OUTPUT_DIR = 'raw-data/list-IPServices/'   # Директория для выходных данных *.json

# Фильтрация на уровне устройства (connections)
SRC_ADDRESS = 'ALL' # Фильтр адреса источника (параметры: 'ALL' - все SRC-ADDRESS connections. Или IP адрес источника: '192.168.0.10' или порт ':53')
DST_ADDRESS = 'ALL'  # Фильтр адреса назначения (параметры 'ALL' - все DST-ADDRESS connections. Или IP адрес источника: '1.1.1.1' или порт ':443')
CONN_MARK = 'none-mark' # Фильтр Connection Mark (параметры: none-mark - все соединения, без маркировки. Или наименование Connection Mark).

# ===== КОД СКРИПТА =====

# Автоматическое определение имени лог файла
# Получает имя скрипта без расширения .py
script_name = Path(__file__).stem  # Например: "get_IP_Connections-ExampleDevices"
log_filename = f"{script_name}.log"

# Создание директории в logs (автоматическое имя из названия скрипта)
log_path = Path(f'logs/additional/get_IP_Connections/{log_filename}')
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

def get_device_credentials(device_ip: str) -> tuple[str, str, bool, int]:
    """Получает учетные данные для конкретного устройства."""
    if device_ip in SPECIAL_CREDENTIALS:
        creds = SPECIAL_CREDENTIALS[device_ip]
        username = creds[0]
        password = creds[1]

        # Определение SSL (по умолчанию использует глобальное значение)
        ssl_flag = SSL
        if len(creds) > 2:
            ssl_flag = creds[2].lower() == "true"

        # Определение порта (по умолчанию использует глобальный)
        port = API_SSL_PORT if ssl_flag else API_PORT
        if len(creds) > 3:
            try:
                port = int(creds[3])
            except ValueError:
                logging.warning(f"Устройство {device_ip} недоступно по порту, пробуем порт по умолчанию: {port}")
    else:
        username = DEFAULT_USERNAME
        password = DEFAULT_PASSWORD
        ssl_flag = SSL
        port = API_SSL_PORT if ssl_flag else API_PORT

    return username, password, ssl_flag, port

def create_ssl_context() -> ssl.SSLContext:
    """Создает SSL контекст с отключенной проверкой сертификата."""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context

def connect_to_mikrotik(host: str, username: str, password: str, port: int, ssl_enabled: bool) -> Optional[RouterOsApiPool]:
    """Подключается к MikroTik устройству через RouterOS API."""
    try:
        ssl_context = create_ssl_context() if ssl_enabled else None

        pool = RouterOsApiPool(
            host=host,
            username=username,
            password=password,
            port=port,
            use_ssl=ssl_enabled,
            plaintext_login=True,
            ssl_context=ssl_context
        )
        api = pool.get_api()
        logging.info(f"Успешное подключение к {host}")
        return pool

    except RouterOsApiCommunicationError as e:
        # Обработка ошибки авторизации
        error_msg = str(e)
        if "invalid user name or password" in error_msg:
            logging.error(f"Ошибка авторизации на устройстве {host}. Проверьте учётные данные (логин, пароль).")
        else:
            logging.error(f"Ошибка связи с устройством {host}: {error_msg}")
        return None

    except RouterOsApiConnectionError as e:
        logging.error(f"Ошибка подключения к {host}: {e}")
        return None

    except Exception as e:
        logging.error(f"Неожиданная ошибка при подключении к {host}: {e}", exc_info=True)
        return None

def get_connections(api, src_address: str, dst_address: str, conn_mark: str, as_json_file: str, dns_yaml_file: str, output_dir: str) -> List[Dict[str, Any]]:
    """Получает список соединений с MikroTik с применением фильтров."""
    try:
        connection_resource = api.get_resource('/ip/firewall/connection')

        # Выводит информацию о всех фильтрах
        logging.info("=== ОБЩИЕ ПАРАМЕТРЫ ===")
        logging.info(f"SRC_ADDRESS: '{src_address}'")
        logging.info(f"DST_ADDRESS: '{dst_address}'")
        logging.info(f"CONN_MARK: '{conn_mark}'")
        logging.info(f"ASN_FILTER: '{as_json_file}'")
        logging.info(f"DNS_FILTER: '{dns_yaml_file}'")
        logging.info(f"OUTPUT_DIR: '{output_dir}'")
        logging.info("=" * 30)

        # Получает ВСЕ соединения
        all_connections = connection_resource.get()
        logging.info(f"Всего соединений на устройстве: {len(all_connections)}")

        # Применяет фильтр программно
        filtered_connections = []

        for conn in all_connections:
            match = True

            # Фильтр по src-address (с обработкой портов)
            if src_address != 'ALL':
                conn_src = conn.get('src-address', '')
                if not conn_src:
                    match = False
                else:
                    # Если фильтр начинается с ':' - ищет порт
                    if src_address.startswith(':'):
                        port_to_find = src_address[1:]  # Убирает двоеточие
                        if ':' in conn_src:
                            _, port = conn_src.split(':', 1)
                            if port_to_find not in port:
                                match = False
                        else:
                            match = False  # Порт отсутствует в адресе
                    else:
                        # Обычный поиск по полному адресу
                        if src_address not in conn_src:
                            match = False

            # Фильтр по dst-address (с обработкой портов)
            if match and dst_address != 'ALL':
                conn_dst = conn.get('dst-address', '')
                if not conn_dst:
                    match = False
                else:
                    # Если фильтр начинается с ':' - ищет порт
                    if dst_address.startswith(':'):
                        port_to_find = dst_address[1:]  # Убирает двоеточие
                        if ':' in conn_dst:
                            _, port = conn_dst.split(':', 1)
                            if port_to_find not in port:
                                match = False
                        else:
                            match = False  # Порт отсутствует в адресе
                    else:
                        # Обычный поиск по полному адресу
                        if dst_address not in conn_dst:
                            match = False

            # Фильтр по connection-mark (точное совпадение в разных форматах)
            if match and conn_mark != 'none-mark':
                conn_mark_value = conn.get('connection-mark', '')

                # Проверяет разные возможные форматы connection-mark
                mark_matches = False

                # 1. Точное совпадение
                if conn_mark_value == conn_mark:
                    mark_matches = True

                # 2. Connection-mark в hex формате (0xXXXX)
                elif conn_mark_value.startswith('0x') and conn_mark.isdigit():
                    try:
                        # Конвертирует десятичное значение в hex для сравнения
                        decimal_value = int(conn_mark)
                        hex_value = f"0x{decimal_value:04x}"
                        if conn_mark_value.lower() == hex_value.lower():
                            mark_matches = True
                    except ValueError:
                        pass

                # 3. Connection-mark с префиксом/суффиксом
                elif conn_mark in conn_mark_value:
                    mark_matches = True

                if not mark_matches:
                    match = False

            if match:
                filtered_connections.append(conn)

        logging.info(f"После фильтрации осталось {len(filtered_connections)} соединений")

        # Логирование для connection-mark
        if conn_mark != 'none-mark':
            logging.debug("=== Детальная информация о connection-mark ===")
            mark_values = set()
            for conn in all_connections[:20]:  # Проверка первых 20 соединений
                mark = conn.get('connection-mark', 'NONE')
                mark_values.add(mark)
                logging.debug(f"Connection: SRC={conn.get('src-address')}, DST={conn.get('dst-address')}, MARK='{mark}'")
            logging.debug(f"Уникальные значения connection-mark в системе: {sorted(mark_values)}")

        return filtered_connections

    except Exception as e:
        logging.error(f"Ошибка при получении соединений: {e}", exc_info=True)
        return []

def extract_addresses(connections: List[Dict[str, Any]], filter_type: str = 'dst') -> Set[str]:
    """Извлекает уникальные IPv4 адреса из списка соединений."""
    addresses = set()

    for conn in connections:
        # Выбирает поле в зависимости от типа фильтра
        if filter_type == 'src':
            addr = conn.get('src-address', '')
        else:  # 'dst'
            addr = conn.get('dst-address', '')

        if not addr:
            continue

        # Обработка разных форматов адресов
        try:
            # Убирает порт если есть (формат: 1.2.3.4:80)
            if ':' in addr:
                ip_part = addr.split(':')[0]
                # Проверка на IPv4
                ipaddress.IPv4Address(ip_part)
                addresses.add(ip_part)
                continue

            # Прямой IPv4 адрес (без порта)
            ipaddress.IPv4Address(addr)
            addresses.add(addr)

        except (ipaddress.AddressValueError, ValueError):
            # Пропуск невалидных IPv4
            continue

    logging.info(f"Извлечено {len(addresses)} уникальных IPv4 адресов ({'source' if filter_type == 'src' else 'destination'})")
    return addresses

def debug_connection_marks(api):
    """Функция отладки значений connection-mark на устройстве."""
    try:
        connection_resource = api.get_resource('/ip/firewall/connection')
        all_connections = connection_resource.get()

        mark_values = set()
        for conn in all_connections:
            mark = conn.get('connection-mark', 'NONE')
            if mark != 'NONE':
                mark_values.add(mark)

        logging.info(f"Все connection-mark на устройстве: {sorted(mark_values)}")

        # Проверка настроек firewall mangle rules
        try:
            mangle_resource = api.get_resource('/ip/firewall/mangle')
            mangle_rules = mangle_resource.get()

            connection_marks_in_rules = set()
            for rule in mangle_rules:
                mark = rule.get('connection-mark', '')
                new_mark = rule.get('new-connection-mark', '')
                if mark:
                    connection_marks_in_rules.add(mark)
                if new_mark:
                    connection_marks_in_rules.add(new_mark)

            logging.info(f"Connection-mark в mangle rules: {sorted(connection_marks_in_rules)}")

        except Exception as e:
            logging.warning(f"Не удалось получить mangle rules: {e}")

    except Exception as e:
        logging.error(f"Ошибка при отладке connection-mark: {e}")

def load_as_prefixes(as_json_file: str) -> List[ipaddress.IPv4Network]:
    """Загружает префиксы AS из JSON файла (опционально)."""
    if as_json_file.lower() == 'none':
        logging.info("Фильтрация по AS префиксам отключена")
        return []

    try:
        with open(as_json_file, 'r') as f:
            data = json.load(f)

        prefixes = []
        as_data = data.get('as_data', {})

        for asn, as_info in as_data.items():
            prefixes_v4 = as_info.get('prefixes_v4', [])
            for prefix in prefixes_v4:
                try:
                    network = ipaddress.IPv4Network(prefix)
                    prefixes.append(network)
                except ValueError:
                    continue

        logging.info(f"Загружено {len(prefixes)} IPv4 префиксов из {as_json_file}")
        return prefixes

    except Exception as e:
        logging.error(f"Ошибка при загрузке AS префиксов: {e}", exc_info=True)
        return []

def load_dns_ips(dns_yaml_file: str) -> Set[str]:
    """Загружает IP адреса из DNS YAML файла (опционально)."""
    if dns_yaml_file.lower() == 'none':
        logging.info("Фильтрация по DNS IP отключена")
        return set()

    try:
        with open(dns_yaml_file, 'r') as f:
            data = yaml.safe_load(f)

        ips = set()

        categories = data.get('categories', {})
        for category_name, category_data in categories.items():
            for domain, domain_info in category_data.items():
                # Обрабатка IPv4
                ipv4_data = domain_info.get('ipv4', {})
                if isinstance(ipv4_data, dict):
                    # Получение адреса из current
                    ipv4_current = ipv4_data.get('current', [])
                    for ip in ipv4_current:
                        try:
                            ipaddress.IPv4Address(ip)
                            ips.add(ip)
                        except ipaddress.AddressValueError:
                            continue

                    # Получение адреса из historical
                    ipv4_historical = ipv4_data.get('historical', {})
                    for ip in ipv4_historical.keys():
                        try:
                            ipaddress.IPv4Address(ip)
                            ips.add(ip)
                        except ipaddress.AddressValueError:
                            continue
                elif isinstance(ipv4_data, list):
                    # Старая структура (простой список)
                    for ip in ipv4_data:
                        try:
                            ipaddress.IPv4Address(ip)
                            ips.add(ip)
                        except ipaddress.AddressValueError:
                            continue

                ipv6_data = domain_info.get('ipv6', {})
                if isinstance(ipv6_data, dict):
                    # Получение адреса из current
                    ipv6_current = ipv6_data.get('current', [])
                    for ip in ipv6_current:
                        try:
                            ipaddress.IPv6Address(ip)
                        except ipaddress.AddressValueError:
                            continue

                    # Адреса из historical
                    ipv6_historical = ipv6_data.get('historical', {})
                    for ip in ipv6_historical.keys():
                        try:
                            ipaddress.IPv6Address(ip)
                        except ipaddress.AddressValueError:
                            continue
                elif isinstance(ipv6_data, list):
                    # Старая структура (простой список)
                    for ip in ipv6_data:
                        try:
                            ipaddress.IPv6Address(ip)
                        except ipaddress.AddressValueError:
                            continue

        logging.info(f"Загружено {len(ips)} IPv4 адресов из {dns_yaml_file}")
        return ips

    except Exception as e:
        logging.error(f"Ошибка при загрузке DNS IP: {e}", exc_info=True)
        return set()

def filter_by_as_prefixes(addresses: Set[str], prefixes: List[ipaddress.IPv4Network]) -> Set[str]:
    """Фильтрует адреса, которые входят в префиксы AS."""
    filtered_addresses = set()

    for addr in addresses:
        ip = ipaddress.IPv4Address(addr)
        for prefix in prefixes:
            if ip in prefix:
                filtered_addresses.add(addr)
                break

    logging.info(f"После фильтрации по AS префиксам осталось {len(filtered_addresses)} адресов")
    return filtered_addresses

def filter_by_dns_ips(addresses: Set[str], dns_ips: Set[str]) -> Set[str]:
    """Фильтрует адреса, которые отсутствуют в DNS данных."""
    filtered_addresses = addresses - dns_ips
    logging.info(f"После фильтрации по DNS IP осталось {len(filtered_addresses)} адресов")
    return filtered_addresses

def generate_filename(host: str, src_address: str, dst_address: str, conn_mark: str) -> str:
    """Генерирует имя файла по шаблону с учётом фильтров."""
    # Замена "." и ":" на "_"
    host_clean = host.replace('.', '_').replace(':', '_')

    # Обработка src_address
    if src_address != 'ALL':
        src_clean = f"src_{src_address.replace('.', '_').replace(':', '_')}"
    else:
        src_clean = 'src_ALL'

    # Обработка dst_address
    if dst_address != 'ALL':
        dst_clean = f"dst_{dst_address.replace('.', '_').replace(':', '_')}"
    else:
        dst_clean = 'dst_ALL'

    # Обработка conn_mark
    if conn_mark != 'none-mark':
        mark_clean = conn_mark.replace(' ', '_').replace(':', '_')
    else:
        mark_clean = 'none-mark'

    filename = f"{host_clean}:{src_clean}:{dst_clean}:{mark_clean}.txt"
    return filename

def save_results(addresses: Set[str], output_dir: str, filename: str):
    """Сохраняет результаты в JSON файл с временными метками."""
    try:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename.replace('.txt', '.json'))

        # Загрузка существующих данные
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
            except Exception as e:
                logging.warning(f"Ошибка при чтении JSON файла: {e}")
                existing_data = create_new_data_structure()
        else:
            existing_data = create_new_data_structure()

        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Обновление адресов
        for addr in addresses:
            if addr in existing_data['addresses']:
                # Обновление существующего адрес
                existing_data['addresses'][addr]['last_seen'] = current_time
                existing_data['addresses'][addr]['seen_count'] += 1
            else:
                # Добавление нового адреса
                existing_data['addresses'][addr] = {
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'seen_count': 1
                }

        # Обновление метаданных
        existing_data['metadata']['last_updated'] = current_time
        existing_data['metadata']['total_addresses'] = len(existing_data['addresses'])

        # Сохранение обновленных данных
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(existing_data, f, indent=2, ensure_ascii=False)

        logging.info(f"Результаты сохранены в {filepath} (обработано {len(addresses)} адресов)")

    except Exception as e:
        logging.error(f"Ошибка при сохранении результатов: {e}", exc_info=True)

def create_new_data_structure() -> Dict[str, Any]:
    """Создает структуру данных для JSON файла."""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return {
        "metadata": {
            "created": current_time,
            "last_updated": current_time,
            "total_addresses": 0,
            "source_device": DEVICES,
            "filters_applied": {
                "src_address": SRC_ADDRESS,
                "dst_address": DST_ADDRESS,
                "conn_mark": CONN_MARK,
                "asn_filter": ASN_FILTER,
                "dns_filter": DNS_FILTER
            }
        },
        "addresses": {}
    }

def process_single_device(device_ip: str) -> bool:
    """Обрабатывает одно устройство."""
    logging.info(f"\n--- Обработка устройства {device_ip} ---")

    # Получаем учетные данные для устройства
    username, password, ssl_flag, port = get_device_credentials(device_ip)

    # Подключаемся к устройству
    pool = connect_to_mikrotik(device_ip, username, password, port, ssl_flag)

    if not pool:
        logging.error(f"Не удалось подключиться к устройству {device_ip}")
        return False

    try:
        api = pool.get_api()

        # Вывод всех connection-mark на устройстве
        if CONN_MARK != 'none-mark':
            debug_connection_marks(api)

        # Получение соединения
        connections = get_connections(
            api=api,
            src_address=SRC_ADDRESS,
            dst_address=DST_ADDRESS,
            conn_mark=CONN_MARK,
            as_json_file=ASN_FILTER,
            dns_yaml_file=DNS_FILTER,
            output_dir=OUTPUT_DIR,
        )
        if not connections:
            logging.warning(f"Не найдено соединений по заданным фильтрам на устройстве {device_ip}")
            return True

        # Определение типа адресов для извлечения
        if SRC_ADDRESS != 'ALL' and SRC_ADDRESS.startswith(':'):
            extracted_addresses = extract_addresses(connections, filter_type='src')
        elif DST_ADDRESS != 'ALL' and DST_ADDRESS.startswith(':'):
            extracted_addresses = extract_addresses(connections, filter_type='dst')
        else:
            extracted_addresses = extract_addresses(connections, filter_type='dst')

        if not extracted_addresses:
            logging.warning(f"Не найдено IPv4 адресов на устройстве {device_ip}")
            return True

        # Загрузка данных AS
        as_prefixes = []
        if ASN_FILTER.lower() != 'none':
            as_prefixes = load_as_prefixes(ASN_FILTER)
            if not as_prefixes:
                logging.warning("Не удалось загрузить AS префиксы, но продолжаем работу")
        else:
            logging.info("Пропускаем фильтрацию по AS префиксам")

        # Загрузка данных DNS
        dns_ips = set()
        if DNS_FILTER.lower() != 'none':
            dns_ips = load_dns_ips(DNS_FILTER)
        else:
            logging.info("Пропускаем фильтрацию по DNS IP")

        # Фильтрация по AS префиксам
        if as_prefixes:
            filtered_by_as = filter_by_as_prefixes(extracted_addresses, as_prefixes)
        else:
            filtered_by_as = extracted_addresses

        # Фильтрация по DNS (IP)
        if dns_ips:
            final_addresses = filter_by_dns_ips(filtered_by_as, dns_ips)
        else:
            final_addresses = filtered_by_as

        if not final_addresses:
            logging.warning(f"После фильтрации не осталось адресов на устройстве {device_ip}")
            return True

        # Генерация имени выходного файла и сохранение
        filename = generate_filename(device_ip, SRC_ADDRESS, DST_ADDRESS, CONN_MARK)
        save_results(final_addresses, OUTPUT_DIR, filename)

        logging.info(f"Обработка устройства {device_ip} завершена. Сохранено {len(final_addresses)} адресов")
        return True

    except RouterOsApiCommunicationError as e:
        # Дополнительная обработка ошибок API во время работы
        error_msg = str(e)
        if "invalid user name or password" in error_msg:
            logging.error(f"Ошибка авторизации на устройстве {device_ip} во время выполнения команды. Проверьте учётные данные.")
        else:
            logging.error(f"Ошибка связи с устройством {device_ip} во время выполнения: {error_msg}")
        return False

    except Exception as e:
        logging.error(f"Ошибка при обработке устройства {device_ip}: {e}", exc_info=True)
        return False
    finally:
        if pool:
            try:
                pool.disconnect()
                logging.info(f"Успешное отключение от устройства {device_ip}")
            except Exception as e:
                logging.error(f"Ошибка при отключении от устройства {device_ip}: {e}", exc_info=True)

def main():
    """Основная функция для выполнения процесса анализа соединений."""
    logging.info("\n=== Запуск %s - анализ соединений (connection) MikroTik ===", script_name)
    logging.info(f"Количество устройств: {len(DEVICES)} шт.")

    success_count = 0
    failed_count = 0

    for device_ip in DEVICES:
        if process_single_device(device_ip):
            success_count += 1
        else:
            failed_count += 1

    logging.info(f"\n=== Итоги обработки ===")
    logging.info(f"Успешно обработано: {success_count} устройств")
    logging.info(f"Не удалось обработать: {failed_count} устройств")
    logging.info("=== Обработка завершена ===")

if __name__ == "__main__":
    main()
