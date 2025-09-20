import logging
import os
import ssl
from pathlib import Path
from datetime import datetime, timedelta
from routeros_api import RouterOsApiPool
from routeros_api.exceptions import RouterOsApiConnectionError
from typing import List, Dict, Optional, Union

# ===== КОНФИГУРАЦИЯ СКРИПТА =====
MIKROTIK_HOST = '<IP_host>'
MIKROTIK_USER = '<User_connect>'
MIKROTIK_PASS = '<Password_user>'
API_PORT = 8728                  # API port (8728)
API_SSL_PORT = 8729              # API-SSL port (8729)
SSL = True                       # Use SSL (True/False)

ADDRESS_LISTS = ['Chebunet-list-IPServices']    # Список адрес-листов для экспорта. Можно перечислить несколько, через ",".
EXPORT_TYPE = 'all'                             # Тип выгружаемых данных 'static' - статичные, 'dynamic' - динамичные, или 'all' - все .
OUTPUT_DIR = 'raw-data/Chebunet-list-IPServices/test'   # Директория для выходных данных
MAX_AGE = '1000d 00:00:00'                      # Максимальный возраст записей (формат "dd hh:mm:ss") - старше удаляются
'''
Пояснение к MAX_AGE - макс. значение на MikroTik в разделе Address Lists для параметра Creation-Time = 248d 00:00:00 (RouterOS 6,7) .
Если выставить значение > 248d 00:00:00, скрипт не будет находить старые записи, соответственно, удаления старых записей не будет происходить.
Может пригодиться, если записи не нужно удалять из листа.
'''

# Автоматическое определение имени лог файла
# Получаем имя текущего скрипта без расширения .py
script_name = Path(__file__).stem  # Например: "getting_saving_addressLists-ExampleDevices"
log_filename = f"{script_name}.log"

# Создание директории в logs (автоматическое имя из названия скрипта)
log_path = Path(f'logs/helper/getting_saving_addressLists/{log_filename}')
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

def parse_mikrotik_time(time_str: str) -> datetime:
    """Конвертирует время MikroTik (например 'aug/18/2025 06:42:22') в datetime."""
    return datetime.strptime(time_str, '%b/%d/%Y %H:%M:%S')

def is_entry_expired(creation_time_str: str, max_age: str) -> bool:
    """Проверяет, истек ли срок жизни записи."""
    try:
        # Парсинг максимального возраста
        days, time = max_age.split(' ')
        h, m, s = map(int, time.split(':'))
        max_delta = timedelta(days=int(days[:-1]), hours=h, minutes=m, seconds=s)

        # Парсинг время создания записи
        create_time = parse_mikrotik_time(creation_time_str)

        return datetime.now() - create_time > max_delta
    except Exception as e:
        logging.error(f"Ошибка проверки срока записи: {e}")
        return False

def cleanup_old_entries(api, list_name: str, max_age: str):
    """Удаляет устаревшие статические записи из адрес-листа."""
    try:
        resource = api.get_resource('/ip/firewall/address-list')
        entries = resource.get(list=list_name, dynamic='no')  # Только статические

        deleted_count = 0
        for entry in entries:
            if 'creation-time' in entry and is_entry_expired(entry['creation-time'], max_age):
                resource.remove(id=entry['id'])
                logging.info(f"Удалена устаревшая запись: {entry['address']} (создана {entry['creation-time']})")
                deleted_count += 1

        logging.info(f"Удалено {deleted_count} устаревших записей из листа '{list_name}'")
        return deleted_count
    except Exception as e:
        logging.error(f"Ошибка очистки листа '{list_name}': {e}")
        return 0

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
        return pool  # Возвращаем pool вместо api для правильного управления соединением
    except RouterOsApiConnectionError as e:
        logging.error(f"Ошибка подключения: {e}")
        return None
    except Exception as e:
        logging.error(f"Неожиданная ошибка при подключении: {e}", exc_info=True)
        return None


def check_address_list_exists(api, list_name: str) -> bool:
    """Проверяет существование адрес-листа на MikroTik."""
    try:
        ipv4_resource = api.get_resource('/ip/firewall/address-list')
        # Получаем уникальные адрес-листы
        lists = set(item['list'] for item in ipv4_resource.get())
        return list_name in lists
    except Exception as e:
        logging.error(f"Ошибка при проверке существования адрес-листа: {e}")
        return False


def get_address_list_entries(api, list_name: str, entry_type: str = 'all') -> Optional[List[str]]:
    """Получает записи из адрес-листа MikroTik."""
    try:
        ipv4_resource = api.get_resource('/ip/firewall/address-list')

        # Формируем параметры запроса
        params = {'list': list_name}
        if entry_type in ['static', 'dynamic']:
            params['dynamic'] = 'yes' if entry_type == 'dynamic' else 'no'

        items = ipv4_resource.get(**params)

        # Фильтруем только IPv4 адреса и извлекаем нужные данные
        entries = []
        for item in items:
            if 'address' in item:
                entries.append(item['address'])

        logging.info(f"Найдено {len(entries)} записей в адрес-листе '{list_name}' (тип: {entry_type})")
        return entries if entries else None

    except Exception as e:
        logging.error(f"Ошибка при получении адрес-листа '{list_name}': {e}")
        return None


def save_to_file(addresses: Union[List[str], None], list_name: str, output_dir: str) -> bool:
    """Сохраняет адреса в текстовый файл, перезаписывая предыдущие данные."""
    try:
        # Создаем папку, если она не существует
        os.makedirs(output_dir, exist_ok=True)

        # Убеждаемся, что путь заканчивается на слеш
        if not output_dir.endswith('/') and not output_dir.endswith('\\'):
            output_dir += '/'

        filename = f"{output_dir}{list_name}.txt"

        # Режим 'w' автоматически перезаписывает файл
        with open(filename, 'w') as f:
            if addresses:
                for address in addresses:
                    f.write(f"{address}\n")
            else:
                f.write("# Адрес-лист пуст или не существует\n")

        logging.info(f"Результаты сохранены в {filename}")
        return True
    except IOError as e:
        logging.error(f"Ошибка ввода-вывода: {e}")
        return False
    except Exception as e:
        logging.error(f"Неожиданная ошибка при сохранении файла: {e}")
        return False

def main():
    """Основная функция для выполнения процесса экспорта и очистки."""
    logging.info("\n=== Запуск %s - выгрузка адрес-листов MikroTik ===", script_name)

    # Подключаемся к MikroTik
    port = API_SSL_PORT if SSL else API_PORT
    pool = None

    try:
        pool = connect_to_mikrotik(MIKROTIK_HOST, MIKROTIK_USER, MIKROTIK_PASS, port, SSL)

        if not pool:
            logging.error("Не удалось подключиться к MikroTik. Завершение работы.")
            return

        api = pool.get_api()

        # Обрабатываем каждый адрес-лист
        for list_name in ADDRESS_LISTS:
            # Проверяем существование адрес-листа
            if not check_address_list_exists(api, list_name):
                logging.warning(f"Адрес-лист '{list_name}' не существует на устройстве")
                save_to_file(None, list_name, OUTPUT_DIR)
                continue

            # Очищаем устаревшие записи (только статические)
            cleanup_old_entries(api, list_name, MAX_AGE)

            # Получаем актуальные адреса из листа
            addresses = get_address_list_entries(api, list_name, EXPORT_TYPE)

            # Сохраняем в файл
            if not save_to_file(addresses, list_name, OUTPUT_DIR):
                logging.error(f"Не удалось сохранить адрес-лист '{list_name}'")

    except RouterOsApiConnectionError as e:
        logging.error(f"Ошибка подключения: {e}", exc_info=True)
    except Exception as e:
        logging.error(f"Неожиданная ошибка: {e}", exc_info=True)
    finally:
        if pool:
            try:
                pool.disconnect()
                logging.info("Успешное отключение от MikroTik")
            except Exception as e:
                logging.error(f"Ошибка при отключении: {e}", exc_info=True)

        logging.info("=== Выгрузка листов завершена ===")

if __name__ == "__main__":
    main()
