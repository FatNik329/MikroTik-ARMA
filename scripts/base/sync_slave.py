import routeros_api
import yaml
import time
import socket
import concurrent.futures
import threading
import logging
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from collections import defaultdict
from routeros_api import RouterOsApiPool
from routeros_api.exceptions import RouterOsApiConnectionError, RouterOsApiCommunicationError
import ssl
from typing import Dict, Set, List, Tuple, Optional, Any

# Настройка логгирования
def setup_logger():
    global logger

    logger = logging.getLogger('sync_slave')
    logger.setLevel(logging.DEBUG)

    class HostnameFilter(logging.Filter):
        def filter(self, record):
            record.hostname = getattr(threading.current_thread(), 'hostname', 'Main')
            return True
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

        # Консольный вывод
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    ch.addFilter(HostnameFilter())
    logger.addHandler(ch)

    # Файловый вывод (логи)
    log_file = Path('logs/base/sync_slave/sync_slave.log')
    log_file.parent.mkdir(exist_ok=True)
    fh = logging.FileHandler(log_file)
    fh.setFormatter(formatter)
    fh.addFilter(HostnameFilter())
    logger.addHandler(fh)

    return logger

class MikroTikConnection:
    """Класс управления подключениями к MikroTik"""

    @staticmethod
    def create_connection(host: str, username: str, password: str, use_ssl: bool = False, port: Optional[int] = None) -> RouterOsApiPool:
        """Создание подключения к устройству"""
        port = port or (8729 if use_ssl else 8728)

        ssl_context = None
        if use_ssl:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

        return RouterOsApiPool(
            host=host,
            username=username,
            password=password,
            plaintext_login=True,
            use_ssl=use_ssl,
            port=port,
            ssl_verify=False,
            ssl_verify_hostname=False,
            ssl_context=ssl_context
        )

class DeviceChecker:
    """Класс проверки доступности устройств"""

    @staticmethod
    def check_device_available(ip: str, port: int, timeout: int = 3) -> Tuple[bool, Optional[float]]:
        """Проверка доступности устройства с возвратом времени ping"""
        if timeout is None:
            timeout = 3

        start_time = time.time()

        # Проверка ping
        ping_success = DeviceChecker._check_ping(ip, timeout)

        # Проверка порта
        port_available = DeviceChecker._check_port(ip, port, timeout)

        ping_time = time.time() - start_time if ping_success else None
        return port_available, ping_time

    @staticmethod
    def _check_ping(ip: str, timeout: int) -> bool:
        """Проверка доступности через ping"""
        try:
            param = '-n' if os.name == 'nt' else '-c'
            command = ['ping', param, '1', '-W', str(timeout), ip]
            return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        except Exception:
            return False

    @staticmethod
    def _check_port(ip: str, port: int, timeout: int) -> bool:
        """Проверка доступности порта"""
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except Exception:
            return False

class AddressListManager:
    """Менеджер для работы со списками адресов"""

    @staticmethod
    def get_address_set(api, list_name: str, ipv6_supported: bool = False) -> Set[Tuple[str, str, str]]:
        """Получение множества адресов из списка"""
        result = set()

        # IPv4 addresses
        AddressListManager._add_addresses_to_set(api, '/ip/firewall/address-list', list_name, result, 'ipv4')

        # IPv6 addresses if supported
        if ipv6_supported:
            AddressListManager._add_addresses_to_set(api, '/ipv6/firewall/address-list', list_name, result, 'ipv6')

        return result

    @staticmethod
    def _add_addresses_to_set(api, resource_path: str, list_name: str, result_set: set, ip_type: str):
        """Добавляет адреса из ресурса в множество"""
        try:
            resource = api.get_resource(resource_path)
            items = resource.get(list=list_name)

            for item in items:
                if AddressListManager._is_active_address(item):
                    address = str(item['address'])
                    comment = str(item.get('comment', ''))
                    result_set.add((address, comment, ip_type))
        except Exception as e:
            logging.debug(f"Ошибка получения {ip_type} списка {list_name}: {str(e)}")

    @staticmethod
    def _is_active_address(item) -> bool:
        """Проверяет, активность адреса (не dynamic и не disabled)"""
        dynamic = str(item.get('dynamic', 'no')).lower() in ['yes', 'true']
        disabled = str(item.get('disabled', 'no')).lower() in ['yes', 'true']
        return not dynamic and not disabled

class SyncOperationsCalculator:
    """Калькулятор операций синхронизации"""

    @staticmethod
    def calculate_operations(master_set: Set[Tuple], slave_set: Set[Tuple], ipv6_supported: bool) -> Dict[str, Set]:
        """Вычисляет операции для синхронизации"""
        # Фильтрация master_set по поддержке IPv6
        filtered_master = {item for item in master_set if ipv6_supported or item[2] == 'ipv4'}

        # Создаем словари для быстрого поиска
        master_dict = {(addr, ip_type): comment for addr, comment, ip_type in filtered_master}
        slave_dict = {(addr, ip_type): comment for addr, comment, ip_type in slave_set}

        common_keys = set(master_dict.keys()) & set(slave_dict.keys())

        # Вычисление операции
        to_update = {
            (key[0], master_dict[key], slave_dict[key], key[1])
            for key in common_keys
            if master_dict[key] != slave_dict[key]
        }

        update_keys = {(addr, ip_type) for addr, _, _, ip_type in to_update}

        to_add = {
            item for item in filtered_master
            if (item[0], item[2]) not in update_keys
        } - slave_set
        to_remove = {
            item for item in slave_set
            if (item[0], item[2]) not in update_keys
        } - filtered_master

        return {
            'add': to_add,
            'remove': to_remove,
            'update': to_update
        }

class MikroTikSyncer:
    def __init__(self):
        self.logger = setup_logger()
        self.config = self._load_config()
        self.parallel_settings = self.config['slave_settings'].get('parallel', {
            'enabled': False, 'count_slave': 2, 'max_workers': 4, 'batch_size': 50, 'delay': 0.3
        })

        # Применение приоритетов параметров из mikrotik.yaml
        mikrotik_config = self.config.get('mikrotik', {})
        if 'batch_size' in mikrotik_config:
            self.parallel_settings['batch_size'] = mikrotik_config['batch_size']
        elif 'batch_size' in self.config['slave_settings']:
            self.parallel_settings['batch_size'] = self.config['slave_settings']['batch_size']

        self._connection_lock = threading.Lock()
        self.error_counter = 0

    def _load_config(self) -> Dict[str, Any]:
        """Загрузка всех конфигураций"""
        try:
            with open('security/mikrotik.yaml') as f:
                mikrotik_config = yaml.safe_load(f) or {}

            with open('configs/config.yaml') as f:
                general_config = yaml.safe_load(f) or {}

            slave_settings = general_config.get('sync_slave', {})
            slave_settings.setdefault('sett_auth', {'use_ssl': False})
            slave_settings.setdefault('setting_sync', {})

            # Применение приоритетов - параметры из mikrotik.yaml переопределяют config.yaml
            # Объединяем настройки с приоритетом для mikrotik.yaml
            for key in ['batch_size', 'update_delay', 'timeout']:
                if key in mikrotik_config:
                    if key == 'batch_size':
                        # batch_size может быть в корне mikrotik.yaml
                        slave_settings.setdefault('parallel', {})['batch_size'] = mikrotik_config[key]
                    elif key == 'update_delay':
                        slave_settings.setdefault('setting_sync', {})[key] = mikrotik_config[key]
                    elif key == 'timeout':
                        slave_settings[key] = mikrotik_config[key]

            # Проверка вложенной структуры mikrotik.yaml
            if 'parallel' in mikrotik_config and 'batch_size' in mikrotik_config['parallel']:
                slave_settings.setdefault('parallel', {})['batch_size'] = mikrotik_config['parallel']['batch_size']

            if 'setting_sync' in mikrotik_config and 'update_delay' in mikrotik_config['setting_sync']:
                slave_settings.setdefault('setting_sync', {})['update_delay'] = mikrotik_config['setting_sync']['update_delay']

            # Настройка уровня логирования
            log_level = slave_settings.get('logging', {}).get('log_level', 'INFO')
            self.logger.setLevel(getattr(logging, log_level))

            return {
                'mikrotik': mikrotik_config,
                'slave_settings': slave_settings
            }
        except Exception as e:
            self.logger.critical(f"Ошибка загрузки конфигурации: {str(e)}")
            raise

    def check_ipv6_support(self, api) -> bool:
        """Проверка поддержки IPv6 на устройстве"""
        try:
            package_resource = api.get_resource('/system/package')
            ipv6_package = package_resource.get(name="ipv6")
            return bool(ipv6_package and ipv6_package[0].get('disabled', 'true') == 'false')
        except Exception as e:
            self.logger.warning(f"Ошибка проверки IPv6: {str(e)}")
            return False

    def _format_connection_info(self, device_name: str, host: str, use_ssl: bool, ping_time: Optional[float] = None) -> str:
        """Форматирует информацию о подключении"""
        port = 8729 if use_ssl else 8728
        ping_info = f", Ping: {ping_time:.2f}s" if ping_time else ""
        return f"{device_name} ({host}:{port}, SSL: {use_ssl}{ping_info})"

    def sync_slave_device(self, master_data: Dict, slave: Dict) -> bool:
        """Синхронизация одного slave устройства"""
        slave_name = slave['name']
        slave_ip = slave['host']

        use_ssl = slave.get('type_auth', {}).get('use_ssl',
                      self.config['slave_settings']['sett_auth'].get('use_ssl', False))

        port = 8729 if use_ssl else 8728

        if 'list_sync' not in slave:
            self.logger.error(f"Для {slave_name} не указаны списки синхронизации")
            return False

        self.logger.info(f"\n=== Slave: {slave_name} ({slave_ip}) ===")

        # Проверка доступности
        available, ping_time = DeviceChecker.check_device_available(slave_ip, port)
        if not available:
            self.logger.error(f"Устройство {slave_name} недоступно")
            return False

        slave_pool = None
        try:
            # Подключение к устройству
            slave_pool = MikroTikConnection.create_connection(
                slave_ip, slave['username'], slave['password'], use_ssl, port
            )
            slave_api = slave_pool.get_api()

            self.logger.info(f"Успешное подключение: {self._format_connection_info(slave_name, slave_ip, use_ssl, ping_time)}")

            ipv6_supported = self.check_ipv6_support(slave_api)
            self.logger.info(f"Поддержка IPv6: {'включена' if ipv6_supported else 'отключена'}")

            # Синхронизация списков
            lists_to_sync = set(slave['list_sync'])
            self.logger.debug(f"Начинаем синхронизацию списков: {lists_to_sync}")
            result = self._sync_address_lists(slave_api, master_data, lists_to_sync, ipv6_supported, slave_name)
            self.logger.debug(f"Синхронизация списков завершена, результат: {result}")
            return result

        # Обработка ошибок авторизации Slave
        except RouterOsApiCommunicationError as e:
            error_msg = str(e)
            if "invalid user name or password" in error_msg.lower():
                self.logger.error(f"Ошибка авторизации на Slave устройстве {slave_name}. Проверьте учётные данные (логин, пароль).")
            else:
                self.logger.error(f"Ошибка связи с устройством {slave_name}: {e}")
            return False
        except RouterOsApiConnectionError as e:
            self.logger.warning(f"Ошибка подключения к {slave_name}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Ошибка синхронизации {slave_name}: {str(e)}", exc_info=True)
            return False
        finally:
            # Закрытие подключения
            if slave_pool:
                self.logger.debug(f"Закрываем подключение к {slave_name}")
                try:
                    slave_pool.disconnect()
                    self.logger.debug(f"Подключение к {slave_name} закрыто")
                except Exception as e:
                    self.logger.warning(f"Ошибка при закрытии подключения к {slave_name}: {str(e)}")

    def _sync_address_lists(self, slave_api, master_data: Dict, lists_to_sync: Set[str],
                           ipv6_supported: bool, slave_name: str) -> bool:
        """Синхронизация списков адресов"""
        synced_lists = []

        def sync_single_list(list_name: str):
            if list_name not in master_data:
                return False


            with self._connection_lock:
                slave_set = AddressListManager.get_address_set(slave_api, list_name, ipv6_supported)

            operations = SyncOperationsCalculator.calculate_operations(
                master_data[list_name], slave_set, ipv6_supported
            )

            if any(operations.values()):
                self._log_operations(list_name, operations)
                with self._connection_lock:
                    self._execute_operations(slave_api, list_name, operations, ipv6_supported, slave_name)
                synced_lists.append(list_name)
                return True
            else:
                self.logger.info(f"[{list_name}] Данные актуальны")
                return False

        # Параллельная или последовательная обработка
        if self.parallel_settings['enabled']:
            with ThreadPoolExecutor(
                max_workers=min(len(lists_to_sync), self.parallel_settings['max_workers']),
                thread_name_prefix=f"Slave_{slave_name}"
            ) as executor:
                list(executor.map(sync_single_list, lists_to_sync))
        else:
            for list_name in lists_to_sync:
                sync_single_list(list_name)

        if synced_lists:
            self.logger.info(f"Устройство {slave_name}: синхронизированы списки: {', '.join(synced_lists)}")

        return True

    def _log_operations(self, list_name: str, operations: Dict[str, Set]):
        """Логирование информации об операциях"""
        add_count = len(operations['add'])
        remove_count = len(operations['remove'])
        update_count = len(operations['update'])

        if add_count + remove_count + update_count > 0:
            self.logger.info(f"[{list_name}] Добавление: {add_count}, Удаление: {remove_count}, Обновление: {update_count}")

    def _execute_operations(self, slave_api, list_name: str, operations: Dict[str, Set],
                          ipv6_supported: bool, slave_name: str):
        """Выполнение операций синхронизации"""
        # Обновление записей
        for address, new_comment, old_comment, ip_type in operations['update']:
            if ip_type == 'ipv6' and not ipv6_supported:
                continue
            self._update_address(slave_api, list_name, address, old_comment, new_comment, ip_type)

        # Добавление записей
        self._add_addresses_batch(slave_api, list_name, operations['add'], ipv6_supported)

        # Удаление записей
        for address, comment, ip_type in operations['remove']:
            if ip_type == 'ipv6' and not ipv6_supported:
                continue
            self._remove_address(slave_api, list_name, address, comment, ip_type)

    def _update_address(self, slave_api, list_name: str, address: str, old_comment: str, new_comment: str, ip_type: str):
        """Обновление адреса"""
        try:
            resource_path = '/ipv6/firewall/address-list' if ip_type == 'ipv6' else '/ip/firewall/address-list'
            resource = slave_api.get_resource(resource_path)
            items = resource.get(list=list_name, address=address, comment=old_comment)

            if items:
                resource.set(id=items[0]['id'], comment=str(new_comment))
                update_delay = self.config['slave_settings']['setting_sync'].get('update_delay', 0.05)
                time.sleep(update_delay)
        except Exception as e:
            self.error_counter += 1
            self.logger.error(f"Ошибка обновления {address}: {str(e)}")

    def _add_addresses_batch(self, slave_api, list_name: str, addresses: Set[Tuple], ipv6_supported: bool):
        """Пакетное добавление адресов"""
        batch = []
        for i, (address, comment, ip_type) in enumerate(addresses, 1):
            if ip_type == 'ipv6' and not ipv6_supported:
                continue

            batch.append((address, comment, ip_type))

            if len(batch) >= self.parallel_settings['batch_size'] or i == len(addresses):
                self._process_batch(slave_api, list_name, batch, ipv6_supported)
                batch = []

    def _process_batch(self, slave_api, list_name: str, batch: List[Tuple], ipv6_supported: bool):
        """Обработка пачки адресов для добавления"""
        if not batch:
            return

        try:
            for addr, comm, ip_t in batch:
                resource_path = '/ipv6/firewall/address-list' if ip_t == 'ipv6' and ipv6_supported else '/ip/firewall/address-list'
                resource = slave_api.get_resource(resource_path)

                resource.add(list=list_name, address=str(addr), comment=str(comm))

        except Exception as e:
            self.error_counter += 1
            self.logger.error(f"Ошибка пакетного добавления: {str(e)}")

    def _remove_address(self, slave_api, list_name: str, address: str, comment: str, ip_type: str):
        """Удаление адреса"""
        try:
            resource_path = '/ipv6/firewall/address-list' if ip_type == 'ipv6' else '/ip/firewall/address-list'
            resource = slave_api.get_resource(resource_path)
            items = resource.get(list=list_name, address=address, comment=comment)

            if items:
                for item in items:
                    resource.remove(id=item['id'])
                update_delay = self.config['slave_settings']['setting_sync'].get('update_delay', 0.05)
                time.sleep(update_delay)
        except Exception as e:
            self.error_counter += 1
            self.logger.error(f"Ошибка удаления {address}: {str(e)}")

    def run_sync(self):
        """Основной метод запуска синхронизации"""
        start_time = time.time()
        self.logger.info("\n===== Запуск sync_slave.py - синхронизация Slave устройств =====")
        logger.info(f"Параллельный режим: {'включен' if self.parallel_settings['enabled'] else 'отключен'}")

        self._check_duplicate_slaves()

        master_stats = defaultdict(lambda: {
            'ipv6_status': 'не проверено',
            'synced_lists': set(),
            'missing_lists': set(),
            'success_slaves': set(),
            'unavailable_slaves': set()
        })

        # Обработка всех master устройств
        for master_name, master_config in self.config['mikrotik'].get('devices', {}).items():
            if not master_config.get('slaves'):
                self.logger.info(f"Группа {master_name} не имеет slaves устройств, пропускаем")
                continue

            self._process_master_group(master_name, master_config, master_stats)

        self._print_final_stats(master_stats, start_time)

    def _check_duplicate_slaves(self):
        """Проверка дубликатов slave устройств"""
        for master_name, master_config in self.config['mikrotik'].get('devices', {}).items():
            slaves = master_config.get('slaves', [])
            seen_names, seen_ips = set(), set()

            for slave in slaves:
                slave_name = slave.get('name', '')
                slave_ip = slave.get('host', '')

                if slave_name in seen_names:
                    raise ValueError(f"Duplicate slave name '{slave_name}' in master group '{master_name}'")
                if slave_ip in seen_ips:
                    raise ValueError(f"Duplicate slave IP '{slave_ip}' in master group '{master_name}'")

                seen_names.add(slave_name)
                seen_ips.add(slave_ip)

    def _process_master_group(self, master_name: str, master_config: Dict, master_stats: Dict):
        """Обработка одной группы master-slave"""
        master_ip = master_config['host']
        master_display = f"{master_config.get('name', master_name)} ({master_ip})"
        stats = master_stats[master_display]

        self.logger.info(f"\n=== Обработка группы: {master_display} ===")

        # Получение данных с master
        master_data = self._get_master_data(master_config, stats)
        if not master_data:
            return

        # Обработка slaves
        slaves = master_config['slaves']
        if self.parallel_settings['enabled']:
            self._process_slaves_parallel(slaves, master_data, stats)
        else:
            self._process_slaves_sequential(slaves, master_data, stats)

    def _get_master_data(self, master_config: Dict, stats: Dict) -> Optional[Dict]:
        """Получение данных с master устройства"""
        master_ip = master_config['host']

        use_ssl = master_config.get('type_auth', {}).get('use_ssl',
                      self.config['slave_settings']['sett_auth'].get('use_ssl', False))

        port = 8729 if use_ssl else 8728

        # Проверка доступности
        available, _ = DeviceChecker.check_device_available(master_ip, port)
        if not available:
            self.logger.error(f"Master {master_ip} недоступен")
            stats['unavailable_slaves'].update(s['name'] for s in master_config['slaves'])
            return None

        master_pool = None
        try:
            # Подключение к master
            master_pool = MikroTikConnection.create_connection(
                master_ip, master_config['username'], master_config['password'], use_ssl, port
            )
            master_api = master_pool.get_api()

            # Проверка IPv6
            ipv6_supported = self.check_ipv6_support(master_api)
            stats['ipv6_status'] = 'включен' if ipv6_supported else 'выключен'
            self.logger.info(f"Поддержка IPv6: {stats['ipv6_status']}")

            # Получение списков для синхронизации
            lists_to_fetch = self._get_sync_lists(master_config['slaves'])
            if not lists_to_fetch:
                self.logger.info("Нет списков для синхронизации")
                return None

            master_data = {}
            for list_name in lists_to_fetch:
                address_set = AddressListManager.get_address_set(master_api, list_name, ipv6_supported)
                if address_set:
                    master_data[list_name] = address_set
                    stats['synced_lists'].add(list_name)

                    # Логируем статистику по списку
                    ipv4_count = len([x for x in address_set if x[2] == 'ipv4'])
                    ipv6_count = len([x for x in address_set if x[2] == 'ipv6'])
                    self.logger.debug(f"Список {list_name}: {ipv4_count} IPv4 и {ipv6_count} IPv6 записей")
                else:
                    stats['missing_lists'].add(list_name)

            return master_data

        # Обработка ошибок Master
        except RouterOsApiCommunicationError as e:
            error_msg = str(e)
            master_name = master_config.get('name', 'Master')
            if "invalid user name or password" in error_msg.lower():
                self.logger.error(f"Ошибка авторизации на Master устройстве {master_name}. Проверьте учётные данные (логин, пароль).")
            else:
                self.logger.error(f"Ошибка связи с устройством {master_name}: {e}")
            return None
        except RouterOsApiConnectionError as e:
            master_name = master_config.get('name', 'Master')
            self.logger.warning(f"Ошибка подключения к {master_name}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Ошибка получения данных с Master {master_ip}: {str(e)}")
            return None
        finally:
            # Закрытие подключения
            if master_pool:
                master_pool.disconnect()

    def _get_sync_lists(self, slaves: List[Dict]) -> Set[str]:
        """Получение уникальных списков для синхронизации"""
        lists_to_fetch = set()
        for slave in slaves:
            if 'list_sync' in slave:
                lists_to_fetch.update(slave['list_sync'])
            else:
                self.logger.warning(f"У slave устройства {slave.get('name', 'noname')} отсутствует list_sync")
        return lists_to_fetch

    def _process_slaves_sequential(self, slaves: List[Dict], master_data: Dict, stats: Dict):
        """Обработка slaves в последовательном режиме"""
        for slave in slaves:
            slave_name = slave.get('name', 'noname')
            if self.sync_slave_device(master_data, slave):
                stats['success_slaves'].add(slave_name)
            else:
                stats['unavailable_slaves'].add(slave_name)

    def _process_slaves_parallel(self, slaves: List[Dict], master_data: Dict, stats: Dict):
        """Обработка slaves в параллельном режиме"""
        with ThreadPoolExecutor(
            max_workers=min(self.parallel_settings['count_slave'], len(slaves)),
            thread_name_prefix="SlaveSync"
        ) as executor:
            future_to_slave = {
                executor.submit(self.sync_slave_device, master_data, slave): slave.get('name', 'noname')
                for slave in slaves
            }

            for future in concurrent.futures.as_completed(future_to_slave):
                slave_name = future_to_slave[future]
                try:
                    if future.result():
                        stats['success_slaves'].add(slave_name)
                    else:
                        stats['unavailable_slaves'].add(slave_name)
                except Exception as e:
                    self.logger.error(f"Ошибка синхронизации {slave_name}: {str(e)}")
                    stats['unavailable_slaves'].add(slave_name)

    def _print_final_stats(self, master_stats: Dict, start_time: float):
        """Вывод итоговой статистики"""
        self.logger.info("\n==== ИТОГОВАЯ СТАТИСТИКА ====")

        for master, stats in master_stats.items():
            self.logger.info(f"\n=== Группа {master} ===")
            self.logger.info(f"Статус IPv6: {stats.get('ipv6_status', 'не проверено')}")

            if stats.get('synced_lists'):
                self.logger.info(f"Синхронизированные списки (общее кол-во.): {len(stats['synced_lists'])}")
            if stats.get('missing_lists'):
                self.logger.info(f"Отсутствующие списки: {len(stats['missing_lists'])}")

            self.logger.info(f"Успешные синхронизации (устройства): {len(stats.get('success_slaves', []))}")
            self.logger.info(f"Неудачные синхронизации (устройства): {len(stats.get('unavailable_slaves', []))}")

        self.logger.info(f"\nОбщее количество ошибок при синхронизации: {self.error_counter}")
        self.logger.info(f"\nОбщее время выполнения: {time.time() - start_time:.2f} секунд")
        self.logger.info("==== Синхронизация завершена ====\n")

if __name__ == '__main__':
    try:
        syncer = MikroTikSyncer()
        syncer.run_sync()
    except Exception as e:
        logging.critical(f"Критическая ошибка: {str(e)}", exc_info=True)
