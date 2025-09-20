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
from routeros_api.exceptions import RouterOsApiConnectionError

logger = None

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

class MikroTikSyncer:
    def __init__(self):
        self.load_configs()
        # Настройки параллелизма
        self.parallel_settings = self.slave_settings.get('parallel', {
            'enabled': False,
            'count_slave': 2,
            'max_workers': 4,
            'batch_size': 50,
            'delay': 0.3
        })

    def load_configs(self):
        """Загрузка конфигурационных файлов"""
        try:
            with open('security/mikrotik.yaml') as f:
                self.mikrotik_config = yaml.safe_load(f) or {}

            with open('configs/config.yaml') as f:
                general_config = yaml.safe_load(f) or {}

                # Загружает настройки для slave устройств
                self.slave_settings = general_config.get('sync_slave', {})

                # Применяет дефолтные настройки авторизации, если не указаны
                if 'sett_auth' not in self.slave_settings:
                    self.slave_settings['sett_auth'] = {'use_ssl': False}

            log_level = self.slave_settings.get('logging', {}).get('log_level', 'INFO')
            logger.setLevel(getattr(logging, log_level))

        except Exception as e:
            logger.critical(f"Ошибка загрузки конфигурации: {str(e)}")
            raise

    def check_device_available(self, ip, port, timeout=None):
        """Проверка доступности устройства"""
        timeout = timeout or self.slave_settings.get('setting_sync', {}).get('timeout', 3)
        start_time = time.time()
        ping_success = False

        # 1. Проверка ICMP ping
        try:
            param = '-n' if os.name == 'nt' else '-c'
            command = ['ping', param, '1', '-W', str(timeout), ip]
            ping_success = subprocess.call(command,
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL) == 0
        except Exception as e:
            logger.debug(f"Ошибка проверки ping для {ip}: {str(e)}")

        # 2. Проверка доступности порта
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                ping_time = time.time() - start_time
                threading.current_thread().ping_time = ping_time
                return True
        except Exception as e:
            logger.debug(f"Устройство {ip} недоступно на порту {port}: {str(e)}")
            if ping_success:
                logger.error(f"Устройство {ip} доступно по ping, но порт {port} недоступен")
            else:
                logger.error(f"Устройство {ip} полностью недоступно (нет ping и порт {port} закрыт)")
            return False

    def check_ipv6_support(self, api):
        """Проверяет, включен ли пакет IPv6 на устройстве"""
        try:
            package_resource = api.get_resource('/system/package')
            ipv6_package = package_resource.get(name="ipv6")
            if not ipv6_package:
                logger.debug("Пакет IPv6 не найден на устройстве")
                return False
            enabled = ipv6_package[0].get('disabled', 'true') == 'false'
            logger.debug(f"Поддержка IPv6: {'включена' if enabled else 'отключена'}")
            return enabled
        except Exception as e:
            logger.warning(f"Ошибка проверки пакета IPv6: {str(e)}. Предполагаем, что IPv6 отключен")
            return False

    def _format_connection_info(self, device_name, host, use_ssl, ping_time=None):
        """Форматирует информацию о подключении для логов"""
        ssl_status = "True" if use_ssl else "False"
        port = 8729 if use_ssl else 8728
        ping_info = f", Ping: {ping_time:.2f}s" if ping_time is not None else ""
        return f"{device_name} ({host}:{port}, SSL: {ssl_status}{ping_info})"

    def get_address_set(self, api, list_name, ipv6_supported=False):
        """Получение множества адресов (IPv4 и IPv6) с проверкой формата"""
        if not api:
            return set()

        result = set()

        try:
            # Обработка IPv4
            resource = api.get_resource('/ip/firewall/address-list')
            items = resource.get(list=list_name)

            for item in items:
                dynamic = str(item.get('dynamic', 'no')).lower() in ['yes', 'true']
                disabled = str(item.get('disabled', 'no')).lower() in ['yes', 'true']

                if not dynamic and not disabled:
                    address = str(item['address'])
                    comment = str(item.get('comment', ''))
                    result.add((address, comment, 'ipv4'))

            # Обработка IPv6 (если пакет включен)
            if ipv6_supported:
                ipv6_resource = api.get_resource('/ipv6/firewall/address-list')
                ipv6_items = ipv6_resource.get(list=list_name)

                for item in ipv6_items:
                    dynamic = str(item.get('dynamic', 'no')).lower() in ['yes', 'true']
                    disabled = str(item.get('disabled', 'no')).lower() in ['yes', 'true']

                    if not dynamic and not disabled:
                        address = str(item['address'])
                        comment = str(item.get('comment', ''))
                        result.add((address, comment, 'ipv6'))

        except Exception as e:
            logger.error(f"Ошибка получения списка {list_name}: {str(e)}")

            if result:
                ipv4_count = len([x for x in result if x[2] == 'ipv4'])
                ipv6_count = len([x for x in result if x[2] == 'ipv6'])
                logger.debug(f"Список {list_name}: {len(result)} записей (IPv4: {ipv4_count}, IPv6: {ipv6_count})")

        return result

    def create_connection(self, host, username, password, use_ssl, port):
        """Создание подключения"""
        ssl_context = None

        if use_ssl:
            import ssl
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

        return routeros_api.RouterOsApiPool(
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

    def _find_updates(self, master_set, slave_set):
        """
        Находит записи для обновления (одинаковый адрес, но разные комментарии)
        Возвращает множество кортежей (address, new_comment, old_comment, ip_type)
        """
        updates = set()

        # Создает словарь для быстрого поиска по адресу и типу
        master_dict = {(addr, ip_type): comment for addr, comment, ip_type in master_set}
        slave_dict = {(addr, ip_type): comment for addr, comment, ip_type in slave_set}

        # Поиск пересекающихся адресов с разными комментариями
        common_addresses = set(master_dict.keys()) & set(slave_dict.keys())

        for addr, ip_type in common_addresses:
            master_comment = master_dict[(addr, ip_type)]
            slave_comment = slave_dict[(addr, ip_type)]

            if master_comment != slave_comment:
                updates.add((addr, master_comment, slave_comment, ip_type))

        return updates

    def sync_slave_parallel(self, master, slave):
        """Параллельная синхронизация с добавлением информации о IPv6"""
        slave_name = slave['name']
        slave_ip = slave['host']
        use_ssl = slave.get('type_auth', {}).get('use_ssl', False)
        port = 8729 if use_ssl else 8728

        # Проверяет наличие list_sync конфигурации
        if 'list_sync' not in slave:
            logger.error(f"Для устройства {slave_name} не указаны списки синхронизации list_sync. Пропускаем.")
            return False

        logger.info(f"\n=== Slave: {slave_name} ({slave_ip}) ===")
        logger.info(f"Параметры подключения: {self._format_connection_info(slave_name, slave_ip, use_ssl)}")

        if not self.check_device_available(slave_ip, port):
            logger.error(f"Устройство {slave_name} ({slave_ip}) недоступно")
            return False

        try:
            slave_pool = self.create_connection(
                host=slave_ip,
                username=slave['username'],
                password=slave['password'],
                use_ssl=use_ssl,
                port=port
            )
            slave_api = slave_pool.get_api()
            ping_time = getattr(threading.current_thread(), 'ping_time', None)
            logger.info(f"Успешное подключение к {self._format_connection_info(slave_name, slave_ip, use_ssl, ping_time)}")
            ipv6_supported = self.check_ipv6_support(slave_api)
            logger.info(f"Поддержка IPv6 на {slave_name}: {'включена' if ipv6_supported else 'отключена'}")

            # Получение списков для синхронизации
            lists_to_sync = list(set(slave.get('list_sync', [])))
            needs_sync = False
            synced_lists = []

            # Создание ThreadPool для обработки списков
            with ThreadPoolExecutor(
                max_workers=min(len(lists_to_sync), self.parallel_settings['max_workers']),
                thread_name_prefix=f"Slave_{slave_name}"
            ) as executor:
                futures = []
                for list_name in lists_to_sync:
                    if list_name not in master['data']:
                        continue

                    slave_set = self.get_address_set(slave_api, list_name, ipv6_supported)

                    to_add = master['data'][list_name] - slave_set
                    to_remove = slave_set - master['data'][list_name]
                    to_update = self._find_updates(master['data'][list_name], slave_set)

                    if not to_add and not to_remove:
                        logger.info(f"[{list_name}] Данные актуальны, синхронизация не требуется")
                        continue

                    needs_sync = True
                    synced_lists.append(list_name)
                    futures.append(
                        executor.submit(
                            self.sync_single_list,
                            slave_api,
                            list_name,
                            master['data'][list_name],
                            slave_set,
                            ipv6_supported,
                            slave_name
                        )
                    )

                if not futures:
                    if not needs_sync:
                        logger.info(f"Все данные на устройстве {slave_name} актуальны")
                    return True

                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Ошибка при синхронизации: {str(e)}")

            if needs_sync:
                logger.info(f"Устройство {slave_name}: синхронизированы списки: {', '.join(synced_lists)}")
            return True

        except Exception as e:
            logger.error(f"Ошибка параллельной синхронизации {slave_name}: {str(e)}")
            return False
        finally:
            if 'slave_pool' in locals():
                slave_pool.disconnect()
        logger.info(f"=== END Slave: {slave_name} ===\n")

    def sync_slave(self, master, slave):
        """Синхронизация одного slave устройства с поддержкой IPv6"""
        if self.parallel_settings['enabled']:
            return self.sync_slave_parallel(master, slave)

        slave_name = slave['name']
        slave_ip = slave['host']
        use_ssl = slave.get('type_auth', {}).get('use_ssl', False)
        port = 8729 if use_ssl else 8728

        # Проверка параметра list_sync в конфиге security/mikrotik.yaml
        if 'list_sync' not in slave:
            logger.error(f"Для устройства {slave_name} не указаны списки синхронизации в list_sync. Пропускаем.")
            return False

        delay = self.parallel_settings.get('delay', 0.3)
        batch_size = self.parallel_settings.get('batch_size', 50)

        logger.info(f"\n=== Обработка Slave: {slave_name} ({slave_ip}) ===")
        logger.info(f"Параметры подключения: {self._format_connection_info(slave_name, slave_ip, use_ssl)}")

        if not self.check_device_available(slave_ip, port):
            logger.error(f"Устройство {slave_name} недоступно на порту {port}")
            return False

        try:
            slave_pool = self.create_connection(
                host=slave_ip,
                username=slave['username'],
                password=slave['password'],
                use_ssl=use_ssl,
                port=port
            )
            slave_api = slave_pool.get_api()
            ping_time = getattr(threading.current_thread(), 'ping_time', None)
            logger.info(f"Успешное подключение к {self._format_connection_info(slave_name, slave_ip, use_ssl, ping_time)}")
            ipv6_supported = self.check_ipv6_support(slave_api)
            logger.info(f"Поддержка IPv6 на устройстве: {'включена' if ipv6_supported else 'отключена'}")

            lists_to_sync = list(set(slave['list_sync']))
            needs_sync = False
            synced_lists = []

            for list_name in lists_to_sync:
                if list_name not in master['data']:
                    continue

                # Фильтрует master_set перед синхронизацией
                master_set = master['data'][list_name]
                filtered_master_set = set()
                for item in master_set:
                    if ipv6_supported or item[2] == 'ipv4':
                        filtered_master_set.add(item)

                slave_set = self.get_address_set(slave_api, list_name, ipv6_supported)

                to_update = self._find_updates(filtered_master_set, slave_set)

                # Исключение обновляемых записей из вычисления добавления/удаления
                update_addresses = {(addr, ip_type) for addr, new_comm, old_comm, ip_type in to_update}

                to_add = {item for item in filtered_master_set
                          if (item[0], item[2]) not in update_addresses} - slave_set

                to_remove = {item for item in slave_set
                             if (item[0], item[2]) not in update_addresses} - filtered_master_set

                if not to_add and not to_remove and not to_update:
                    logger.info(f"[{list_name}] Данные актуальны, синхронизация не требуется")
                    continue

                needs_sync = True
                synced_lists.append(list_name)

                logger.debug(f"Master records: {len(master_set)} (IPv4: {len([x for x in master_set if x[2] == 'ipv4'])}, IPv6: {len([x for x in master_set if x[2] == 'ipv6'])})")
                logger.debug(f"Slave records: {len(slave_set)} (IPv4: {len([x for x in slave_set if x[2] == 'ipv4'])}, IPv6: {len([x for x in slave_set if x[2] == 'ipv6'])})")

                logger.info(f"[{list_name}] Записей к добавлению: {len(to_add)} (IPv4: {len([x for x in to_add if x[2] == 'ipv4'])}, IPv6: {len([x for x in to_add if x[2] == 'ipv6'])})")
                logger.info(f"[{list_name}] Записей к удалению: {len(to_remove)} (IPv4: {len([x for x in to_remove if x[2] == 'ipv4'])}, IPv6: {len([x for x in to_remove if x[2] == 'ipv6'])})")
                logger.info(f"[{list_name}] Записей к обновлению: {len(to_update)} (IPv4: {len([x for x in to_update if x[3] == 'ipv4'])}, IPv6: {len([x for x in to_update if x[3] == 'ipv6'])})")

                # Обновление
                if to_update:
                    updated_count = {'ipv4': 0, 'ipv6': 0}
                    for address, new_comment, old_comment, ip_type in to_update:
                        try:
                            if ip_type == 'ipv4':
                                resource = slave_api.get_resource('/ip/firewall/address-list')
                            elif ip_type == 'ipv6' and ipv6_supported:
                                resource = slave_api.get_resource('/ipv6/firewall/address-list')
                            else:
                                continue

                            # Поиск существующей записи для обновления
                            items = resource.get(list=list_name, address=address, comment=old_comment)
                            if items:
                                for item in items:
                                    resource.set(id=item['id'], comment=str(new_comment))
                                    updated_count[ip_type] += 1
                                    break
                            time.sleep(delay/5)
                        except Exception as e:
                            logger.error(f"Ошибка обновления {ip_type} записи {address}: {str(e)}")
                    logger.info(f"Обновлено записей: IPv4 - {updated_count['ipv4']}, IPv6 - {updated_count['ipv6']}")

               # Добавление
                if to_add:
                    added_count = {'ipv4': 0, 'ipv6': 0}
                    for address, comment, ip_type in to_add:
                        try:

                            # Проверка - существует ли запись на устройстве
                            if ip_type == 'ipv4':
                                resource = slave_api.get_resource('/ip/firewall/address-list')
                                existing = resource.get(list=list_name, address=address)
                            elif ip_type == 'ipv6' and ipv6_supported:
                                resource = slave_api.get_resource('/ipv6/firewall/address-list')
                                existing = resource.get(list=list_name, address=address)
                            else:
                                continue

                            if existing:  # Запись существует на устройстве -> пропуск
                                logger.debug(f"Запись {address} уже существует, пропускаем добавление")
                                continue

                            resource.add(
                                list=list_name,
                                address=str(address),
                                comment=str(comment)
                            )
                            added_count[ip_type] += 1

                            if (added_count['ipv4'] + added_count['ipv6']) % batch_size == 0:  # Применяет batch_size из настроек
                                logger.debug(f"Добавлено {added_count['ipv4'] + added_count['ipv6']} записей")
                                time.sleep(delay)  # Применяет delay из настроек
                        except Exception as e:
                            logger.error(f"Ошибка добавления {ip_type} записи {address}: {str(e)}")
                    logger.info(f"Добавлено записей: IPv4 - {added_count['ipv4']}, IPv6 - {added_count['ipv6']}")


                # Удаление
                if to_remove:
                    removed_count = {'ipv4': 0, 'ipv6': 0}
                    for address, comment, ip_type in to_remove:
                        try:
                            if ip_type == 'ipv4':
                                resource = slave_api.get_resource('/ip/firewall/address-list')
                            elif ip_type == 'ipv6' and ipv6_supported:
                                resource = slave_api.get_resource('/ipv6/firewall/address-list')
                            else:
                                continue

                            items = resource.get(list=list_name, address=address)
                            if items:
                                for item in items:
                                    if str(item.get('comment', '')) == comment:
                                        resource.remove(id=item['id'])
                                        removed_count[ip_type] += 1
                            time.sleep(delay/5)
                        except Exception as e:
                            logger.error(f"Ошибка удаления {ip_type} записи {address}: {str(e)}")
                    logger.info(f"Удалено записей: IPv4 - {removed_count['ipv4']}, IPv6 - {removed_count['ipv6']}")

                logger.info(f"Список {list_name} успешно синхронизирован")

            if not needs_sync:
                logger.info(f"Все данные на устройстве {slave_name} актуальны")
            elif synced_lists:
                logger.info(f"Устройство {slave_name}: синхронизированы списки: {', '.join(synced_lists)}")

            return True

        except Exception as e:
            logger.error(f"Ошибка синхронизации {slave_name}: {str(e)}", exc_info=True)
            return False
        finally:
            if 'slave_pool' in locals():
                slave_pool.disconnect()

    def sync_single_list(self, slave_api, list_name, master_set, slave_set, ipv6_supported, slave_name):
        """Синхронизация одного списка с проверкой существующих записей"""
        thread_name = threading.current_thread().name.replace("ThreadPoolExecutor-", "")
        slave_ip = getattr(threading.current_thread(), 'slave_ip', 'N/A')
        logger.info(f"[Slave: {slave_name} ({slave_ip})][Поток: {thread_name}] Обработка списка {list_name}")

        # Фильтрует master_set в соответствии с поддержкой IPv6
        filtered_master_set = set()
        for item in master_set:
            if ipv6_supported or item[2] == 'ipv4':  # Получать только IPv4 (если IPv6 не поддерживается)
                filtered_master_set.add(item)

        to_add = filtered_master_set - slave_set
        to_remove = slave_set - filtered_master_set
        to_update = self._find_updates(filtered_master_set, slave_set)

        # Обновление записей (изменение комментариев)
        updated_count = {'ipv4': 0, 'ipv6': 0}
        for address, new_comment, old_comment, ip_type in to_update:
            try:
                # Пропуск IPv6 (если не поддерживается)
                if ip_type == 'ipv6' and not ipv6_supported:
                    continue

                resource = slave_api.get_resource(
                    '/ipv6/firewall/address-list' if ip_type == 'ipv6' and ipv6_supported
                    else '/ip/firewall/address-list'
                )
                # Поиск записи для обновления
                items = resource.get(list=list_name, address=address, comment=old_comment)
                if items:
                    for item in items:
                        resource.set(id=item['id'], comment=str(new_comment))
                        updated_count[ip_type] += 1
                        break
                time.sleep(self.parallel_settings['delay']/5)
            except Exception as e:
                logger.error(f"[Поток {thread_name}] Ошибка обновления {ip_type} записи {address}: {str(e)}")

        # Добавление записей
        added_count = {'ipv4': 0, 'ipv6': 0}
        batch = []
        for i, (address, comment, ip_type) in enumerate(to_add, 1):
            try:
                if ip_type == 'ipv6' and not ipv6_supported:
                    continue

                resource = slave_api.get_resource(
                    '/ipv6/firewall/address-list' if ip_type == 'ipv6' and ipv6_supported
                    else '/ip/firewall/address-list'
                )
                # Проверка, существует ли уже такая запись
                existing = resource.get(list=list_name, address=address, comment=comment)
                if not existing:
                    batch.append((address, comment, ip_type))
            except Exception as e:
                logger.error(f"[Поток {thread_name}] Ошибка проверки существующей записи {address}: {str(e)}")


        # Удаление записей
        removed_count = {'ipv4': 0, 'ipv6': 0}
        for address, comment, ip_type in to_remove:
            try:
                if ip_type == 'ipv6' and not ipv6_supported:
                    continue

                resource = slave_api.get_resource(
                    '/ipv6/firewall/address-list' if ip_type == 'ipv6' and ipv6_supported
                    else '/ip/firewall/address-list'
                )
                items = resource.get(list=list_name, address=address, comment=comment)
                if items:
                    for item in items:
                        resource.remove(id=item['id'])
                        removed_count[ip_type] += 1
                time.sleep(self.parallel_settings['delay']/5)
            except Exception as e:
                logger.error(f"[Поток {thread_name}] Ошибка удаления {ip_type} записи {address}: {str(e)}")

            if len(batch) >= self.parallel_settings['batch_size'] or i == len(to_add):
                if batch:
                    try:
                        for addr, comm, ip_t in batch:
                            resource = slave_api.get_resource(
                                '/ipv6/firewall/address-list' if ip_t == 'ipv6' and ipv6_supported
                                else '/ip/firewall/address-list'
                            )
                            resource.add(list=list_name, address=str(addr), comment=str(comm))
                            added_count[ip_t] += 1

                        logger.debug(f"[Поток {thread_name}] {slave_name}: добавлено {len(batch)} записей")
                        batch = []
                        time.sleep(self.parallel_settings['delay'])
                    except Exception as e:
                        logger.error(f"[Поток {thread_name}] Ошибка пакетного добавления: {str(e)}")

        logger.info(f"[Поток {thread_name}] {slave_name}/{list_name}: добавлено IPv4 - {added_count['ipv4']}, IPv6 - {added_count['ipv6']}; удалено IPv4 - {removed_count['ipv4']}, IPv6 - {removed_count['ipv6']}; обновлено IPv4 - {updated_count['ipv4']}, IPv6 - {updated_count['ipv6']}")
        return True

    def process_master(self, master_name, master_config):
        """Обработка одного master устройства и его slaves с поддержкой IPv6"""
        master_ip = master_config['host']
        master_display_name = master_config.get('name', master_name)
        use_ssl = master_config.get('type_auth', {}).get('use_ssl', False)
        port = 8729 if use_ssl else 8728

        logger.info(f"\n=== Обработка Master: {master_display_name} ===")
        logger.info(f"Параметры подключения: {self._format_connection_info(master_display_name, master_ip, use_ssl)}")


        # Проверка доступности
        if not self.check_device_available(master_ip, port):
            logger.error(f"Master {self._format_connection_info(master_display_name, master_ip, use_ssl)} недоступен")
            return 0, 0

        try:
            master_pool = routeros_api.RouterOsApiPool(
                host=master_ip,
                username=master_config['username'],
                password=master_config['password'],
                plaintext_login=True,
                use_ssl=use_ssl,
                port=port,
                ssl_verify=False,
                ssl_verify_hostname=False
            )
            master_api = master_pool.get_api()

            # Проверка поддержки IPv6 на master
            ipv6_supported = self.check_ipv6_support(master_api)
            logger.info(
                f"Успешное подключение к {master_display_name} | "
                f"Порт: {port}, SSL: {'ВКЛ' if use_ssl else 'ВЫКЛ'}, "
                f"IPv6: {'включен' if ipv6_supported else 'выключен'}"
            )

            # Получение необходимых списков
            master_data = {}
            lists_to_fetch = set()

            # Получение всех уникальных списков из slaves
            for slave in master_config.get('slaves', []):
                if 'list_sync' in slave:
                    lists_to_fetch.update(slave['list_sync'])

            if not lists_to_fetch:
                logger.info("Нет списков для синхронизации")
                return 0, 0

            logger.info(f"Получаем списки с Master: {', '.join(lists_to_fetch)}")

            for list_name in lists_to_fetch:
                address_set = self.get_address_set(master_api, list_name,ipv6_supported)
                if address_set is not None:
                    master_data[list_name] = address_set
                    ipv4_count = len([x for x in address_set if x[2] == 'ipv4'])
                    ipv6_count = len([x for x in address_set if x[2] == 'ipv6'])
                    logger.debug(f"Список {list_name}: {ipv4_count} IPv4 и {ipv6_count} IPv6 записей")

            # Обработка slaves
            success_count = 0
            error_count = 0

            for slave in master_config.get('slaves', []):
                if self.sync_slave({'data': master_data}, slave):
                    success_count += 1
                else:
                    error_count += 1

            return success_count, error_count

        except Exception as e:
            logger.error(f"Ошибка обработки Master {master_name}: {str(e)}")
            return 0, len(master_config.get('slaves', []))
        finally:
            if 'master_pool' in locals():
                master_pool.disconnect()


    def run_sync(self):
        """Основной метод запуска синхронизации"""
        start_time = time.time()
        logger.info("\n===== Запуск sync_slave.py - синхронизация Slave устройств =====")
        logger.info(f"Параллельный режим: {'включен' if self.parallel_settings['enabled'] else 'отключен'}")

        # Проверка дубликатов в пределах Master
        for master_name, master_config in self.mikrotik_config.get('devices', {}).items():
            if 'slaves' not in master_config:
                continue

            slaves = master_config['slaves']
            seen_names = set()
            seen_ips = set()

            for slave in slaves:
                slave_name = slave.get('name', '')
                slave_ip = slave.get('host', '')

                # Проверка дубликатов имен
                if slave_name in seen_names:
                    logger.error(f"ОШИБКА: В группе {master_name} обнаружено дублирование имени Slave: {slave_name}")
                    raise ValueError(f"Duplicate slave name '{slave_name}' in master group '{master_name}'")
                seen_names.add(slave_name)

                # Проверка дубликатов IP
                if slave_ip in seen_ips:
                    logger.error(f"ОШИБКА: В группе {master_name} обнаружено дублирование IP: {slave_ip}")
                    raise ValueError(f"Duplicate slave IP '{slave_ip}' in master group '{master_name}'")
                seen_ips.add(slave_ip)

            logger.debug(f"Группа {master_name}: проверено {len(slaves)} Slave устройств, дубликатов не обнаружено")

        if self.parallel_settings['enabled']:
            logger.info(f"Настройки параллелизма: max_workers={self.parallel_settings['max_workers']}, "
                       f"batch_size={self.parallel_settings['batch_size']}, "
                       f"delay={self.parallel_settings['delay']}")

        master_stats = defaultdict(lambda: {
            'ipv6_status': 'не проверено',
            'synced_lists': set(),
            'missing_lists': set(),
            'success_slaves': set(),
            'unavailable_slaves': set()
        })

        for master_name, master_config in self.mikrotik_config.get('devices', {}).items():
            if 'slaves' not in master_config or not master_config['slaves']:
                logger.info(f"Группа {master_name} не имеет slaves устройств, пропускаем")
                continue

            master_ip = master_config['host']
            master_display = f"{master_config.get('name', master_name)} ({master_ip})"
            current_stats = master_stats[master_display]
            use_ssl = master_config.get('type_auth', {}).get('use_ssl', False)

            logger.info(f"\n=== Обработка группы: {master_display} ===")
            ping_time = getattr(threading.current_thread(), 'ping_time', None)
            logger.info(f"Параметры подключения: {self._format_connection_info(master_config.get('name', master_name), master_ip, use_ssl, ping_time)}")

            try:
                use_ssl = master_config.get('type_auth', {}).get('use_ssl', False)
                port = 8729 if use_ssl else 8728

                if not self.check_device_available(master_ip, port):
                    logger.error(f"Master {master_display} недоступен на порту {port}")
                    current_stats['unavailable_slaves'].update(s['name'] for s in master_config['slaves'])
                    continue

                master_pool = self.create_connection(
                    host=master_ip,
                    username=master_config['username'],
                    password=master_config['password'],
                    use_ssl=use_ssl,
                    port=port
                )
                master_api = master_pool.get_api()
                logger.info(f"Успешное подключение к {master_display}")

                ipv6_supported = self.check_ipv6_support(master_api)
                current_stats['ipv6_status'] = 'включен' if ipv6_supported else 'выключен'
                logger.info(f"Поддержка IPv6: {current_stats['ipv6_status']}")

                lists_to_fetch = set()
                for slave in master_config['slaves']:
                    if 'list_sync' in slave:
                        lists_to_fetch.update(slave['list_sync'])
                    else:
                        logger.warning(f"У slave устройства {slave.get('name', 'noname')} отсутствует list_sync")

                if not lists_to_fetch:
                    logger.info("Нет списков для синхронизации")
                    continue

                master_data = {}
                for list_name in lists_to_fetch:
                    address_set = self.get_address_set(master_api, list_name, ipv6_supported)
                    if address_set:
                        master_data[list_name] = address_set
                        current_stats['synced_lists'].add(list_name)
                        ipv4_count = len([x for x in address_set if x[2] == 'ipv4'])
                        ipv6_count = len([x for x in address_set if x[2] == 'ipv6'])
                        logger.debug(f"Список {list_name}: {ipv4_count} IPv4 и {ipv6_count} IPv6 записей")
                    else:
                        current_stats['missing_lists'].add(list_name)

                if self.parallel_settings['enabled']:
                    self._process_slaves_parallel(master_config, master_data, master_display, current_stats)
                else:
                    self._process_slaves_sequential(master_config, master_data, master_display, current_stats)

            except Exception as e:
                logger.error(f"Ошибка получения данных с Master {master_display}: {str(e)}")
                continue
            finally:
                if master_pool:
                    master_pool.disconnect()

        # Вывод итоговой статистики
        logger.info("\n==== ИТОГОВАЯ СТАТИСТИКА ====")
        for master, stats in master_stats.items():
            logger.info(f"\n=== Группа {master} ===")
            logger.info(f"Статус IPv6: {stats.get('ipv6_status', 'не проверено')}")

            if stats.get('synced_lists'):
                logger.info(f"\nУспешно синхронизированные списки:")
                for lst in sorted(stats['synced_lists']):
                    logger.info(f"  - {lst}")

            if stats.get('missing_lists'):
                logger.info(f"\nОтсутствующие списки на Master:")
                for lst in sorted(stats['missing_lists']):
                    logger.info(f"  - {lst}")

            logger.info("\nРезультаты синхронизации Slave устройств:")
            if stats.get('success_slaves'):
                logger.info(f"Успешно: {len(stats['success_slaves'])}")
                for slave in sorted(stats['success_slaves']):
                    logger.info(f"  - {slave}")

            if stats.get('unavailable_slaves'):
                logger.info(f"Недоступно: {len(stats['unavailable_slaves'])}")
                for slave in sorted(stats['unavailable_slaves']):
                    logger.info(f"  - {slave}")

        logger.info(f"\nОбщее время выполнения: {time.time() - start_time:.2f} секунд")
        logger.info("\n==== Синхронизация завершена ====\n")

    def _process_slaves_sequential(self, master_config, master_data, master_display, stats):
        """Обработка slaves в последовательном режиме"""
        for slave in master_config['slaves']:
            slave_name = slave.get('name', 'noname')
            if self.sync_slave({'data': master_data}, slave):
                stats['success_slaves'].add(slave_name)
            else:
                stats['unavailable_slaves'].add(slave_name)

    def _process_slaves_parallel(self, master_config, master_data, master_display, stats):
        """Обработка slaves в параллельном режиме"""
        with ThreadPoolExecutor(
            max_workers=min(
                self.parallel_settings['count_slave'],
                len(master_config['slaves'])
            ),
            thread_name_prefix=f"M_{master_display[:10]}"
        ) as executor:
            futures = {
                executor.submit(
                    self.sync_slave_parallel,
                    {'data': master_data},
                    slave
                ): slave.get('name', 'noname')
                for slave in master_config['slaves']
            }

            for future in concurrent.futures.as_completed(futures):
                slave_name = futures[future]
                try:
                    if future.result():
                        stats['success_slaves'].add(slave_name)
                    else:
                        stats['unavailable_slaves'].add(slave_name)
                    logger.debug(f"Успешно завершена синхронизация {slave_name}")
                except Exception as e:
                    logger.error(f"Ошибка синхронизации {slave_name}: {str(e)}")
                    stats['unavailable_slaves'].add(slave_name)

if __name__ == '__main__':
    try:
        logger = setup_logger()
        syncer = MikroTikSyncer()
        syncer.run_sync()
    except Exception as e:
        logger.critical(f"Критическая ошибка: {str(e)}", exc_info=True)
