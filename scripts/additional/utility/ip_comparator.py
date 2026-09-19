#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Скрипт для сравнения IPv4/IPv6 адресов в множестве TXT файлов.
Обнаруживает точные совпадения IP-адресов между файлами и вхождение IP в подсети.
Поддерживает IP-адреса как с маской и без маски.
"""

import os
import logging
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import Dict, Set, List, Union, Optional, Tuple
import time
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# ==================== НАСТРОЙКИ ====================
# Укажите список абсолютных путей до директорий с TXT файлами (примеры)
DIRECTORIES_PATHS = [
    "raw-data/ExampleList1/RouteList/",
    "raw-data/ExampleList2/RouteList/",
    "raw-data/ExampleList3/RouteList/",
]

# Уровень логирования (DEBUG - детальный, INFO - только ключевые моменты)
LOG_LEVEL = logging.INFO

# Проверка вхождения IP в подсети между директориями
MEMBERSHIP_CHECK = False  # True - включить, False - отключить

# Количество потоков для чтения файлов (0 - отключить многопоточность)
THREAD_POOL_SIZE = 4  # Рекомендуемые значения: 2, 4, 8
# ==================================================

class IPComparator:
    """Класс для сравнения IP-адресов в файлах"""

    def __init__(self, directories_paths: List[str], recursive: bool = True, use_threading: bool = True):
        self.directories_paths = [Path(path) for path in directories_paths]
        self.recursive = recursive
        self.use_threading = use_threading and THREAD_POOL_SIZE > 0
        self.thread_pool_size = THREAD_POOL_SIZE if use_threading else 0

        self.files_data: Dict[str, Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]] = {}
        self.directory_files_data: Dict[str, Dict[str, Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]]] = {}
        self.directory_networks_data: Dict[str, Dict[str, Set[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]]] = {}

        # Кэши для парсинга
        self._parse_ip_cache = {}
        self._parse_network_cache = {}

        # Блокировка для потокобезопасности
        self._lock = threading.Lock()

        # Счетчики для отслеживания прогресса
        self._loaded_files_count = 0
        self._total_files_count = 0

        self.setup_logging()

    def setup_logging(self):
        """Настройка логирования в терминал и файл"""
        script_name = Path(__file__).stem
        log_filename = f"{script_name}.log"

        log_path = Path(f'logs/additional/{script_name}/{log_filename}')
        log_path.parent.mkdir(parents=True, exist_ok=True)

        logging.basicConfig(
            level=LOG_LEVEL,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(log_path, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )

        logging.debug(f"Лог-файл: {log_path}")

    def parse_ip(self, ip_str: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        """
        Парсинг IP-адреса с кэшированием.
        Поддерживает:
        - Чистый IP-адрес (без маски)
        - IP-адрес с маской (CIDR): 192.168.1.0/24, 2001:db8::/32
        Возвращает объект IPv4Address или IPv6Address, или None при ошибке.
        """
        if ip_str in self._parse_ip_cache:
            return self._parse_ip_cache[ip_str]

        ip_str = ip_str.strip()
        if not ip_str:
            self._parse_ip_cache[ip_str] = None
            return None

        try:
            result = ipaddress.ip_address(ip_str)
            self._parse_ip_cache[ip_str] = result
            return result
        except ValueError:
            pass

        try:
            network = ipaddress.ip_network(ip_str, strict=False)
            result = network.network_address
            self._parse_ip_cache[ip_str] = result
            return result
        except ValueError:
            logging.debug(f"Неверный IP-адрес или сеть '{ip_str}'")
            self._parse_ip_cache[ip_str] = None
            return None

    def parse_network(self, ip_str: str) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """
        Парсинг IP-адреса как сети с кэшированием.
        Поддерживает:
        - Чистый IP-адрес (без маски) - преобразуется в сеть /32 или /128
        - IP-адрес с маской (CIDR): 192.168.1.0/24, 2001:db8::/32
        Возвращает объект IPv4Network или IPv6Network, или None при ошибке.
        """
        if ip_str in self._parse_network_cache:
            return self._parse_network_cache[ip_str]

        ip_str = ip_str.strip()
        if not ip_str:
            self._parse_network_cache[ip_str] = None
            return None

        try:
            result = ipaddress.ip_network(ip_str, strict=False)
            self._parse_network_cache[ip_str] = result
            return result
        except ValueError:
            pass

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                result = ipaddress.ip_network(f"{ip_obj}/32", strict=False)
            else:
                result = ipaddress.ip_network(f"{ip_obj}/128", strict=False)
            self._parse_network_cache[ip_str] = result
            return result
        except ValueError:
            logging.debug(f"Неверный IP-адрес или сеть '{ip_str}'")
            self._parse_network_cache[ip_str] = None
            return None

    def find_txt_files(self) -> Dict[Path, List[Path]]:
        """Поиск всех TXT файлов в указанных директориях"""
        dir_files = {}

        for dir_path in self.directories_paths:
            if not dir_path.exists():
                logging.warning(f"Директория не существует: {dir_path}")
                continue

            if not dir_path.is_dir():
                logging.warning(f"Указанный путь не является директорией: {dir_path}")
                continue

            if self.recursive:
                files = list(dir_path.rglob("*.txt"))
            else:
                files = list(dir_path.glob("*.txt"))

            dir_files[dir_path] = files
            logging.debug(f"Найдено {len(files)} TXT файлов в {dir_path}")

        return dir_files

    def read_file(self, file_path: Path) -> Tuple[Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]],
                                                   Set[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]]:
        """
        Чтение файла и извлечение IP-адресов и сетей.
        """
        ip_set = set()
        network_set = set()

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                line_number = 0
                for line in f:
                    line_number += 1
                    line = line.strip()
                    if not line:
                        continue

                    network_obj = self.parse_network(line)
                    if network_obj:
                        network_set.add(network_obj)
                        ip_obj = self.parse_ip(line)
                        if ip_obj:
                            ip_set.add(ip_obj)
                    elif line.strip():
                        logging.debug(f"Файл {file_path.name}, строка {line_number}: пропущено '{line}'")

            logging.debug(f"Загружено {len(ip_set)} IP-адресов и {len(network_set)} сетей из файла: {file_path.name}")
            return ip_set, network_set

        except FileNotFoundError:
            logging.error(f"Файл не найден: {file_path}")
            return set(), set()
        except PermissionError:
            logging.error(f"Нет прав доступа к файлу: {file_path}")
            return set(), set()
        except Exception as e:
            logging.error(f"Ошибка при чтении файла {file_path}: {e}")
            return set(), set()

    def _process_file_result(self, dir_path: Path, file_path: Path, ip_set: Set, network_set: Set):
        """
        Потоковая обработка результата чтения файла.
        """
        if ip_set or network_set:
            with self._lock:
                dir_key = str(dir_path)
                rel_path = str(file_path)

                # Инициализирует структуры для директории
                if dir_key not in self.directory_files_data:
                    self.directory_files_data[dir_key] = {}
                    self.directory_networks_data[dir_key] = {}

                self.directory_files_data[dir_key][rel_path] = ip_set
                self.directory_networks_data[dir_key][rel_path] = network_set
                self.files_data[rel_path] = ip_set

                self._loaded_files_count += 1

                # Логирует прогресс каждые 10 файлов
                if self._loaded_files_count % 10 == 0:
                    logging.debug(f"Прогресс загрузки: {self._loaded_files_count}/{self._total_files_count} файлов")
        else:
            logging.debug(f"Файл не содержит IP-адресов: {file_path.name}")

    def load_files(self):
        """
        Загрузка всех TXT файлов из директорий.
        Поддерживает последовательную и многопоточную загрузку.
        """
        dir_files = self.find_txt_files()

        if not dir_files:
            logging.warning("Не найдено TXT файлов для обработки")
            return False

        # Подсчет общего количества файлов
        self._total_files_count = sum(len(files) for files in dir_files.values())
        self._loaded_files_count = 0

        # Сбор всех файлов в список для обработки
        files_to_process = []
        for dir_path, files in dir_files.items():
            for file_path in files:
                files_to_process.append((dir_path, file_path))

        logging.info(f"Найдено {self._total_files_count} TXT файлов для обработки")

        if self.use_threading:
            # Многопоточная загрузка
            with ThreadPoolExecutor(max_workers=self.thread_pool_size) as executor:
                # Создание задачи для каждого файла
                future_to_file = {
                    executor.submit(self.read_file, file_path): (dir_path, file_path)
                    for dir_path, file_path in files_to_process
                }

                for future in as_completed(future_to_file):
                    dir_path, file_path = future_to_file[future]
                    try:
                        ip_set, network_set = future.result()
                        self._process_file_result(dir_path, file_path, ip_set, network_set)
                    except Exception as e:
                        logging.error(f"Ошибка при обработке файла {file_path}: {e}")
        else:
            # Последовательная загрузка
            for dir_path, file_path in files_to_process:
                logging.debug(f"Чтение файла: {file_path}")
                ip_set, network_set = self.read_file(file_path)
                self._process_file_result(dir_path, file_path, ip_set, network_set)

        # Проверка успешности загрузки
        logging.info(f"Загружено {self._loaded_files_count} файлов с IP-адресами")

        # Подсчет директорий с файлами
        directories_with_files = sum(1 for files in self.directory_files_data.values() if files)
        logging.info(f"Директорий с загруженными файлами: {directories_with_files} из {len(self.directories_paths)}")

        if directories_with_files < 2:
            logging.warning(f"Недостаточно директорий с файлами для сравнения (необходимо минимум 2). Найдено: {directories_with_files}")
            return False

        return bool(self.files_data)

    def compare_across_directories(self):
        """Сравнение IP-адресов между разными директориями"""
        if len(self.directory_files_data) < 2:
            logging.warning("Недостаточно директорий для сравнения (необходимо минимум 2)")
            return False

        dir_names = list(self.directory_files_data.keys())
        logging.info("=" * 42)
        logging.info("СРАВНЕНИЕ АДРЕСОВ МЕЖДУ МАРШРУТНЫМИ ЛИСТАМИ")
        logging.info("=" * 42)
        logging.info(f"Всего загружено директорий с файлами: {len(dir_names)}")

        for idx, dir_path in enumerate(dir_names, 1):
            files_count = len(self.directory_files_data[dir_path])
            clean_path = str(Path(dir_path))
            logging.info(f"  {idx}. {clean_path} ({files_count} файлов)")
        logging.info("")

        ip_index: Dict[str, List[tuple]] = {}

        for dir_path, files_dict in self.directory_files_data.items():
            for file_path, ip_set in files_dict.items():
                for ip_obj in ip_set:
                    ip_str = str(ip_obj)
                    if ip_str not in ip_index:
                        ip_index[ip_str] = []
                    ip_index[ip_str].append((dir_path, file_path))

        cross_dir_ips = {}
        for ip_str, entries in ip_index.items():
            unique_dirs = set(dir_path for dir_path, _ in entries)
            if len(unique_dirs) > 1:
                cross_dir_ips[ip_str] = entries

        if cross_dir_ips:
            logging.info(f"------ ПЕРЕСЕЧЕНИЯ АДРЕСОВ ОБНАРУЖЕНЫ ------")
            logging.info(f"{len(cross_dir_ips)} адресов, встречающихся в разных листах:")

            dir_stats = {}

            for ip_str, entries in sorted(cross_dir_ips.items()):
                logging.info(f"  {ip_str}:")
                dir_groups = {}
                for dir_path, file_path in entries:
                    if dir_path not in dir_groups:
                        dir_groups[dir_path] = []
                    dir_groups[dir_path].append(file_path)

                for dir_path, files in dir_groups.items():
                    clean_path = str(Path(dir_path))
                    logging.info(f"    - {clean_path} ({len(files)} файлов):")
                    for file_path in files:
                        logging.info(f"        * {Path(file_path).name}")

                    if dir_path not in dir_stats:
                        dir_stats[dir_path] = set()
                    dir_stats[dir_path].add(ip_str)

            logging.info("\n" + "=" * 80)
            logging.info("СТАТИСТИКА ПО ДИРЕКТОРИЯМ С ТОЧНЫМИ СОВПАДЕНИЯМИ:")
            logging.info(f"  Всего директорий с пересечениями: {len(dir_stats)}")

            if dir_stats:
                for dir_path, ips in sorted(dir_stats.items(), key=lambda x: len(x[1]), reverse=True):
                    clean_path = str(Path(dir_path))
                    logging.info(f"  {clean_path}: {len(ips)} пересечений")
            else:
                logging.info("  Нет директорий с пересечениями")
        else:
            logging.info("------ Пересечений адресов между листами не обнаружено ------")

        if MEMBERSHIP_CHECK:
            self.check_membership_across_directories()

        return bool(cross_dir_ips)

    def _separate_ips_by_version(self, ip_set: Set) -> Tuple[Set, Set]:
        """Разделение IP-адресов на IPv4 и IPv6."""
        ipv4_set = set()
        ipv6_set = set()

        for ip in ip_set:
            if isinstance(ip, ipaddress.IPv4Address):
                ipv4_set.add(ip)
            else:
                ipv6_set.add(ip)

        return ipv4_set, ipv6_set

    def _separate_networks_by_version(self, network_set: Set) -> Tuple[Set, Set]:
        """Разделение сетей на IPv4 и IPv6."""
        ipv4_networks = set()
        ipv6_networks = set()

        for network in network_set:
            if isinstance(network, ipaddress.IPv4Network):
                ipv4_networks.add(network)
            else:
                ipv6_networks.add(network)

        return ipv4_networks, ipv6_networks

    def _binary_search_network(self, sorted_networks: List, ip_obj) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """Бинарный поиск сети, содержащей IP-адрес."""
        int_ip = int(ip_obj)
        left, right = 0, len(sorted_networks) - 1

        while left <= right:
            mid = (left + right) // 2
            network = sorted_networks[mid]

            if ip_obj in network:
                return network
            elif int_ip < int(network.network_address):
                right = mid - 1
            else:
                left = mid + 1

        return None

    def _check_membership_optimized(self, ips: Set, networks: Set) -> Dict[str, Set]:
        """
        Проверка вхождения IP в сети.
        Использует сортировку и бинарный поиск.
        """
        if not ips or not networks:
            return {}

        ipv4_ips, ipv6_ips = self._separate_ips_by_version(ips)
        ipv4_networks, ipv6_networks = self._separate_networks_by_version(networks)

        result = {}

        if ipv4_ips and ipv4_networks:
            sorted_ipv4_networks = sorted(ipv4_networks, key=lambda x: int(x.network_address))

            for ip in ipv4_ips:
                network = self._binary_search_network(sorted_ipv4_networks, ip)
                if network:
                    ip_str = str(ip)
                    if ip_str not in result:
                        result[ip_str] = set()
                    result[ip_str].add(network)

        if ipv6_ips and ipv6_networks:
            sorted_ipv6_networks = sorted(ipv6_networks, key=lambda x: int(x.network_address))

            for ip in ipv6_ips:
                network = self._binary_search_network(sorted_ipv6_networks, ip)
                if network:
                    ip_str = str(ip)
                    if ip_str not in result:
                        result[ip_str] = set()
                    result[ip_str].add(network)

        return result

    def check_membership_across_directories(self):
        """Проверка вхождения IP-адресов в подсети между разными директориями."""
        if len(self.directory_networks_data) < 2:
            logging.warning("Недостаточно директорий для проверки вхождения в подсети")
            return

        logging.info("\n" + "=" * 42)
        logging.info("ПРОВЕРКА ВХОЖДЕНИЯ IP В ПОДСЕТИ МЕЖДУ ДИРЕКТОРИЯМИ")
        logging.info("=" * 42)

        dir_names = list(self.directory_networks_data.keys())

        dir_networks: Dict[str, Dict[str, Set[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]]] = {}
        dir_ips: Dict[str, Dict[str, Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]]] = {}

        for dir_path in dir_names:
            dir_networks[dir_path] = {}
            dir_ips[dir_path] = {}

            for file_path, network_set in self.directory_networks_data[dir_path].items():
                dir_networks[dir_path][file_path] = network_set

            for file_path, ip_set in self.directory_files_data[dir_path].items():
                dir_ips[dir_path][file_path] = ip_set

        membership_found = False
        membership_stats = {}

        for dir1 in dir_names:
            for dir2 in dir_names:
                if dir1 == dir2:
                    continue

                all_networks_dir2 = set()
                for file2, networks in dir_networks[dir2].items():
                    all_networks_dir2.update(networks)

                for file1, ips in dir_ips[dir1].items():
                    membership_result = self._check_membership_optimized(ips, all_networks_dir2)

                    for ip_str, networks in membership_result.items():
                        if not membership_found:
                            membership_found = True
                            logging.info("------ ОБНАРУЖЕНЫ ВХОЖДЕНИЯ IP В ПОДСЕТИ ------")

                        clean_dir1 = str(Path(dir1))
                        clean_dir2 = str(Path(dir2))
                        file1_name = Path(file1).name

                        for network in networks:
                            network_str = str(network)
                            file2_found = None
                            for file2, networks_set in dir_networks[dir2].items():
                                for net in networks_set:
                                    if str(net) == network_str:
                                        file2_found = Path(file2).name
                                        break
                                if file2_found:
                                    break

                            if not file2_found:
                                file2_found = "unknown"

                            logging.info(f"  {ip_str} (из {clean_dir1}/{file1_name}) входит в подсеть {network_str} (из {clean_dir2}/{file2_found})")

                            if clean_dir1 not in membership_stats:
                                membership_stats[clean_dir1] = set()
                            membership_stats[clean_dir1].add(ip_str)

        if not membership_found:
            logging.info("------ ВХОЖДЕНИЙ IP В ПОДСЕТИ НЕ ОБНАРУЖЕНО ------")
        else:
            logging.info("\n" + "=" * 80)
            logging.info("СТАТИСТИКА ПО ВХОЖДЕНИЯМ IP В ПОДСЕТИ:")

            if membership_stats:
                for dir_path, ips in sorted(membership_stats.items(), key=lambda x: len(x[1]), reverse=True):
                    logging.info(f"  {dir_path}: {len(ips)} IP-адресов входят в подсети других листов")
            else:
                logging.info("  Нет вхождений IP в подсети")

    def compare_files_debug(self):
        """Сравнение файлов и поиск точных совпадений IP-адресов (DEBUG режим)"""
        if len(self.files_data) < 2:
            logging.debug("Недостаточно файлов для сравнения (необходимо минимум 2)")
            return

        file_paths = list(self.files_data.keys())
        all_intersections = {}

        logging.debug("=" * 60)
        logging.debug("СРАВНЕНИЕ АДРЕСОВ В ПРЕДЕЛАХ МАРШРУТНОГО ЛИСТА(DEBUG РЕЖИМ)")
        logging.debug("=" * 60)
        logging.debug(f"Всего файлов для сравнения: {len(file_paths)}")

        ip_index: Dict[str, List[str]] = {}
        for file_path, ip_set in self.files_data.items():
            for ip_obj in ip_set:
                ip_str = str(ip_obj)
                if ip_str not in ip_index:
                    ip_index[ip_str] = []
                ip_index[ip_str].append(file_path)

        duplicate_ips = {ip: files for ip, files in ip_index.items() if len(files) > 1}

        if duplicate_ips:
            logging.debug(f"Обнаружено {len(duplicate_ips)} адресов, встречающихся в нескольких файлах:")
            for ip_str, files_list in sorted(duplicate_ips.items()):
                logging.debug(f"  {ip_str} -> {len(files_list)} файлов:")
                for file_path in files_list:
                    logging.debug(f"    - {file_path}")
                all_intersections[ip_str] = files_list
        else:
            logging.debug("------ Пересечений адресов в пределах листа не найдено ------")

        logging.debug("=" * 80)

    def run(self):
        """Запуск процесса сравнения"""
        start_time = time.time()

        script_name = Path(__file__).stem

        logging.info("=" * 61)
        logging.info(f"Запуск {script_name} - сравнение адресов маршрутных листов")
        logging.info("=" * 61)
        logging.info("------------ ПАРАМЕТРЫ ЗАПУСКА ------------")
        logging.info(f"Версии IP: IPv4 и IPv6")
        logging.info(f"Проверка вхождения в подсети: {MEMBERSHIP_CHECK}")
        logging.info(f"Многопоточное чтение: {'ВКЛЮЧЕНО' if self.use_threading else 'ОТКЛЮЧЕНО'}")
        if self.use_threading:
            logging.info(f"Количество потоков: {self.thread_pool_size}")
        logging.info(f"Всего директорий указано: {len(self.directories_paths)}")
        for idx, path in enumerate(self.directories_paths, 1):
            clean_path = str(Path(path))
            logging.info(f"  {idx}. {clean_path}")
        logging.info("=" * 43)

        if self.load_files():
            logging.info("=" * 43)
            has_intersections = self.compare_across_directories()
            self.compare_files_debug()
        else:
            logging.error("Не удалось загрузить файлы для сравнения")

        elapsed_time = time.time() - start_time
        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)

        logging.info("=" * 23)
        logging.info(f"ВРЕМЯ ВЫПОЛНЕНИЯ: {minutes} мин {seconds} сек")
        logging.info("=" * 23)
        logging.info("СКРИПТ УСПЕШНО ИСПОЛНЕН")
        logging.info("=" * 23)


def main():
    """Главная функция"""
    if not DIRECTORIES_PATHS or len(DIRECTORIES_PATHS) < 2:
        logging.error("Требуется минимум 2 директории для сравнения.")
        return

    comparator = IPComparator(DIRECTORIES_PATHS, True, True)
    comparator.run()


if __name__ == "__main__":
    main()
  
