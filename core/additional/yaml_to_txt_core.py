"""
Ядро функционала для скриптов yaml_to_txt-*
Содержит всю общую логику для конвертации YAML файлов с IP адресами (IPv4) в текстовые файлы (TXT)
"""
import yaml
import sys
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any
import time
import signal

class YAMLToTXTConverter:
    """Класс для конвертации YAML файлов в TXT"""

    def __init__(self, config, script_name=None, logger=None):
        """
        Args:
            config: Словарь с конфигурацией
            script_name: Имя скрипта (опционально)
            logger: Объект логгера (опционально)
        """
        self.config = config
        self.script_name = script_name
        self.logger = logger if logger is not None else logging.getLogger(__name__)
        self.stats = {
            "files_processed": 0,
            "ips_extracted": 0,
            "errors": 0,
            "yaml_paths_processed": 0
        }
        self._stop_requested = False

    def run(self) -> bool:
        """
        Основной метод запуска обработки
        Returns:
            True если обработка завершена успешно, False в случае ошибки
        """
        try:
            # Обработка сигналов
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)

            start_time = time.time()
            all_results = {}

            # Проверка и подготовка путей YAML
            yaml_paths = self.config.get("yaml_paths", [])
            if not yaml_paths:
                self.logger.error("Не указаны пути YAML в конфигурации")
                return False

            # Конвертация строковых путей в объекты Path
            path_objects = []
            for path in yaml_paths:
                if isinstance(path, str):
                    path_objects.append(Path(path))
                else:
                    path_objects.append(path)

            valid_paths = []
            for yaml_path in path_objects:
                if not yaml_path.exists():
                    self.logger.error(f"Путь не существует и будет пропущен: {yaml_path}")
                else:
                    valid_paths.append(yaml_path)

            if not valid_paths:
                self.logger.error("Нет валидных путей для обработки")
                return False

            # Вывод настроек
            self.logger.info("=" * 60)
            self.logger.info("НАСТРОЙКИ СКРИПТА:")
            if self.script_name:
                self.logger.info(f"Имя скрипта: {self.script_name}")
            self.logger.info(f"Количество путей YAML: {len(valid_paths)}")
            for i, path in enumerate(valid_paths, 1):
                self.logger.info(f"  {i}. {path}")

            output_dir = self.config.get("output_dir")
            if output_dir:
                output_dir = Path(output_dir) if isinstance(output_dir, str) else output_dir
                self.logger.info(f"Выходная директория: {output_dir}")
            self.logger.info(f"Рекурсивный поиск: {'Да' if self.config.get('recursive_search', False) else 'Нет'}")
            self.logger.info("=" * 60)

            # Обработка каждого пути
            for yaml_path in valid_paths:
                if self._stop_requested:
                    break

                self.logger.info(f"Обработка пути {yaml_path} ({valid_paths.index(yaml_path) + 1}/{len(valid_paths)})")
                path_results = self.process_yaml_path(yaml_path)

                for category, ips in path_results.items():
                    if category in all_results:
                        all_results[category].update(ips)
                    else:
                        all_results[category] = ips

            # Сохранение результатов
            if all_results:
                if output_dir:
                    self.logger.info(f"Сохранение результатов в директорию: {output_dir}")
                    for category, ips in all_results.items():
                        self.save_to_txt(category, ips, output_dir)
                else:
                    self.logger.error("Не указана выходная директория в конфигурации")
                    return False
            else:
                self.logger.warning("Не найдено IP адресов для обработки")

            # Вывод статистики
            execution_time = time.time() - start_time
            # Выводим статистику
            execution_time = time.time() - start_time
            self.logger.info("=" * 60)
            self.logger.info("СТАТИСТИКА ОБРАБОТКИ:")
            self.logger.info(f"Обработано путей: {self.stats['yaml_paths_processed']}/{len(valid_paths)}")
            self.logger.info(f"Обработано файлов: {self.stats['files_processed']}")
            self.logger.info(f"Извлечено IP адресов: {self.stats['ips_extracted']}")
            self.logger.info(f"Создано TXT файлов: {len(all_results)}")
            self.logger.info(f"Ошибок: {self.stats['errors']}")
            self.logger.info(f"Время выполнения: {execution_time:.2f} секунд")
            self.logger.info("=" * 60)

            if self._stop_requested:
                self.logger.warning("Обработка была прервана")
                return False
            else:
                self.logger.info("Обработка завершена успешно!")
                return True

        except KeyboardInterrupt:
            self.logger.info("Обработка прервана пользователем")
            return False
        except Exception as e:
            self.logger.error(f"Критическая ошибка: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False

    def request_stop(self):
        """Запросить остановку обработки"""
        self._stop_requested = True
        self.logger.info("Получен запрос на остановку...")

    def _signal_handler(self, signum, frame):
        """Обработчик сигналов для корректного завершения"""
        self.logger.info(f"Получен сигнал {signum}, запрос на остановку...")
        self.request_stop()

    def extract_ipv4_from_historical(self, data: Dict, category: str) -> Set[str]:
        """
        Извлекает IPv4 адреса из раздела 'historical'
        Args:
            data: Загруженные данные YAML
            category: Название категории
        Returns:
            Множество IPv4 адресов
        """
        ipv4_addresses = set()

        try:
            categories = data.get("categories", {})
            if not categories:
                self.logger.info(f"В файле отсутствует раздел 'categories'")
                return ipv4_addresses

            category_data = categories.get(category)
            if not category_data:
                self.logger.info(f"Категория '{category}' не найдена в файле")
                return ipv4_addresses

            for hostname, host_data in category_data.items():
                if self._stop_requested:
                    return ipv4_addresses

                if not isinstance(host_data, dict):
                    continue

                # Провка раздела ipv4
                ipv4_data = host_data.get("ipv4")
                if not ipv4_data or not isinstance(ipv4_data, dict):
                    continue

                # Извлечение адреса из historical
                historical_data = ipv4_data.get("historical")
                if not historical_data or not isinstance(historical_data, dict):
                    continue

                # Сбор всех IPv4 адреса
                for ip_address in historical_data.keys():
                    if isinstance(ip_address, str):
                        ipv4_addresses.add(ip_address.strip())

        except Exception as e:
            self.logger.info(f"Ошибка при извлечении IPv4: {e}")

        return ipv4_addresses

    def find_all_categories(self, data: Dict) -> List[str]:
        """
        Находит все категории в YAML файле
        Args:
            data: Загруженные данные YAML
        Returns:
            Список названий категорий
        """
        categories = []

        try:
            categories_data = data.get("categories", {})
            if categories_data and isinstance(categories_data, dict):
                categories = list(categories_data.keys())

        except Exception as e:
            self.logger.info(f"Ошибка при поиске категорий: {e}")

        return categories

    def process_yaml_file(self, yaml_path: Path) -> Dict[str, Set[str]]:
        """
        Обрабатывает один YAML файл
        Args:
            yaml_path: Путь к YAML файлу
        Returns:
            Словарь {категория: множество_IP_адресов}
        """
        if self._stop_requested:
            return {}

        self.logger.info(f"Обработка файла: {yaml_path}")

        result = {}

        try:
            with open(yaml_path, 'r', encoding=self.config["encoding"]) as file:
                data = yaml.safe_load(file)

            if not data:
                self.logger.info(f"Файл {yaml_path} пуст или некорректен")
                return result

            # Находим все категории
            categories = self.find_all_categories(data)

            if not categories:
                self.logger.info(f"В файле {yaml_path} не найдены категории")
                return result

            # Извлечение IP из каждой категории
            for category in categories:
                if self._stop_requested:
                    break

                ip_addresses = self.extract_ipv4_from_historical(data, category)

                if ip_addresses:
                    result[category] = ip_addresses
                    self.logger.info(f"Категория '{category}': найдено {len(ip_addresses)} IP-адресов")
                    self.stats["ips_extracted"] += len(ip_addresses)
                else:
                    self.logger.info(f"Категория '{category}': IP-адреса не найдены")

            self.stats["files_processed"] += 1

        except yaml.YAMLError as e:
            self.logger.info(f"Ошибка разбора YAML файла {yaml_path}: {e}")
            self.stats["errors"] += 1
        except Exception as e:
            self.logger.info(f"Ошибка при обработке файла {yaml_path}: {e}")
            self.stats["errors"] += 1

        return result

    def save_to_txt(self, category: str, ip_addresses: Set[str], output_dir: Path):
        """
        Сохраняет IP адреса в TXT файл

        Args:
            category: Название категории (имя файла)
            ip_addresses: Множество IP адресов
            output_dir: Директория для сохранения
        """
        if not ip_addresses or self._stop_requested:
            return

        safe_category_name = "".join(c for c in category if c.isalnum() or c in (' ', '-', '_')).rstrip()
        if not safe_category_name:
            safe_category_name = "unknown_category"

        txt_filename = f"{safe_category_name}.txt"
        txt_path = output_dir / txt_filename

        try:
            # Создать директорию если не существует
            txt_path.parent.mkdir(parents=True, exist_ok=True)

            # Сохранить IP адреса
            sorted_ips = sorted(ip_addresses)

            with open(txt_path, 'w', encoding=self.config["encoding"]) as file:
                for ip in sorted_ips:
                    file.write(f"{ip}\n")

            self.logger.info(f"Сохранено {len(sorted_ips)} IP в файл: {txt_path}")

        except Exception as e:
            self.logger.info(f"Ошибка при сохранении файла {txt_path}: {e}")
            self.stats["errors"] += 1

    def find_yaml_files(self, yaml_path: Path) -> List[Path]:
        """
        Находит все YAML файлы в указанном пути
        Args:
            yaml_path: Путь для поиска
        Returns:
            Список путей к YAML файлам
        """
        yaml_files = []

        try:
            if yaml_path.is_file() and yaml_path.suffix.lower() in ['.yaml', '.yml']:
                yaml_files.append(yaml_path)
            elif yaml_path.is_dir():
                if self.config["RECURSIVE_SEARCH"]:
                    yaml_files = list(yaml_path.rglob(self.config["YAML_PATTERN"]))
                else:
                    yaml_files = list(yaml_path.glob(self.config["YAML_PATTERN"]))
        except Exception as e:
            self.logger.info(f"Ошибка при поиске файлов в {yaml_path}: {e}")

        return yaml_files

    def process_yaml_path(self, yaml_path: Path) -> Dict[str, Set[str]]:
        """
        Обрабатывает один путь из self.config["YAML_PATHS"]
        Args:
            yaml_path: Путь к директории или файлу YAML
        Returns:
            Объединенные результаты по всем файлам в пути
        """
        if self._stop_requested:
            return {}

        all_results = {}

        # Проверка существования пути
        if not yaml_path.exists():
            self.logger.info(f"Путь не существует: {yaml_path}")
            return all_results

        # Поиск всех YAML файлов
        yaml_files = self.find_yaml_files(yaml_path)

        if not yaml_files:
            self.logger.info(f"YAML файлы не найдены в {yaml_path}")
            return all_results

        self.logger.info(f"Найдено {len(yaml_files)} YAML файлов в {yaml_path}")

        # Обработка каждого файла
        for yaml_file in yaml_files:
            if self._stop_requested:
                break

            if yaml_file.is_file():
                file_results = self.process_yaml_file(yaml_file)

                # Объединение результатов
                for category, ips in file_results.items():
                    if category in all_results:
                        all_results[category].update(ips)
                    else:
                        all_results[category] = ips

        self.stats["yaml_paths_processed"] += 1

        return all_results

if __name__ == "__main__":
    main()
