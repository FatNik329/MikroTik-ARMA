#!/usr/bin/env python3
"""
Скрипт для конвертации YAML файлов с IP адресами в текстовые файлы
Извлекает IPv4 адреса из разделов 'historical' файлов results-dns.yaml и сохраняет их в TXT файлы
"""

import yaml
import sys
import logging
from pathlib import Path
from typing import Dict, List, Set
import time
import signal


# ============================================================================
# КОНФИГУРАЦИЯ СКРИПТА
# ============================================================================
CONFIG = {
    # ПУТИ К YAML ФАЙЛАМ (УКАЗАТЬ СВОИ ПУТИ)
    "YAML_PATHS": [
        Path("raw-data/listExample1/DNS/results-dns.yaml"),
        Path("raw-data/listExample2/DNS/results-dns.yaml"),
    ],

    # Директория для логов
    "LOG_DIR": Path("logs/additional/yaml_to_txt/"),

    # Директория для выходных TXT файлов
    "OUTPUT_DIR": Path("raw-data/NewlistExample"),

    # Маска для поиска YAML файлов
    "YAML_PATTERN": "*.yaml",

    # Кодировка файлов
    "ENCODING": "utf-8",

    # Рекурсивный поиск в поддиректориях
    "RECURSIVE_SEARCH": False,
}


# ============================================================================
# НАСТРОЙКА ЛОГИРОВАНИЯ
# ============================================================================
# Автоматическое определение имени лог файла
script_name = Path(__file__).stem
log_filename = f"{script_name}.log"

# Создание директории для логов
log_path = CONFIG["LOG_DIR"] / log_filename
log_path.parent.mkdir(parents=True, exist_ok=True)

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_path, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


# ============================================================================
# ОСНОВНАЯ ЛОГИКА
# ============================================================================
class YAMLToTXTConverter:
    """Класс для конвертации YAML файлов в TXT"""

    def __init__(self, logger):
        self.logger = logger
        self.stats = {
            "files_processed": 0,
            "ips_extracted": 0,
            "errors": 0,
            "yaml_paths_processed": 0
        }
        self._stop_requested = False

    def request_stop(self):
        """Запросить остановку обработки"""
        self._stop_requested = True
        self.logger.info("Получен запрос на остановку...")

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
                self.logger.warning(f"В файле отсутствует раздел 'categories'")
                return ipv4_addresses

            category_data = categories.get(category)
            if not category_data:
                self.logger.warning(f"Категория '{category}' не найдена в файле")
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
            self.logger.error(f"Ошибка при извлечении IPv4: {e}")

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
            self.logger.error(f"Ошибка при поиске категорий: {e}")

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
            with open(yaml_path, 'r', encoding=CONFIG["ENCODING"]) as file:
                data = yaml.safe_load(file)

            if not data:
                self.logger.warning(f"Файл {yaml_path} пуст или некорректен")
                return result

            # Находим все категории
            categories = self.find_all_categories(data)

            if not categories:
                self.logger.warning(f"В файле {yaml_path} не найдены категории")
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
                    self.logger.debug(f"Категория '{category}': IP-адреса не найдены")

            self.stats["files_processed"] += 1

        except yaml.YAMLError as e:
            self.logger.error(f"Ошибка разбора YAML файла {yaml_path}: {e}")
            self.stats["errors"] += 1
        except Exception as e:
            self.logger.error(f"Ошибка при обработке файла {yaml_path}: {e}")
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

        # Создать безопасное имя файла
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

            with open(txt_path, 'w', encoding=CONFIG["ENCODING"]) as file:
                for ip in sorted_ips:
                    file.write(f"{ip}\n")

            self.logger.info(f"Сохранено {len(sorted_ips)} IP в файл: {txt_path}")

        except Exception as e:
            self.logger.error(f"Ошибка при сохранении файла {txt_path}: {e}")
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
                if CONFIG["RECURSIVE_SEARCH"]:
                    yaml_files = list(yaml_path.rglob(CONFIG["YAML_PATTERN"]))
                else:
                    yaml_files = list(yaml_path.glob(CONFIG["YAML_PATTERN"]))
        except Exception as e:
            self.logger.error(f"Ошибка при поиске файлов в {yaml_path}: {e}")

        return yaml_files

    def process_yaml_path(self, yaml_path: Path) -> Dict[str, Set[str]]:
        """
        Обрабатывает один путь из CONFIG["YAML_PATHS"]
        Args:
            yaml_path: Путь к директории или файлу YAML
        Returns:
            Объединенные результаты по всем файлам в пути
        """
        if self._stop_requested:
            return {}

        self.logger.info(f"Обработка пути: {yaml_path}")

        all_results = {}

        # Проверка существования пути
        if not yaml_path.exists():
            self.logger.error(f"Путь не существует: {yaml_path}")
            return all_results

        # Поиск всех YAML файлов
        yaml_files = self.find_yaml_files(yaml_path)

        if not yaml_files:
            self.logger.warning(f"YAML файлы не найдены в {yaml_path}")
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


def signal_handler(signum, frame):
    """Обработчик сигналов для корректного завершения"""
    logger = logging.getLogger(__name__)
    logger.info(f"Получен сигнал {signum}, завершение работы...")

    if 'converter' in globals():
        globals()['converter'].request_stop()


def main():
    """Основная функция скрипта"""
    global converter

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Настройка логирования
    logger.info("=" * 60)
    logging.info("Запуск скрипта %s - конвертация YAML в TXT", script_name)
    logger.info("=" * 60)

    # Вывод настроек
    logger.info("НАСТРОЙКИ СКРИПТА:")
    logger.info(f"Количество путей YAML: {len(CONFIG['YAML_PATHS'])}")
    for i, path in enumerate(CONFIG['YAML_PATHS'], 1):
        logger.info(f"  {i}. {path}")
    logger.info(f"Выходная директория: {CONFIG['OUTPUT_DIR']}")
    logger.info(f"Рекурсивный поиск: {'Да' if CONFIG['RECURSIVE_SEARCH'] else 'Нет'}")
    logger.info(f"Директория логов: {CONFIG['LOG_DIR']}")
    logger.info("=" * 60)

    # Проверка путей
    valid_paths = []
    for yaml_path in CONFIG["YAML_PATHS"]:
        if not yaml_path.exists():
            logger.error(f"Путь не существует и будет пропущен: {yaml_path}")
        else:
            valid_paths.append(yaml_path)

    if not valid_paths:
        logger.error("Нет валидных путей для обработки. Проверьте CONFIG['YAML_PATHS']")
        sys.exit(1)

    converter = YAMLToTXTConverter(logger)
    all_results = {}

    try:
        start_time = time.time()

        # Обрабатываем каждый путь
        for yaml_path in valid_paths:
            if converter._stop_requested:
                break

            logger.info(f"Обработка пути {yaml_path} ({valid_paths.index(yaml_path) + 1}/{len(valid_paths)})")

            path_results = converter.process_yaml_path(yaml_path)

            # Объединяем результаты всех путей
            for category, ips in path_results.items():
                if category in all_results:
                    all_results[category].update(ips)
                else:
                    all_results[category] = ips

        if not all_results:
            logger.warning("Не найдено IP адресов для обработки")
        else:
            # Сохраняем результаты
            logger.info(f"Сохранение результатов в директорию: {CONFIG['OUTPUT_DIR']}")
            for category, ips in all_results.items():
                converter.save_to_txt(category, ips, CONFIG["OUTPUT_DIR"])

        # Выводим статистику
        execution_time = time.time() - start_time
        logger.info("=" * 60)
        logger.info("СТАТИСТИКА ОБРАБОТКИ:")
        logger.info(f"Обработано путей: {converter.stats['yaml_paths_processed']}/{len(valid_paths)}")
        logger.info(f"Обработано файлов: {converter.stats['files_processed']}")
        logger.info(f"Извлечено IP адресов: {converter.stats['ips_extracted']}")
        logger.info(f"Создано TXT файлов: {len(all_results)}")
        logger.info(f"Ошибок: {converter.stats['errors']}")
        logger.info(f"Время выполнения: {execution_time:.2f} секунд")
        logger.info("=" * 60)

        if converter._stop_requested:
            logger.warning("Обработка была прервана")
        else:
            logger.info("Обработка завершена успешно!")

    except KeyboardInterrupt:
        logger.info("Обработка прервана пользователем (Ctrl+C)")
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
