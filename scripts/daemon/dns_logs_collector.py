#!/usr/bin/env python3
"""
Скрипт-демон DNS Logs Collector
Собирает логи DNS сервисов из named pipe и сохраняет в JSONL с ротацией по времени
"""

import sys
import os
import json
import time
import re
import signal
import logging
import logging.handlers
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Callable
from enum import Enum
import threading
from queue import Queue, Empty
import argparse
import importlib.util
from importlib import import_module

# Добавляет путь к корневой директории проекта
current_file = Path(__file__).resolve()
project_root = current_file.parent.parent.parent
sys.path.insert(0, str(project_root))

from core.maintenance.monitoring import MonitoringCore, BaseHealthCheckHandler

# Конфигурация по умолчанию
DEFAULT_CONFIG = {
    # Входные данные
    "input": {
        "pipe_path": "/tmp/example_dns_queries",  # файл или директория с .pipe файлами
    },

    # Выходные данные
    "output": {
        "directory": "/path/to/storage/dns_logs_jsonl",      # Путь сохранения выходных данных
        "filename_pattern": "dns_queries_%Y-%m-%d.jsonl",    # Паттерн сохраняемых данных
        "retention_days": 14,                                # удалять файлы старше N дней
    },

    # Обработка данных
    "processing": {
        "flush_interval_sec": 20,  # интервал принудительной записи
        "batch_size": 200,         # размер данных для одной операции записи
    },


    # Плагины для обработки логов сервисов
    "plugins": {
        "directory": "core/plugins/dns_collect",     # путь к директории с плагинами
        "enabled_plugins": ["dnscrypt", "dnsmasq"],  # список включенных плагинов ("" - использует все плагины)
        "plugin_suffix": "_logs.py",                 # суффикс плагинов
    },

    # Параметры мониторинга
    "monitoring": {
        "stats_interval_sec": 600,  # Интервал вывода статистики в секундах
        "listen_port": 55145,       # Порт для health check сервера (0 - отключить)
    },

    # Логирование демона
    "logging": {
        "level": "INFO",   # Уровень логирования
        "file": "logs/daemon/dns_logs_collector/dns_logs_collector.log", # Путь логов исполнения
        "max_size_mb": 10, # Максимальный размер логов
        "backup_count": 2, # Количество архивов логов
    }
}

class PluginManager:
    """Менеджер плагинов обработки логов"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.plugins = {}
        self.load_plugins()

    def load_plugins(self):
        """Загрузка всех плагинов"""
        plugins_dir = Path(self.config['plugins']['directory'])
        plugin_suffix = self.config['plugins']['plugin_suffix']
        enabled_plugins = self.config['plugins']['enabled_plugins']

        if not plugins_dir.exists():
            logging.warning(f"Директория плагинов не найдена: {plugins_dir}")
            return

        # Путь к директории плагинов в sys.path
        if str(plugins_dir) not in sys.path:
            sys.path.insert(0, str(plugins_dir))

        # Поиск плагинов
        plugin_files = list(plugins_dir.glob(f"*{plugin_suffix}"))

        # Сисок доступных плагинов для проверки
        available_plugins = []
        for plugin_file in plugin_files:
            plugin_name = plugin_file.stem.replace('_logs', '')
            available_plugins.append(plugin_name)

        # Проверка запрошенных плагинов
        if enabled_plugins:
            missing_plugins = []
            for plugin_name in enabled_plugins:
                if plugin_name not in available_plugins:
                    missing_plugins.append(plugin_name)

            if missing_plugins:
                logging.warning(f"Плагины не найдены: {', '.join(missing_plugins)}")
                logging.warning(f"Доступные плагины: {', '.join(available_plugins)}")

        # Загрузка плагинов
        loaded_count = 0
        for plugin_file in plugin_files:
            plugin_name = plugin_file.stem.replace('_logs', '')

            # Проверка на включение плагина
            if enabled_plugins and plugin_name not in enabled_plugins:
                continue

            try:
                # Динамический импорт плагина
                module_name = plugin_file.stem
                spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                module = importlib.util.module_from_spec(spec)

                # Загружает модуль в sys.modules
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                # Поиск класса плагина
                plugin_class = None
                for attr_name in dir(module):
                    if (attr_name.endswith('Plugin') and
                        not attr_name.startswith('__') and
                        attr_name != 'DNSPluginBase'):
                        attr = getattr(module, attr_name)
                        if isinstance(attr, type):
                            try:
                                # Импортирует базовый класс
                                from dns_plugin_base import DNSPluginBase as BaseClass
                                if issubclass(attr, BaseClass) and attr != BaseClass:
                                    plugin_class = attr
                                    break
                            except ImportError:
                                # Если не удалось импортировать базовый класс, ищет классы с методом parse_line
                                if hasattr(attr, 'parse_line') and callable(getattr(attr, 'parse_line')):
                                    plugin_class = attr
                                    break

                if plugin_class:
                    plugin_instance = plugin_class()
                    self.plugins[plugin_name] = plugin_instance

                    # Получает имя сервиса из плагина
                    service_name = getattr(plugin_instance, 'SERVICE_NAME',
                                          getattr(plugin_instance, 'service_name', plugin_name))

                    logging.info(f"Загружен плагин: {plugin_name} ({service_name})")
                    loaded_count += 1
                else:
                    logging.warning(f"Не найден класс плагина в {plugin_file}")

            except Exception as e:
                logging.error(f"Ошибка загрузки плагина {plugin_file}: {e}")
                import traceback
                logging.debug(traceback.format_exc())

        logging.info(f"Загружено плагинов: {loaded_count}/{len(enabled_plugins) if enabled_plugins else 'все доступные'}")

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Пробует распарсить строку доступными плагинами"""
        if not line.strip():
            return None

        for plugin_name, plugin in self.plugins.items():
            try:
                record = plugin.parse_line(line)
                if record:
                    # Информация о плагине
                    record['_plugin'] = plugin_name

                    # Имя сервиса из плагина
                    service_name = getattr(plugin, 'SERVICE_NAME',
                                          getattr(plugin, 'service_name', plugin_name))

                    if 'service' not in record:
                        record['service'] = service_name
                    return record
            except Exception as e:
                logging.debug(f"Плагин {plugin_name} не смог распарсить строку: {e}")

        return None

    def get_plugins_info(self) -> Dict[str, Any]:
        """Получить информацию о всех плагинах"""
        info = {}
        for plugin_name, plugin in self.plugins.items():
            if hasattr(plugin, 'get_info'):
                info[plugin_name] = plugin.get_info()
            else:
                service_name = getattr(plugin, 'SERVICE_NAME',
                                      getattr(plugin, 'service_name', plugin_name))

                info[plugin_name] = {
                    "service": service_name,
                    "supported_formats": getattr(plugin, 'supported_formats', []),
                    "description": f"Плагин обработки логов {service_name}"
                }
        return info

class LogParser:
    """Универсальный парсер логов с поддержкой плагинов"""

    def __init__(self, config: Dict[str, Any]):
        self.plugin_manager = PluginManager(config)

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Парсинг строки с использованием плагинов"""
        return self.plugin_manager.parse_line(line)

    def get_plugins_info(self) -> Dict[str, Any]:
        """Получить информацию о плагинах"""
        return self.plugin_manager.get_plugins_info()

class PipeReader:
    """Читатель named pipe"""

    def __init__(self, pipe_path: str, watch_directory: bool = False):
        self.pipe_path = Path(pipe_path)
        self.watch_directory = watch_directory
        self.pipes = {}
        self.running = False
        self.threads = []

    def get_pipe_files(self) -> List[Path]:
        """Получить список pipe файлов для чтения"""
        path = Path(self.pipe_path)

        if path.is_dir():
            # Поиск .pipe файлов
            pipe_files = list(path.glob("*.pipe"))
            if pipe_files:
                logging.info(f"Найдено {len(pipe_files)} .pipe файлов в директории {path}")
            else:
                logging.warning(f"Не найдено .pipe файлов в директории {path}")
            return pipe_files
        elif path.exists():
            if path.suffix == '.pipe' or '.pipe' in path.name:
                return [path]
            else:
                logging.warning(f"Файл {path} не имеет расширения .pipe")
                return [path]
        else:
            logging.warning(f"Не найден pipe файл или директория: {path}")
            return []

    def read_pipe(self, pipe_path: Path, queue: Queue):
        """Чтение данных из pipe и помещать в очередь"""
        logging.info(f"Запуск чтения из pipe: {pipe_path}")
        time.sleep(1)

        max_retries = 5
        retry_delay = 2
        first_open = True
        pipe = None

        for attempt in range(max_retries):
            try:
                import fcntl

                fd = os.open(pipe_path, os.O_RDONLY | os.O_NONBLOCK)
                pipe = os.fdopen(fd, 'r', encoding='utf-8', errors='ignore')

                logging.info(f"Успешно открыт pipe: {pipe_path}")

                # Очистка накопленных данных
                if first_open:
                    logging.info(f"Очистка накопленных данных в pipe: {pipe_path}")
                    cleared_lines = 0
                    while True:
                        try:
                            line = pipe.readline()
                            if not line:
                                break
                            cleared_lines += 1
                        except (IOError, BlockingIOError):
                            break

                    if cleared_lines > 0:
                        logging.debug(f"Очищено {cleared_lines} строк из pipe {pipe_path}")

                    first_open = False

                    fd = pipe.fileno()
                    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                    fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)

                while self.running:
                    try:
                        line = pipe.readline()
                        if line:
                            queue.put((pipe_path, line.strip()))
                        else:
                            if not Path(pipe_path).exists():
                                logging.warning(f"Pipe файл {pipe_path} был удален или переименован, переоткрывает")
                                break
                            time.sleep(0.1)
                    except (IOError, OSError) as e:
                        logging.warning(f"Ошибка чтения из pipe {pipe_path}: {e}, переоткрывает")
                        break

                pipe.close()

            except FileNotFoundError:
                logging.error(f"Pipe файл не найден: {pipe_path}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                break
            except Exception as e:
                if attempt < max_retries - 1:
                    logging.warning(f"Ошибка открытия pipe {pipe_path} (попытка {attempt + 1}/{max_retries}): {e}")
                    time.sleep(retry_delay)
                else:
                    logging.error(f"Не удалось открыть pipe {pipe_path} после {max_retries} попыток: {e}")
                    break
            finally:
                if pipe and not pipe.closed:
                    pipe.close()

        logging.info(f"Завершено чтение из pipe: {pipe_path}")

    def start(self, queue: Queue):
        """Запускает чтение из pipe"""
        self.running = True
        self.threads = []
        self.pipes = {}

        # Функция для проверки новых pipe файлов
        def watch_new_pipes():
            """Фоновая проверка появления новых pipe файлов"""
            last_check = 0
            check_interval = 600  # Проверяет каждые 30 секунд

            while self.running:
                time.sleep(5)
                current_time = time.time()

                if current_time - last_check < check_interval:
                    continue

                last_check = current_time

                # Получает pipe файлы
                current_pipes = self.get_pipe_files()

                for pipe_file in current_pipes:
                    if pipe_file not in self.pipes:
                        logging.info(f"Обнаружен новый pipe файл: {pipe_file}, запускаем чтение")

                        # Создает и запускает поток для чтения
                        thread = threading.Thread(
                            target=self.read_pipe,
                            args=(pipe_file, queue),
                            daemon=True
                        )
                        thread.start()

                        self.pipes[pipe_file] = thread
                        self.threads.append(thread)

        # Чтение существующих файлов
        initial_pipes = self.get_pipe_files()
        for pipe_file in initial_pipes:
            logging.info(f"Запуск чтения из существующего pipe: {pipe_file}")
            thread = threading.Thread(
                target=self.read_pipe,
                args=(pipe_file, queue),
                daemon=True
            )
            thread.start()
            self.pipes[pipe_file] = thread
            self.threads.append(thread)

        watcher_thread = threading.Thread(target=watch_new_pipes, daemon=True)
        watcher_thread.start()
        self.threads.append(watcher_thread)

        logging.info(f"Запущено чтение из {len(initial_pipes)} pipe файлов")

    def stop(self):
        """Останавливет чтение"""
        self.running = False
        for thread in self.threads:
            thread.join(timeout=2)
        self.threads.clear()

class LogWriter:
    """Пишет логи в JSONL с ротацией"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.output_dir = Path(config['output']['directory'])
        self.filename_pattern = config['output']['filename_pattern']
        self.retention_days = config['output']['retention_days']

        # Текущий файл для записи
        self.current_file = None
        self.current_date = None

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def get_filename_for_date(self, date_obj: datetime) -> str:
        """Получить имя файла для даты"""
        return date_obj.strftime(self.filename_pattern)

    def rotate_if_needed(self, record_date: datetime = None):
        """Проверка и выполнение ротации файлов (только по дате)"""
        if record_date is None:
            record_date = datetime.now()

        current_date_str = record_date.date().isoformat()

        # Проверка даты
        date_changed = self.current_date != current_date_str

        # Если файл используется и дата не изменилась - пропуск
        if self.current_file and not date_changed:
            return

        if self.current_file:
            self.current_file.close()
            self.current_file = None
            self.current_date = None

        # Открывает новый файл
        filename = self.get_filename_for_date(record_date)
        filepath = self.output_dir / filename

        try:
            self.current_file = open(filepath, 'a', encoding='utf-8')
            self.current_date = current_date_str

            if date_changed:
                file_size = filepath.stat().st_size if filepath.exists() else 0
                logging.info(f"Открыт файл для записи: {filepath} (размер: {file_size} байт)")

            # Очистка старых файлов (при смене даты)
            if date_changed:
                self.cleanup_old_files()

        except Exception as e:
            logging.error(f"Ошибка открытия файла {filepath}: {e}")
            raise

    def write_record(self, record: Dict[str, Any]):
        """Записать одну запись в лог"""
        try:
            # Определяет дату записи
            record_date = None
            if 'datetime' in record:
                try:
                    record_date = datetime.fromisoformat(record['datetime'])
                except (ValueError, KeyError):
                    pass

            if not record_date and 'unix_timestamp' in record:
                try:
                    record_date = datetime.fromtimestamp(record['unix_timestamp'])
                except (ValueError, KeyError):
                    pass

            if not record_date:
                record_date = datetime.now()

            # Проверка ротации
            if not self.current_file or self.current_date != record_date.date().isoformat():
                self.rotate_if_needed(record_date)

            # Запись в JSONL
            json_line = json.dumps(record, ensure_ascii=False)
            self.current_file.write(json_line + '\n')
            self.current_file.flush()

        except Exception as e:
            logging.error(f"Ошибка записи записи: {e}")

    def write_batch(self, records: List[Dict[str, Any]]):
        """Записать пакет записей"""
        if not records:
            return

        try:
            # Определяет дату первой записи
            first_record = records[0]
            record_date = None

            if 'datetime' in first_record:
                try:
                    record_date = datetime.fromisoformat(first_record['datetime'])
                except (ValueError, KeyError):
                    pass

            if not record_date:
                record_date = datetime.now()

            # Проверка ротации
            self.rotate_if_needed(record_date)

            # Сбор в буфер
            data_to_write = ''.join(
                json.dumps(record, ensure_ascii=False) + '\n'
                for record in records
            )

            # Операция записи всего пакета
            self.current_file.write(data_to_write)
            self.current_file.flush()

        except Exception as e:
            logging.error(f"Ошибка записи пакета: {e}")

    def cleanup_old_files(self):
        """Удаление старые файлы логов"""
        if self.retention_days <= 0:
            return

        cutoff_date = datetime.now() - timedelta(days=self.retention_days)

        try:
            for file_path in self.output_dir.glob("*.jsonl"):
                # Извлекает дату из имени файла
                try:
                    filename = file_path.stem
                    date_str = None

                    # Поиск даты в формате YYYY-MM-DD
                    date_match = re.search(r'(\d{4}-\d{2}-\d{2})', filename)
                    if date_match:
                        date_str = date_match.group(1)
                        file_date = datetime.strptime(date_str, '%Y-%m-%d').date()

                        if file_date < cutoff_date.date():
                            file_path.unlink()
                            logging.info(f"Удален старый файл: {file_path}")
                except Exception as e:
                    logging.debug(f"Ошибка обработки файла {file_path}: {e}")

        except Exception as e:
            logging.error(f"Ошибка очистки старых файлов: {e}")

    def close(self):
        """Закрытие файлов"""
        if self.current_file:
            self.current_file.close()
            self.current_file = None

class DNSLogsCollector:
    """Основной класс демона сбора логов"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = DEFAULT_CONFIG
        self.running = False

        # Инициализация компонентов
        self.parser = LogParser(config)

        # Проверка наличия плагинов (минимально 1)
        if not self.parser.plugin_manager.plugins:
            logging.error("Нет загруженных плагинов!")
            logging.error("Скрипт не может работать без плагинов обработки.")
            self.has_plugins = False
        else:
            self.has_plugins = True

        self.pipe_reader = PipeReader(
            pipe_path=config['input']['pipe_path'],
            watch_directory=config['input'].get('watch_directory', False)
        )
        self.writer = LogWriter(config)

        # Логирует информацию о плагинах
        plugins_info = self.parser.get_plugins_info()
        if plugins_info:
            logging.info(f"Загружено плагинов: {len(plugins_info)}")
            for plugin_name, info in plugins_info.items():
                logging.info(f"  - {plugin_name}: {info.get('service', 'N/A')}")
        else:
            logging.warning("Плагины не загружены! Обработка логов невозможна.")

        # Инициализация ядра мониторинга
        self.monitoring_core = MonitoringCore(
            script_name="dns-logs-collector",
            config=config
        )

        # Очереди и буферы
        self.raw_queue = Queue(maxsize=10000)
        self.buffer = []
        self.batch_size = config['processing']['batch_size']
        self.flush_interval = config['processing']['flush_interval_sec']

        # Таймеры и потоки
        self.flush_thread = None
        self.processing_thread = None
        self.health_server_thread = None

        # Статистика
        self.stats = {
            'records_processed': 0,
            'records_written': 0,
            'parse_errors': 0,
            'start_time': None
        }

        # Настройка обработчиков сигналов
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

    def setup_logging(self):
        """Настройка логирования демона"""
        log_config = self.config['logging']
        log_level = getattr(logging, log_config['level'].upper())

        # Очищает существующие обработчики
        root_logger = logging.getLogger()
        root_logger.handlers.clear()

        # Форматтер
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Обработчик файла с ротацией
        if 'file' in log_config:
            log_file = Path(log_config['file'])
            log_file.parent.mkdir(parents=True, exist_ok=True)

            max_bytes = log_config.get('max_size_mb', 10) * 1024 * 1024
            backup_count = log_config.get('backup_count', 5)

            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)

        # Консольный обработчик
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

        root_logger.setLevel(log_level)

        logging.getLogger('urllib3').setLevel(logging.WARNING)

    def signal_handler(self, signum, frame):
        """Обработчик сигналов завершения"""
        logging.info(f"Получен сигнал {signum}, завершение работы")
        self.stop()

    def process_raw_line(self, pipe_path: Path, line: str):
        """Обработать сырую строку из pipe"""
        if not line.strip():
            return

        try:
            # Парсинг строки с помощью плагинов
            record = self.parser.parse_line(line)

            if record:
                record['_collector'] = {
                    'received_at': datetime.now().isoformat(),
                    'pipe_source': str(pipe_path)
                }

                if 'service' not in record and '_plugin' in record:
                    plugin_info = self.parser.get_plugins_info()
                    if record['_plugin'] in plugin_info:
                        record['service'] = plugin_info[record['_plugin']].get('service', record['_plugin'])

                # Добавляет в буфер
                self.buffer.append(record)
                self.stats['records_processed'] += 1

                # Обновляет статистику в мониторинге
                self.monitoring_core.update_statistics(
                    'record_processed',
                    count=1,
                    success=True
                )

            else:
                self.stats['parse_errors'] += 1
                self.monitoring_core.update_statistics(
                    'record_processed',
                    count=1,
                    success=False,
                    error="Parse error"
                )
                logging.debug(f"Не удалось распарсить строку (нет подходящего плагина): {line[:100]}...")

        except Exception as e:
            self.stats['parse_errors'] += 1
            self.monitoring_core.update_statistics(
                'record_processed',
                count=1,
                success=False,
                error=str(e)
            )
            logging.error(f"Ошибка обработки строки: {e}")

    def flush_buffer(self, force: bool = False):
        """Сбросить буфер на диск"""
        if not self.buffer:
            return

        # Пакетная запись
        batch_size = self.batch_size
        for i in range(0, len(self.buffer), batch_size):
            batch = self.buffer[i:i + batch_size]
            self.writer.write_batch(batch)
            self.stats['records_written'] += len(batch)

        self.buffer.clear()

        if force or self.stats['records_written'] % 1000 == 0:
            logging.debug(f"Статистика: обработано {self.stats['records_processed']}, "
                         f"записано {self.stats['records_written']}, "
                         f"ошибок {self.stats['parse_errors']}")

    def flush_worker(self):
        """Фоновая задача для периодического сброса буфера"""
        try:
            while self.running:
                time.sleep(self.flush_interval)
                if self.buffer:
                    self.flush_buffer(force=True)
        except KeyboardInterrupt:
            logging.debug("Flush worker получил KeyboardInterrupt")
        except Exception as e:
            logging.error(f"Ошибка в flush_worker: {e}")

    def processing_worker(self):
        """Фоновая задача обработки сырых строк"""
        try:
            while self.running:
                try:
                    # Блокирующее чтение с таймаутом
                    pipe_path, line = self.raw_queue.get(timeout=1)
                    self.process_raw_line(pipe_path, line)
                except Empty:
                    continue
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logging.error(f"Ошибка в обработчике: {e}")
        except KeyboardInterrupt:
            logging.debug("Processing worker получил KeyboardInterrupt")
        except Exception as e:
            logging.error(f"Критическая ошибка в processing_worker: {e}")


    def start(self):
        """Запустить демон"""
        logging.info(f"\n =============== Запуск - DNS Logs Collector ===============")

        if not self.has_plugins:
            logging.error("Невозможно запустить коллектор: нет плагинов обработки!")
            return

        plugins_info = self.parser.get_plugins_info()
        if plugins_info:
            plugin_list = []
            for plugin_name, info in plugins_info.items():
                service_name = info.get('service', plugin_name)
                plugin_list.append(f"{plugin_name} ({service_name})")

            logging.info(f"Активные плагины обработки: {', '.join(plugin_list)}")
            logging.info(f"Всего плагинов: {len(plugins_info)}")
        else:
            logging.error("КРИТИЧЕСКАЯ ОШИБКА: Нет загруженных плагинов.")
            logging.error("Скрипт не может обрабатывать логи без плагинов.")
            logging.error("Конфигурация плагинов: директория='{self.config['plugins']['directory']}'")
            return

        self.running = True
        self.stats['start_time'] = datetime.now()

        # Запуск health check сервера
        port = self.config.get('monitoring', {}).get('listen_port', 8080)
        if port > 0:
            # Создает кастомный обработчик с доступом к коллектору
            def handler_factory(*args, **kwargs):
                return DNSHealthCheckHandler(*args, collector=self, **kwargs)

            self.health_server_thread = self.monitoring_core.start_health_check_server(handler_factory)
            if self.health_server_thread:
                logging.info(f"Health check сервер запущен на порту {port}")

        # Обновляет статус в мониторинге
        self.monitoring_core.health_status['status'] = 'starting'

        # Запуск pipe reader
        self.pipe_reader.start(self.raw_queue)

        # Запуск фоновых потоков
        self.processing_thread = threading.Thread(
            target=self.processing_worker,
            daemon=True
        )
        self.processing_thread.start()

        self.flush_thread = threading.Thread(
            target=self.flush_worker,
            daemon=True
        )
        self.flush_thread.start()

        # Обновляет статус в мониторинге
        self.monitoring_core.health_status['status'] = 'healthy'
        self.monitoring_core.update_statistics('startup', success=True)

        logging.info("DNS Logs Collector запущен")

        # Основной цикл ожидания
        try:
            while self.running:
                # Проверяет состояние потоков
                if not self.processing_thread.is_alive():
                    logging.error("Поток обработки остановлен!")
                    self.monitoring_core.health_status['status'] = 'degraded'
                    break

                if not self.flush_thread.is_alive():
                    logging.error("Поток сброса остановлен!")
                    self.monitoring_core.health_status['status'] = 'degraded'
                    break

                time.sleep(1)

                # Периодическая статистика
                stats_interval = self.config.get('monitoring', {}).get('stats_interval_sec', 300)
                if time.time() % stats_interval < 1:
                    elapsed = datetime.now() - self.stats['start_time']

                    # Форматирует uptime в DD:HH:MM:SS
                    total_seconds = int(elapsed.total_seconds())
                    days = total_seconds // 86400
                    hours = (total_seconds % 86400) // 3600
                    minutes = (total_seconds % 3600) // 60
                    seconds = total_seconds % 60

                    if days > 0:
                        uptime_str = f"{days}d:{hours:02d}h:{minutes:02d}m:{seconds:02d}s"
                    else:
                        uptime_str = f"{hours:02d}h:{minutes:02d}m:{seconds:02d}s"

                    # Обновляет статистику в мониторинге
                    self.monitoring_core.update_statistics(
                        'stats_report',
                        count=self.stats['records_processed'],
                        success=True
                    )

                    logging.info(
                        f"Статистика за {uptime_str}: "
                        f"обработано {self.stats['records_processed']} записей, "
                        f"записано {self.stats['records_written']}"
                    )

        except KeyboardInterrupt:
            logging.info("Получен KeyboardInterrupt")
            self.monitoring_core.health_status['status'] = 'stopping'
        except Exception as e:
            logging.error(f"Ошибка в основном цикле: {e}")
            self.monitoring_core.health_status['status'] = 'unhealthy'
            self.monitoring_core.update_statistics('main_loop', success=False, error=str(e))

        self.stop()

    def stop(self):
        """Остановить демон"""
        if not self.running:
            return

        logging.info("Остановка DNS Logs Collector...")
        self.running = False

        # Обновляет статус в мониторинге
        self.monitoring_core.health_status['status'] = 'stopping'

        self.pipe_reader.stop()

        timeout_shutdown = 10  # секунд на graceful shutdown
        start_time = time.time()

        # Ожидание очистки очереди (не более timeout_shutdown секунд)
        while (not self.raw_queue.empty() or self.buffer) and \
              (time.time() - start_time) < timeout_shutdown:
            logging.debug(f"Ожидание завершения обработки... "
                         f"Очередь: {self.raw_queue.qsize()}, Буфер: {len(self.buffer)}")
            time.sleep(0.5)
            # Обработка оставшихся сообщений
            try:
                while not self.raw_queue.empty():
                    pipe_path, line = self.raw_queue.get_nowait()
                    self.process_raw_line(pipe_path, line)
            except Empty:
                pass

        # Принудительный сброс буфера
        self.flush_buffer(force=True)

        # Ожидание завершения потоков
        thread_timeout = 5

        if self.processing_thread and self.processing_thread.is_alive():
            self.processing_thread.join(timeout=thread_timeout)
            if self.processing_thread.is_alive():
                logging.warning("Processing thread не завершился за отведенное время")

        if self.flush_thread and self.flush_thread.is_alive():
            self.flush_thread.join(timeout=thread_timeout)
            if self.flush_thread.is_alive():
                logging.warning("Flush thread не завершился за отведенное время")

        self.writer.close()

        # Финальная статистика
        elapsed = datetime.now() - self.stats['start_time']

        # Форматирование uptime в DD:HH:MM:SS
        total_seconds = int(elapsed.total_seconds())
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60

        if days > 0:
            uptime_str = f"{days}d:{hours:02d}h:{minutes:02d}m:{seconds:02d}s"
        else:
            uptime_str = f"{hours:02d}h:{minutes:02d}m:{seconds:02d}s"

        self.monitoring_core.update_statistics(
            'shutdown',
            count=self.stats['records_processed'],
            success=True
        )
        self.monitoring_core.health_status['status'] = 'stopped'

        logging.info(
            f"Итоговая статистика: отработанный uptime {uptime_str}, "
            f"обработано {self.stats['records_processed']} записей, "
            f"ошибок парсинга: {self.stats['parse_errors']}"
        )

        logging.info(f"\n ========== DNS Logs Collector остановлен ==========")

class DNSHealthCheckHandler(BaseHealthCheckHandler):
    """Обработчик health check"""

    def __init__(self, *args, collector=None, **kwargs):
        self.collector = collector
        super().__init__(*args, **kwargs)

    def get_health_status(self) -> Dict[str, Any]:
        """Получить статус здоровья DNS Logs Collector"""
        if not self.collector:
            return {
                "status": "unhealthy",
                "error": "Collector not initialized",
                "timestamp": datetime.now().isoformat()
            }

        try:
            # Базовые метрики
            metrics = {
                "processed_total": self.collector.stats['records_processed'],
                "written_total": self.collector.stats['records_written'],
                "parse_errors_total": self.collector.stats['parse_errors'],
                "buffer_current": len(self.collector.buffer),
                "queue_current": self.collector.raw_queue.qsize(),
                "uptime_seconds": (datetime.now() - self.collector.stats['start_time']).total_seconds()
                    if self.collector.stats['start_time'] else 0
            }

            # Рассчет rate обработки
            if metrics['uptime_seconds'] > 0:
                metrics['processing_rate'] = round(
                    metrics['processed_total'] / metrics['uptime_seconds'], 1
                )
            else:
                metrics['processing_rate'] = 0.0

            # Форматирует uptime
            uptime_seconds = metrics['uptime_seconds']
            days = int(uptime_seconds) // 86400
            hours = (int(uptime_seconds) % 86400) // 3600
            minutes = (int(uptime_seconds) % 3600) // 60
            seconds = int(uptime_seconds) % 60

            if days > 0:
                metrics['uptime_formatted'] = f"{days}d:{hours:02d}h:{minutes:02d}m:{seconds:02d}s"
            else:
                metrics['uptime_formatted'] = f"{hours:02d}h:{minutes:02d}m:{seconds:02d}s"

            # Проверка состояния потоков
            collector_alive = self.collector.running
            pipe_reader_alive = self.collector.pipe_reader.running if self.collector.pipe_reader else False

            # Проверка состояние фоновых потоков
            processing_alive = (self.collector.processing_thread and
                               self.collector.processing_thread.is_alive())
            flush_alive = (self.collector.flush_thread and
                          self.collector.flush_thread.is_alive())
            writer_alive = processing_alive and flush_alive

            # Определение общего статуса
            if not collector_alive:
                status = "stopped"
            elif not processing_alive or not flush_alive:
                status = "degraded"
            elif self.collector.stats['parse_errors'] > 100:  # Порог ошибок
                status = "degraded"
            elif metrics['queue_current'] > 1000:  # Переполнение очереди
                status = "degraded"
            else:
                status = "healthy"

            # Информация о pipe источниках
            pipe_sources = {}
            if hasattr(self.collector.pipe_reader, 'pipes'):
                for pipe_path, thread in self.collector.pipe_reader.pipes.items():
                    pipe_sources[str(pipe_path)] = {
                        "thread_alive": thread.is_alive() if thread else False
                    }

            # Формирует полный ответ
            response = {
                "status": status,
                "service": "dns-logs-collector",
                "collector_alive": collector_alive,
                "pipe_reader_alive": pipe_reader_alive,
                "writer_alive": writer_alive,
                "processing_thread_alive": processing_alive,
                "flush_thread_alive": flush_alive,
                "metrics": metrics,
                "pipe_sources": pipe_sources,
                "timestamp": datetime.now().isoformat()
            }

            # Добавляет информацию из мониторинга
            if hasattr(self.collector, 'monitoring_core'):
                base_status = self.collector.monitoring_core.get_base_health_status()
                response.update({
                    "last_successful_operation": base_status.get('last_successful_operation'),
                    "errors": base_status.get('errors', []),
                    "statistics": base_status.get('statistics', {})
                })

            # Информация о плагинах
            if hasattr(self.collector.parser, 'get_plugins_info'):
                response['plugins'] = self.collector.parser.get_plugins_info()
                response['plugins_count'] = len(response['plugins'])

            return response

        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

def main():
    """Точка входа"""

    parser = argparse.ArgumentParser(description='DNS Logs Collector')
    parser.add_argument('--list-plugins', action='store_true',
                       help='Показать список загруженных плагинов')

    args = parser.parse_args()

    if args.list_plugins:
        parser = LogParser(DEFAULT_CONFIG)
        plugins_info = parser.get_plugins_info()

        print("Загруженные плагины:")
        for plugin_name, info in plugins_info.items():
            print(f"  {plugin_name}:")
            print(f"    Сервис: {info.get('service', 'N/A')}")
            print(f"    Форматы: {', '.join(info.get('supported_formats', []))}")
        return


    # Создание и запуск коллектора
    collector = DNSLogsCollector(DEFAULT_CONFIG)
    collector.setup_logging()

    try:
        collector.start()
    except Exception as e:
        logging.error(f"Критическая ошибка: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
