#!/usr/bin/env python3
"""
Скрипт для скачивания и проверки MMDB базы ASN:
1. iplocate.io
2. ipinfo.io
"""

import logging
import sys
import shutil
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import requests
import maxminddb
import json

# Настройки скрипта
CONFIG = {
    # Ожидаемые поля для базы в рамках системы MikroTik-ARMA (example): "AS15169":"Google LLC":"US"
    "SYSTEM_REQUIRED_FIELDS": ["asn", "org", "country_code"],

    # Сервисы для скачивания MMDB баз (приоритет определяется порядком)
    "SERVICES": {
       "iplocate.io": {            # 1-й сервис для получения MMDB
            "urls": [
                "https://www.iplocate.io/download/ip-to-asn.mmdb?apikey=<YOUR_API_KEY>&variant=daily",   # 1-й URL для загрузки
                "https://github.com/iplocate/ip-address-databases/raw/refs/heads/main/ip-to-asn/ip-to-asn.mmdb?download=", # 2-й URL для загрузки
            ],
            "field_mapping": {}
        },
        "ipinfo.io": {             # 2-й сервис для получения MMDB
            "urls": [
                "https://ipinfo.io/data/ipinfo_lite.mmdb?token=<YOUR_API_KEY>"
            ],
            "field_mapping": {
                "org": "as_name",  # сопоставление полей: org (MikroTik-ARMA) -> as_name (ipinfo.io)
            }
        },

    },

    # Пути для файлов
    "MMDB_DIR": Path("raw-data/ASN-db/"),  # Директория для MMDB файлов
    "BACKUP_DIR": Path("raw-data/ASN-db/backups"),  # Директория для бэкапов MMDB
    "MMDB_FILENAME": "ip-to-asn.mmdb",  # Имя MMDB файла

    # Параметры бэкапов
    "MAX_BACKUPS": 3,  # Максимальное количество хранимых бэкапов MMDB

    # Параметры скачивания
    "DOWNLOAD_TIMEOUT": 30,  # Таймаут скачивания в секундах
    # Минимальный размер файла (в байтах)
    # Формула: МБ × 1024 × 1024
    # 15 MB = 15 * 1024 * 1024 = 15,728,640 байт
    # 256 MB = 256 * 1024 * 1024 = 268,435,456 байт
    # 1 GB = 1 * 1024 * 1024 * 1024 = 1,073,741,824 байт
    "MIN_FILE_SIZE": 15 * 1024 * 1024,

    # Логирование
    "LOG_DIR": Path("logs/additional/get_asn_mmdb"),
    "LOG_LEVEL": "INFO", #DEBUG, INFO, WARNING, ERROR

    # Отладка (срабатывает в случае провальной проверки MMDB базы)
    "DEBUG_DUMP_RECORDS": 2,  # Сколько записей выводить при ошибке (0 = отключено) - работает в обход основного DEBUG режима
    "DEBUG_TEST_IPS": [  # IP для дампа
        "8.8.8.8",
        "1.1.1.1",
        "77.88.8.8",
        "208.67.222.222"
    ],
}

# Автоматическое определение имени лог файла
script_name = Path(__file__).stem
log_filename = f"{script_name}.log"

# Создание директории для логов
log_path = CONFIG["LOG_DIR"] / log_filename
log_path.parent.mkdir(parents=True, exist_ok=True)

# Настройка логирования
log_level = getattr(logging, CONFIG["LOG_LEVEL"].upper(), logging.INFO)

logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_path, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class MMDBDownloader:
    """Скачивание и управление MMDB базой"""

    class ServiceInfo:
        """Информация о сервисе"""
        def __init__(self, name: str, config: Dict):
            self.name = name
            self.urls = config["urls"]
            self.field_mapping = config.get("field_mapping", {})

    def __init__(self, config: Dict):
        self.config = config
        self.mmdb_path = config["MMDB_DIR"] / config["MMDB_FILENAME"]
        self.backup_dir = config["BACKUP_DIR"]

        # Инициализация сервисов из конфигурации
        self.services = {}
        for service_name, service_config in config["SERVICES"].items():
            self.services[service_name] = self.ServiceInfo(service_name, service_config)

        self.mmdb_path.parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def _get_test_ips(self) -> List[str]:
        """Получение тестовых IP для проверки (единый источник)"""
        return self.config.get("DEBUG_TEST_IPS", [
            "8.8.8.8",
            "1.1.1.1",
            "77.88.8.8",
            "208.67.222.222"
        ])

    def analyze_mmdb_structure(self, mmdb_path: Path, num_samples: int = 5,
                              dump_debug_info: bool = False, source_url: Optional[str] = None) -> Dict:
        """Анализ структуры MMDB файла с опциональным выводом отладочной информации"""
        if not mmdb_path.exists():
            logger.error(f"Файл для анализа не существует: {mmdb_path}")
            return {}

        analysis_result = {
            "total_fields_found": set(),
            "field_types": {},
            "sample_records": [],
            "system_compliance": {},
            "service_suggestions": {}
        }

        try:
            if dump_debug_info:
                logger.debug("=" * 60)
                logger.debug("DEBUG: Анализ структуры MMDB файла")
                logger.debug("=" * 60)

            with maxminddb.open_database(str(mmdb_path)) as reader:
                if dump_debug_info:
                    metadata = reader.metadata()
                    logger.debug(f"Метаданные базы:")
                    logger.debug(f"  Тип базы: {metadata.database_type}")
                    logger.debug(f"  Версия: {metadata.binary_format_major_version}.{metadata.binary_format_minor_version}")
                    logger.debug(f"  Дата сборки: {metadata.build_epoch}")
                    logger.debug(f"  Описание: {metadata.description.get('en', 'N/A')}")

                test_ips = self._get_test_ips()

                if dump_debug_info:
                    logger.debug(f"\nДЕТАЛЬНОЕ СОДЕРЖИМОЕ для тестовых IP ({len(test_ips)}):")

                for i, ip in enumerate(test_ips[:num_samples]):
                    try:
                        data = reader.get(ip)
                        if data:
                            record_info = {
                                "ip": ip,
                                "fields": {},
                                "all_field_names": list(data.keys()),
                                "data": data
                            }

                            # Собирает информацию о полях
                            for field_name, field_value in data.items():
                                analysis_result["total_fields_found"].add(field_name)

                                field_type = type(field_value).__name__
                                record_info["fields"][field_name] = {
                                    "type": field_type,
                                    "value": field_value
                                }

                                # Собирает статистику по типам
                                if field_name not in analysis_result["field_types"]:
                                    analysis_result["field_types"][field_name] = set()
                                analysis_result["field_types"][field_name].add(field_type)

                                # Вывод отладочной информации
                                if dump_debug_info:
                                    if isinstance(field_value, (list, dict)):
                                        logger.debug(f"    {field_name}: {type(field_value).__name__} = {field_value}")
                                    elif isinstance(field_value, str):
                                        logger.debug(f"    {field_name}: str = '{field_value}'")
                                    elif isinstance(field_value, (int, float)):
                                        logger.debug(f"    {field_name}: {type(field_value).__name__} = {field_value}")
                                    else:
                                        logger.debug(f"    {field_name}: {type(field_value).__name__} = {repr(field_value)}\n")

                            analysis_result["sample_records"].append(record_info)

                            if dump_debug_info:
                                # Проверяет требования к маппингу
                                system_required_fields = self.config["SYSTEM_REQUIRED_FIELDS"]
                                missing_fields = []
                                for system_field in system_required_fields:
                                    if system_field not in data:
                                        service_info = self.get_service_from_url(source_url) if source_url else None
                                        if service_info:
                                            if system_field in service_info.field_mapping:
                                                mapped_field = service_info.field_mapping[system_field]
                                                if mapped_field not in data:
                                                    missing_fields.append(system_field)
                                            else:
                                                missing_fields.append(system_field)
                                        else:
                                            missing_fields.append(system_field)

                                if missing_fields:
                                    missing_info = []
                                    for system_field in missing_fields:
                                        # Поиск информации о маппинге
                                        service_info = self.get_service_from_url(source_url) if source_url else None
                                        mapped_field = None

                                        if service_info and system_field in service_info.field_mapping:
                                            mapped_field = service_info.field_mapping[system_field]
                                            missing_info.append(f"'{system_field}' (мапится из '{mapped_field}')")
                                        else:
                                            missing_info.append(f"'{system_field}' (прямое поле)")

                                    logger.debug(f"    Отсутствуют поля для: {', '.join(missing_info)}\n")
                                else:
                                    logger.debug(f"    Все поля присутствуют\n")

                        else:
                            if dump_debug_info:
                                logger.debug(f"\n[{i+1}] IP: {ip} - Нет данных в базе")

                    except Exception as ip_error:
                        if dump_debug_info:
                            logger.debug(f"\n[{i+1}] IP: {ip} - Ошибка чтения: {ip_error}")

                # Анализ соответствия системным требованиям (общая логика)
                system_fields = self.config["SYSTEM_REQUIRED_FIELDS"]
                for system_field in system_fields:
                    analysis_result["system_compliance"][system_field] = {
                        "required": True,
                        "found_in_data": system_field in analysis_result["total_fields_found"],
                        "possible_matches": []
                    }

                    if not analysis_result["system_compliance"][system_field]["found_in_data"]:
                        for found_field in analysis_result["total_fields_found"]:
                            if system_field in found_field or found_field in system_field:
                                analysis_result["system_compliance"][system_field]["possible_matches"].append(found_field)

                # Генерация предложений для конфигурации
                for system_field in system_fields:
                    if not analysis_result["system_compliance"][system_field]["found_in_data"]:
                        possible_matches = analysis_result["system_compliance"][system_field]["possible_matches"]
                        if possible_matches:
                            analysis_result["service_suggestions"][system_field] = possible_matches[0]

                if dump_debug_info:
                    logger.info("=" * 60)

                return analysis_result

        except Exception as e:
            logger.error(f"Ошибка при анализе структуры MMDB: {e}")
            return analysis_result

    def create_backup(self) -> Optional[Path]:
        """Создание бэкапа текущего MMDB файла"""
        if not self.mmdb_path.exists():
            logger.info("Текущий MMDB файл не существует, бэкап не требуется")
            return None

        try:
            # Создание имени файла с датой
            timestamp = datetime.now().strftime("%d-%m-%Y")
            backup_name = f"{timestamp}-{self.config['MMDB_FILENAME']}"
            backup_path = self.backup_dir / backup_name

            # Копирование файла
            shutil.copy2(self.mmdb_path, backup_path)
            logger.info(f"Создан бэкап: {backup_path}")

            # Очистка старых бэкапов
            self._cleanup_old_backups()

            return backup_path

        except Exception as e:
            logger.error(f"Ошибка при создании бэкапа: {e}")
            return None

    def _cleanup_old_backups(self):
        """Удаление старых бэкапов"""
        try:
            # Получение бэкапов, отсортированных по дате изменения
            backups = list(self.backup_dir.glob(f"*-{self.config['MMDB_FILENAME']}"))
            backups.sort(key=lambda x: x.stat().st_mtime, reverse=True)

            # Ротация бэкапов
            for backup in backups[self.config["MAX_BACKUPS"]:]:
                backup.unlink()
                logger.info(f"Удален старый бэкап: {backup}")

        except Exception as e:
            logger.error(f"Ошибка при очистке бэкапов: {e}")

    def get_service_from_url(self, url: str) -> Optional['MMDBDownloader.ServiceInfo']:
        """Определение сервиса по URL"""
        if not hasattr(self, 'services') or not self.services:
            return None

        try:
            from urllib.parse import urlparse
            url_lower = url.lower()
            parsed_url = urlparse(url_lower)
            hostname = parsed_url.netloc

            if hostname.startswith('www.'):
                hostname = hostname[4:]
            if ':' in hostname:
                hostname = hostname.split(':')[0]

            for service_name, service_info in self.services.items():
                # Проверяетт все URL сервиса
                for service_url in service_info.urls:
                    service_url_lower = service_url.lower()
                    service_parsed = urlparse(service_url_lower)
                    service_hostname = service_parsed.netloc

                    if service_hostname.startswith('www.'):
                        service_hostname = service_hostname[4:]
                    if ':' in service_hostname:
                        service_hostname = service_hostname.split(':')[0]

                    # Сравнение доменов
                    if hostname == service_hostname:
                        return service_info
        except Exception as e:
            logger.debug(f"Не удалось распарсить URL {url}: {e}")

            for service_name, service_info in self.services.items():
                if service_name.lower() in url.lower():
                    return service_info

        return None

    def download_mmdb(self, url: str) -> Optional[Path]:
        """Скачивание с отображением прогресса"""
        try:
            logger.info(f"Скачивание из: {url}")

            response = requests.get(
                url,
                timeout=self.config["DOWNLOAD_TIMEOUT"],
                stream=True
            )
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))

            if total_size:
                logger.info(f"Общий размер файла: {self._format_size(total_size)}")

            temp_path = self.mmdb_path.with_suffix('.tmp')

            with open(temp_path, 'wb') as f:
                downloaded = 0
                start_time = datetime.now()
                last_log_time = start_time

                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)

                        # Информирование каждые N секунд
                        current_time = datetime.now()
                        time_since_last_log = (current_time - last_log_time).total_seconds()

                        if time_since_last_log >= 10.0:  # Каждые 10 секунд
                            elapsed_time = (current_time - start_time).total_seconds()
                            speed = downloaded / elapsed_time if elapsed_time > 0 else 0

                            if total_size:
                                percent = (downloaded / total_size) * 100
                                logger.info(
                                    f"Прогресс: {percent:.1f}% | "
                                    f"{self._format_size(downloaded)} / {self._format_size(total_size)} | "
                                    f"Скорость: {self._format_size(speed)}/сек"
                                )
                            else:
                                logger.info(
                                    f"Скачано: {self._format_size(downloaded)} | "
                                    f"Скорость: {self._format_size(speed)}/сек"
                                )

                            last_log_time = current_time

            # Финальный лог
            elapsed_time = (datetime.now() - start_time).total_seconds()
            if total_size:
                logger.info(f" Загружено 100% ({self._format_size(total_size)})")

            logger.info(f" Время загрузки: {elapsed_time:.1f} сек")

            return temp_path

        except Exception as e:
            logger.error(f"Ошибка скачивания MMDB: {e}")
            return None

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Форматирование размера в читаемом виде"""
        if size_bytes == 0:
            return "0B"

        size_names = ("B", "KB", "MB", "GB", "TB")
        i = 0
        size = float(size_bytes)

        while size >= 1024 and i < len(size_names) - 1:
            size /= 1024
            i += 1

        return f"{size:.2f} {size_names[i]}"

    def validate_mmdb_structure(self, mmdb_path: Path, source_url: Optional[str] = None) -> bool:
        """Проверка структуры MMDB файла с учетом системных требований"""
        if not mmdb_path.exists():
            logger.error(f"Файл для проверки не существует: {mmdb_path}")
            return False

        try:
            # Сервис для генерации маппинга
            service_info = self.get_service_from_url(source_url) if source_url else None

            if service_info:
                logger.info(f"Проверка MMDB от сервиса: {service_info.name}")

            system_required_fields = self.config["SYSTEM_REQUIRED_FIELDS"]
            logger.info(f"Проверка на обязательные поля MikroTik-ARMA: {system_required_fields}")

            field_mapping = service_info.field_mapping if service_info else {}

            with maxminddb.open_database(str(mmdb_path)) as reader:
                # Тестирование IP для проверки структуры
                test_ips = self._get_test_ips()

                valid_records = 0
                for ip in test_ips:
                    try:
                        data = reader.get(ip)

                        if data:
                            missing_fields = []

                            # Проверяет поля, которое требует MikroTik-ARMA
                            for system_field in system_required_fields:
                                # 1. Проверяет маппинг
                                if system_field in field_mapping:
                                    mapped_field = field_mapping[system_field]
                                    if mapped_field in data:
                                        continue
                                    else:
                                        missing_fields.append(system_field)
                                        logger.debug(f"Поле '{system_field}' должно мапиться из '{mapped_field}', но его нет в базе данных MMBD")

                                # 2. Проверяет прямое совпадение
                                elif system_field in data:
                                    continue

                                # 3. Если ни маппинга, ни прямого совпадения - поле отсутствует
                                else:
                                    missing_fields.append(system_field)

                            if not missing_fields:
                                valid_records += 1

                                org_field = "org"
                                # Определяет поле организации через маппинг
                                if "org" in field_mapping:
                                    org_field = field_mapping["org"]
                                else:
                                    # Пробуем найти поле организации в данных
                                    for possible_field in ["as_name", "organization", "autonomous_system_organization", "org"]:
                                        if possible_field in data:
                                            org_field = possible_field
                                            break

                                org_value = data.get(org_field, 'N/A')
                                logger.debug(f"IP {ip}: OK - AS{data.get('asn', 'N/A')} {org_value}")
                            else:
                                available_fields = list(data.keys())
                                # Детальный вывод данных для отладки
                                logger.warning(f"IP {ip}: отсутствуют системные поля {missing_fields}")
                                logger.warning(f"    Доступные поля ({len(available_fields)}): {available_fields}")
                                logger.warning(f"    Содержимое записи:")
                                for field_name, field_value in data.items():
                                    if isinstance(field_value, (list, dict)):
                                        logger.warning(f"        {field_name}: {type(field_value).__name__} = {field_value}")
                                    else:
                                        logger.warning(f"        {field_name}: {type(field_value).__name__} = '{field_value}'")

                                # Возможные поля для маппинга
                                possible_mappings = {}
                                for missing_field in missing_fields:
                                    similar_fields = []
                                    for available_field in available_fields:
                                        if missing_field in available_field or available_field in missing_field:
                                            similar_fields.append(available_field)
                                    if similar_fields:
                                        possible_mappings[missing_field] = similar_fields

                                if possible_mappings:
                                    logger.warning(f"   Предложение для маппинга для CONFIG['SERVICES']:")
                                    for missing_field, similar_fields in possible_mappings.items():
                                        logger.warning(f"        '{missing_field}': '{similar_fields[0]}'")
                        else:
                            logger.debug(f"IP {ip}: нет данных в базе")

                    except Exception as e:
                        logger.warning(f"Ошибка при проверке IP {ip}: {e}")

                # Проверка успешна, если найдено хотя бы N валидных записей
                if valid_records >= 2:  # 2 валидных записи
                    logger.info(f"Проверка структуры пройдена: {valid_records}/{len(test_ips)} тестовых IP соответствуют системным требованиям")
                    return True
                else:
                    logger.error(f"Проверка структуры не пройдена: {valid_records}/{len(test_ips)} тестовых IP соответствуют системным требованиям")

                    debug_records = self.config.get("DEBUG_DUMP_RECORDS", 0)
                    if debug_records > 0:
                        logger.warning(f"Отладочный дамп ({debug_records} записей)...")
                        self.analyze_mmdb_structure(mmdb_path, debug_records, dump_debug_info=True, source_url=source_url)
                    return False

        except Exception as e:
            logger.error(f"Ошибка при проверке MMDB файла: {e}")

            debug_records = self.config.get("DEBUG_DUMP_RECORDS", 0)
            if debug_records > 0:
                logger.warning("Дополнительный анализ структуры базы...")
                self.print_detailed_analysis(mmdb_path)
            return False

    def calculate_file_hash(self, file_path: Path) -> Optional[str]:
        """Вычисление хэша файла для проверки целостности"""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Ошибка при вычислении хэша файла: {e}")
            return None

    def download_and_validate(self) -> bool:
        """Основной метод скачивания и проверки MMDB файла"""
        logger.info("=" * 60)
        logger.info("Запущен процесс обновления MMDB базы")
        logger.info("=" * 60)

        if not hasattr(self, 'services') or not self.services:
            logger.error("Не настроены сервисы для скачивания")
            return False

        service_names = ", ".join(self.services.keys())
        logger.info(f"Доступные сервисы: {service_names}")

        # Создание бэкапа текущей MMDB
        backup_path = self.create_backup()

        # Генерация списка всех URL для скачивания (порядок из CONFIG)
        all_urls = []
        for service_name in self.config["SERVICES"].keys():
            if service_name in self.services:
                all_urls.extend(self.services[service_name].urls)

        # Попытка скачивания из каждого источника
        downloaded_file = None
        download_url = None

        for url in all_urls:
            downloaded_file = self.download_mmdb(url)
            if downloaded_file:
                download_url = url
                service_info = self.get_service_from_url(url)
                if service_info:
                    logger.info(f"Успешно скачано из сервиса: {service_info.name}")
                break

        if not downloaded_file:
            logger.error("Не удалось скачать файл ни из одного источника")
            return False

        # Проверка структуры скачанного файла с учетом источника
        if not self.validate_mmdb_structure(downloaded_file, download_url):
            logger.error("Скачанный файл не прошел проверку структуры")

            # Если есть бэкап - восстанавливает его (в случае провальной проверки структуры)
            if backup_path and backup_path.exists():
                logger.info("Восстановление файла бэкапа")
                shutil.copy2(backup_path, self.mmdb_path)

            downloaded_file.unlink()
            return False

        # Вычисление хэша нового файла
        new_file_hash = self.calculate_file_hash(downloaded_file)
        if new_file_hash:
            logger.info(f"SHA256 нового файла: {new_file_hash}")

        # Замена текущей MMDB новой
        try:
            # Удаляет старый MMDB если существует
            if self.mmdb_path.exists():
                self.mmdb_path.unlink()

            # Перемещает временный файл на место основного
            shutil.move(downloaded_file, self.mmdb_path)

            service_info = self.get_service_from_url(download_url) if download_url else None
            service_name = service_info.name if service_info else "unknown"
            logger.info(f"Файл успешно обновлен от сервиса {service_name}: {self.mmdb_path}")

            # Экспорт схемы после успешного обновления
            if service_info:
                schema_path = self.export_mmdb_schema(service_info)

            # Проверяет хэш после перемещения
            final_hash = self.calculate_file_hash(self.mmdb_path)
            if final_hash and new_file_hash:
                if final_hash == new_file_hash:
                    logger.info("Целостность файла подтверждена (хэши совпадают)")
                else:
                    logger.warning("Хэши файлов не совпадают. Возможна проблема с целостностью")

            return True

        except Exception as e:
            logger.error(f"Ошибка при замене файла: {e}")

            # Восстановление из бэкапа в случае ошибки
            if backup_path and backup_path.exists():
                logger.info("Восстановление из бэкапа после ошибки")
                try:
                    shutil.copy2(backup_path, self.mmdb_path)
                except Exception as restore_error:
                    logger.error(f"Не удалось восстановить из бэкапа: {restore_error}")

            return False

    def export_mmdb_schema(self, service_info: 'MMDBDownloader.ServiceInfo') -> Optional[Path]:
        """Экспорт схемы полей MMDB базы в JSON файл"""
        try:
            # Получает все поля из тестовых примеров для анализа структуры базы
            all_fields_in_db = set()
            test_examples = self._generate_test_examples()

            # Собирает все поля из тестовых примеров
            for example in test_examples.values():
                if "all_fields" in example:
                    all_fields_in_db.update(example["all_fields"])

            schema_data = {
                "generated_by": "get_asn_mmdb.py",
                "generated_at": datetime.now().isoformat(),
                "service": service_info.name,
                "service_urls": service_info.urls,
                "database_file": str(self.mmdb_path),
                "database_size": self.mmdb_path.stat().st_size if self.mmdb_path.exists() else 0,

                # Ожидаемые поля MMDB в рамках системы
                "system_requirements": {
                    "required_fields": self.config["SYSTEM_REQUIRED_FIELDS"]
                },

                # Адаптация отличающихся полей MMDB
                "field_mapping": {},

                # Все поля, обнаруженные в базе
                "fields_in_database": sorted(list(all_fields_in_db)),

                # Примеры данных для проверки
                "test_examples": test_examples,
            }

            # Генерируем информацию о маппинге для каждого системного поля
            for system_field in self.config["SYSTEM_REQUIRED_FIELDS"]:
                mapping_info = self._find_field_in_service(service_info, system_field)
                schema_data["field_mapping"][system_field] = mapping_info

            # Путь для файла схемы (рядом с MMDB файлом)
            schema_path = self.mmdb_path.with_suffix('.schema.json')

            with open(schema_path, 'w', encoding='utf-8') as f:
                json.dump(schema_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Схема MMDB экспортирована в: {schema_path}")
            return schema_path

        except Exception as e:
            logger.error(f"Ошибка при экспорте схемы: {e}")
            return None

    def _find_field_in_service(self, service_info: 'MMDBDownloader.ServiceInfo', field_name: str) -> Dict:
        """Поиск информации о поле в конфигурации сервиса"""
        result = {
            "standard_name": field_name,
            "source_field": field_name,
            "mapped": False,
            "required": False
        }

        # Проверяет маппинг в конфигурации сервиса
        if field_name in service_info.field_mapping:
            result["source_field"] = service_info.field_mapping[field_name]
            result["mapped"] = True

        # Проверяет, является ли поле обязательным для системы
        result["required"] = field_name in self.config["SYSTEM_REQUIRED_FIELDS"]

        return result

    def _generate_test_examples(self) -> Dict:
        """Генерация тестовых примеров для проверки"""
        examples = {}

        if not self.mmdb_path.exists():
            return examples

        try:
            with maxminddb.open_database(str(self.mmdb_path)) as reader:
                test_ips = ["8.8.8.8", "1.1.1.1", "77.88.8.8"]

                for ip in test_ips:
                    data = reader.get(ip)
                    if data:
                        examples[ip] = {
                            "asn": data.get('asn', data.get('autonomous_system_number')),
                            "org": data.get('org', data.get('as_name', data.get('autonomous_system_organization'))),
                            "country_code": data.get('country_code', data.get('country')),
                            "domain": data.get('domain', data.get('as_domain')),
                            "all_fields": list(data.keys())  # все доступные поля для отладки
                        }
        except Exception as e:
            logger.debug(f"Не удалось сгенерировать тестовые примеры: {e}")

        return examples

def main():
    """Основная функция скрипта"""
    try:
        logger.info("\n")
        logger.info("=" * 62)
        logging.info("Запуск %s - скачивание и проверка MMDB базы", script_name)
        logger.info("=" * 62)
        logger.info(f"Текущая конфигурация:")

        # Логируем основные параметры
        for key, value in CONFIG.items():
            if key not in ["SERVICES", "DOWNLOAD_URLS", "SERVICE_MAPPINGS"]:
                logger.info(f"  {key}: {value}")

        # Логируем системные требования
        logger.info(f"  SYSTEM_REQUIRED_FIELDS: {CONFIG['SYSTEM_REQUIRED_FIELDS']}")

        # Логируем информацию о сервисах
        logger.info("  Настроенные сервисы:")
        for service_name, service_config in CONFIG["SERVICES"].items():
            urls_count = len(service_config["urls"])
            mapping = service_config.get("field_mapping", {})
            mapping_info = f", маппинг полей: {mapping}" if mapping else ""
            logger.info(f"    • {service_name}: URL источников: {urls_count}{mapping_info}")

        # Создание экземпляра загрузчика
        downloader = MMDBDownloader(CONFIG)

        # Запуск процесса скачивания и проверки
        success = downloader.download_and_validate()

        if success:
            logger.info("=" * 60)
            logger.info("Процесс обновления MMDB базы успешно завершен")
            logger.info("=" * 60)
            return 0
        else:
            logger.error("=" * 60)
            logger.error("Процесс обновления MMDB базы завершен с ошибками")
            logger.error("=" * 60)
            return 1

    except KeyboardInterrupt:
        logger.info("Скрипт прерван пользователем")
        return 130
    except Exception as e:
        logger.error(f"Ошибка в скрипте: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
