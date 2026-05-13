#!/usr/bin/env python3
"""
Скрипт для скачивания и обновления данных о ASN (ASN Name export) и префиксах (Table visibility export)  с bgp.tools
"""

import sys
import json
import csv
import hashlib
import shutil
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from abc import ABC, abstractmethod
import logging

# ==================== НАСТРОЙКИ ====================
CONFIG = {
    # Основные директории
    "DATA_DIR": Path("raw-data/exampleData"),           # Директория для файлов
    "BACKUP_DIR": Path("raw-data/exampleData/backups"),          # Директория для бэкапов
    "LOG_DIR": Path("logs/additional/get_asn_prefixes"),    # Директория для логов

    # Настройки TTL (в минутах)
    "TABLE_TTL_MINUTES": 300,     # TTL для table.jsonl
    "ASNS_TTL_MINUTES": 1440,     # TTL для asns.csv

    # Общие настройки
    "MAX_BACKUPS": 3,             # Максимальное количество бэкапов
    "DOWNLOAD_TIMEOUT": 30,        # Таймаут скачивания в секундах
    "MIN_FILE_SIZE": 1024,         # Минимальный размер файла в байтах (1KB)
    "LOG_LEVEL": "INFO",           # Уровень логирования (DEBUG, INFO, WARNING, ERROR)

    # Настройки User-Agent (обязательно для bgp.tools)
    "USER_AGENT": "MikroTik-ARMA - bgp.tools - example@gmail.com",  # !Заменить на свои данные
}

# ==================== КЛАССЫ ДЛЯ РАБОТЫ С ФАЙЛАМИ ====================

class FileManager:
    """Класс для управления файлами, бэкапами и проверкой целостности"""

    def __init__(self, data_dir: Path, backup_dir: Path, max_backups: int):
        self.data_dir = data_dir
        self.backup_dir = backup_dir
        self.max_backups = max_backups
        self.checksum_file = data_dir / "checksums.json"

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        self.checksums = self._load_checksums()

    def _load_checksums(self) -> Dict:
        """Загрузка сохраненных контрольных сумм"""
        if self.checksum_file.exists():
            try:
                with open(self.checksum_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Не удалось загрузить файл контрольных сумм: {e}")
        return {}

    def _save_checksums(self):
        """Сохранение контрольных сумм"""
        try:
            with open(self.checksum_file, 'w') as f:
                json.dump(self.checksums, f, indent=2)
        except Exception as e:
            logger.warning(f"Не удалось сохранить контрольные суммы: {e}")

    def get_file_checksum(self, file_path: Path) -> str:
        """Вычисление SHA256 контрольной суммы файла"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Ошибка при вычислении контрольной суммы {file_path}: {e}")
            return ""

    def create_backup(self, file_path: Path) -> Optional[Path]:
        """Создание бэкапа файла"""
        if not file_path.exists():
            logger.debug(f"Файл {file_path} не существует, бэкап не создан")
            return None

        timestamp = datetime.now().strftime("%d-%m-%Y-%H%M%S")
        backup_path = self.backup_dir / f"{timestamp}-{file_path.name}"

        try:
            shutil.copy2(file_path, backup_path)
            logger.info(f"Создан бэкап: {backup_path}")

            # Очистка старых бэкапов
            self._cleanup_old_backups(file_path.name)

            return backup_path
        except Exception as e:
            logger.error(f"Ошибка при создании бэкапа {file_path}: {e}")
            return None

    def _cleanup_old_backups(self, filename: str):
        """Очистка старых бэкапов для конкретного файла"""
        backups = sorted(self.backup_dir.glob(f"*-{filename}"))
        if len(backups) > self.max_backups:
            for old_backup in backups[:-self.max_backups]:
                old_backup.unlink()
                logger.debug(f"Удален старый бэкап: {old_backup}")

    def restore_backup(self, file_path: Path) -> bool:
        """Восстановление последнего бэкапа файла"""
        backups = sorted(self.backup_dir.glob(f"*-{file_path.name}"))

        if not backups:
            logger.warning(f"Нет доступных бэкапов для {file_path.name}")
            return False

        latest_backup = backups[-1]
        try:
            shutil.copy2(latest_backup, file_path)
            logger.info(f"Восстановлен бэкап: {latest_backup} -> {file_path}")
            return True
        except Exception as e:
            logger.error(f"Ошибка при восстановлении бэкапа: {e}")
            return False

    def verify_checksum(self, file_path: Path, file_type: str) -> bool:
        """Проверка контрольной суммы файла"""
        if file_type not in self.checksums:
            logger.debug(f"Нет сохраненной контрольной суммы для {file_type}")
            return True

        current_checksum = self.get_file_checksum(file_path)
        if not current_checksum:
            return False

        if current_checksum == self.checksums[file_type]:
            logger.info(f"Целостность файла подтверждена (хэши совпадают)")
            return True
        else:
            logger.warning(f"Контрольная сумма не совпадает. Ожидание: {self.checksums[file_type][:16]}..., Получено: {current_checksum[:16]}...")
            return False

    def save_checksum(self, file_path: Path, file_type: str):
        """Сохранение контрольной суммы файла"""
        checksum = self.get_file_checksum(file_path)
        if checksum:
            self.checksums[file_type] = checksum
            self._save_checksums()
            logger.info(f"SHA256 нового файла: {checksum}")

    def is_fresh(self, file_path: Path, ttl_minutes: int) -> bool:
        """Проверка, является ли файл свежим (не старше TTL)"""
        if not file_path.exists():
            return False

        file_age = datetime.now() - datetime.fromtimestamp(file_path.stat().st_mtime)
        is_fresh = file_age < timedelta(minutes=ttl_minutes)

        if is_fresh:
            age_hours = file_age.total_seconds() / 3600
            logger.debug(f"Файл {file_path.name} свежий (возраст: {age_hours:.1f} часов)")

        return is_fresh


# ==================== КЛАСС ДЛЯ РАБОТЫ С BGP.TOOLS ====================

class BGPToolsService:
    """Класс для работы с сервисом bgp.tools"""

    def __init__(self, file_manager: FileManager):
        self.file_manager = file_manager
        self.urls = {
            "prefixes": "https://bgp.tools/table.jsonl",
            "asns": "https://bgp.tools/asns.csv"
        }

    def _get_headers(self) -> Dict[str, str]:
        """Получение HTTP заголовков для запросов"""
        headers = {}

        if CONFIG.get("USER_AGENT"):
            headers["User-Agent"] = CONFIG["USER_AGENT"]
            logger.debug(f"Используется User-Agent: {CONFIG['USER_AGENT']}")
        else:
            logger.warning("User-Agent не настроен! Сервис может блокировать запросы.")

        return headers

    def _download_file(self, url: str, target_path: Path, file_type: str) -> bool:
        """Метод для скачивания файла"""
        try:
            logger.info(f"Скачивание из: {url}")

            headers = self._get_headers()
            response = requests.get(
                url,
                timeout=CONFIG["DOWNLOAD_TIMEOUT"],
                stream=True,
                headers=headers
            )
            response.raise_for_status()

            content_type = response.headers.get('content-type', '')
            if 'text/html' in content_type and file_type in ['jsonl', 'csv']:
                logger.error(f"Сервер вернул HTML вместо {file_type}. Возможно, запрос заблокирован из-за неправильного User-Agent.")
                logger.error(f"Content-Type: {content_type}")
                return False

            total_size = int(response.headers.get('content-length', 0))
            if total_size > 0:
                logger.info(f"Общий размер файла: {total_size / (1024*1024):.2f} MB")

            downloaded = 0
            with open(target_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            if percent % 10 < 0.1:
                                logger.info(f" Загружено {percent:.0f}% ({downloaded / (1024*1024):.2f} MB)")

            logger.info(f"Успешно скачано из сервиса: bgp.tools")
            return True

        except requests.RequestException as e:
            logger.error(f"Ошибка при скачивании {url}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"HTTP статус: {e.response.status_code}")
                if e.response.status_code == 403:
                    logger.error("Доступ запрещен (403). Проверьте User-Agent.")
                elif e.response.status_code == 429:
                    logger.error("Слишком много запросов (429). Увеличьте TTL файлов.")
            return False
        except Exception as e:
            logger.error(f"Неожиданная ошибка при скачивании: {e}")
            return False

    def download_prefixes(self, target_path: Path) -> bool:
        """Скачивание table.jsonl"""
        return self._download_file(self.urls["prefixes"], target_path, "jsonl")

    def download_asns(self, target_path: Path) -> bool:
        """Скачивание asns.csv"""
        return self._download_file(self.urls["asns"], target_path, "csv")

    def validate_prefixes(self, file_path: Path) -> bool:
        """Валидация JSONL файла с префиксами"""
        try:
            required_fields = ['CIDR', 'ASN']
            line_count = 0

            with open(file_path, 'r', encoding='utf-8') as f:
                first_line = f.readline()
                if '<!DOCTYPE html>' in first_line or '<html' in first_line:
                    logger.error("Файл содержит HTML, а не ожидаемые данные.")
                    return False
                f.seek(0)

                for i, line in enumerate(f):
                    if i >= 10:
                        break

                    if not line.strip():
                        continue

                    try:
                        data = json.loads(line)
                        for field in required_fields:
                            if field not in data:
                                logger.error(f"Отсутствует обязательное поле '{field}' в строке {i+1}")
                                return False
                        line_count += 1
                    except json.JSONDecodeError as e:
                        logger.error(f"Ошибка парсинга JSON в строке {i+1}: {e}")
                        return False

            if line_count == 0:
                logger.error("Файл не содержит валидных JSON строк")
                return False

            logger.info(f"Проверка структуры пройдена: {line_count}/10 строк соответствуют требованиям")
            return True

        except Exception as e:
            logger.error(f"Ошибка при валидации prefixes файла: {e}")
            return False

    def validate_asns(self, file_path: Path) -> bool:
        """Валидация CSV файла с ASN"""
        try:
            required_fields = ['asn', 'name', 'class', 'cc']
            row_count = 0

            with open(file_path, 'r', encoding='utf-8') as f:
                first_line = f.readline()
                if '<!DOCTYPE html>' in first_line or '<html' in first_line:
                    logger.error("Файл содержит HTML, а не ожидаемые данные.")
                    return False
                f.seek(0)

                reader = csv.DictReader(f)

                if not all(field in reader.fieldnames for field in required_fields):
                    missing = [f for f in required_fields if f not in reader.fieldnames]
                    logger.error(f"Отсутствуют обязательные колонки в CSV: {missing}")
                    return False

                for i, row in enumerate(reader):
                    if i >= 10:
                        break

                    if not row.get('asn') or not row.get('name'):
                        logger.error(f"Пустые значения в строке {i+1}: asn='{row.get('asn')}', name='{row.get('name')}'")
                        return False

                    row_count += 1

            if row_count == 0:
                logger.error("CSV файл не содержит данных")
                return False

            logger.info(f"Проверка структуры пройдена: проверено {row_count} записей")
            return True

        except Exception as e:
            logger.error(f"Ошибка при валидации ASN файла: {e}")
            return False


# ==================== ОСНОВНОЙ КЛАСС ПРИЛОЖЕНИЯ ====================

class ASNPrefixesUpdater:
    """Основной класс для обновления данных ASN и префиксов"""

    def __init__(self):
        self.file_manager = FileManager(
            data_dir=CONFIG["DATA_DIR"],
            backup_dir=CONFIG["BACKUP_DIR"],
            max_backups=CONFIG["MAX_BACKUPS"]
        )
        self.service = BGPToolsService(self.file_manager)

    def _update_file(self, file_type: str, filename: str, ttl_minutes: int,
                     validator_func, downloader_func) -> bool:
        """Универсальный метод для обновления файла"""
        file_path = CONFIG["DATA_DIR"] / filename

        # Проверяет TTL
        if self.file_manager.is_fresh(file_path, ttl_minutes):
            logger.info(f"Файл {filename} актуален (возраст менее {ttl_minutes} мин), пропуск скачиваниея")
            return True

        # Создает бэкап
        backup_path = self.file_manager.create_backup(file_path)

        # Скачивает новый файл
        if not downloader_func(file_path):
            logger.error(f"Не удалось скачать {filename}")
            if backup_path:
                logger.info("Восстанавление предыдущей версии из бэкапа")
                self.file_manager.restore_backup(file_path)
            return False

        # Проверяет минимальный размер
        if file_path.stat().st_size < CONFIG["MIN_FILE_SIZE"]:
            logger.error(f"Файл недостаточного размера: {file_path.stat().st_size} байт (мин: {CONFIG['MIN_FILE_SIZE']})")
            if backup_path:
                logger.info("Восстанавление предыдущей версии из бэкапа")
                self.file_manager.restore_backup(file_path)
            return False

        # Валидирует файл
        if not validator_func(file_path):
            logger.error(f"Валидация {filename} не пройдена")
            if backup_path:
                logger.info("Восстанавление предыдущей версии из бэкапа")
                self.file_manager.restore_backup(file_path)
            return False

        # Сохраняет контрольную сумму
        self.file_manager.save_checksum(file_path, file_type)

        logger.info(f"Файл {filename} успешно обновлен")
        return True

    def update_prefixes(self) -> bool:
        """Обновление данных о префиксах"""
        logger.info("Обновление данных о префиксах из сервиса: bgp.tools")

        return self._update_file(
            file_type="prefixes",
            filename="table.jsonl",
            ttl_minutes=CONFIG["TABLE_TTL_MINUTES"],
            validator_func=self.service.validate_prefixes,
            downloader_func=self.service.download_prefixes
        )

    def update_asns(self) -> bool:
        """Обновление данных об ASN"""
        logger.info("Обновление данных об ASN из сервиса: bgp.tools")

        return self._update_file(
            file_type="asns",
            filename="asns.csv",
            ttl_minutes=CONFIG["ASNS_TTL_MINUTES"],
            validator_func=self.service.validate_asns,
            downloader_func=self.service.download_asns
        )

    def run(self) -> bool:
        """Запуск процесса обновления"""
        logger.info("=" * 73)
        logger.info("Запуск get_asn_prefixes - получение данных об ASN и префиксах (bgp.tools)")
        logger.info("=" * 73)

        # Вывод конфигурации
        logger.info("Текущая конфигурация:")
        logger.info(f"  DATA_DIR: {CONFIG['DATA_DIR']}")
        logger.info(f"  BACKUP_DIR: {CONFIG['BACKUP_DIR']}")
        logger.info(f"  TABLE_TTL: {CONFIG['TABLE_TTL_MINUTES']} мин")
        logger.info(f"  ASNS_TTL: {CONFIG['ASNS_TTL_MINUTES']} мин")
        logger.info(f"  MAX_BACKUPS: {CONFIG['MAX_BACKUPS']}")
        logger.info(f"  DOWNLOAD_TIMEOUT: {CONFIG['DOWNLOAD_TIMEOUT']} сек")
        logger.info(f"  MIN_FILE_SIZE: {CONFIG['MIN_FILE_SIZE']} байт")
        logger.info(f"  USER_AGENT: {CONFIG['USER_AGENT']}")
        logger.info("=" * 73)

        prefixes_success = self.update_prefixes()
        asns_success = self.update_asns()

        # Итоговый вывод
        logger.info("=" * 58)
        if prefixes_success and asns_success:
            logger.info("Процесс обновления данных ASN и префиксов успешно завершен")
        else:
            logger.warning("Процесс обновления завершен с ошибками")
            if not prefixes_success:
                logger.warning("  - Не удалось обновить данные о префиксах")
            if not asns_success:
                logger.warning("  - Не удалось обновить данные об ASN")
        logger.info("=" * 58)

        return prefixes_success and asns_success


# ==================== ТОЧКА ВХОДА ====================

if __name__ == "__main__":
    # Настройка логирования
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

    # Проверка настройки User-Agent
    if CONFIG["USER_AGENT"] in ["MikroTik-ARMA - bgp.tools - example@gmail.com", ""]:
        logger.warning("=" * 60)
        logger.warning("ВНИМАНИЕ: Используется стандартный User-Agent.")
        logger.warning("Замените USER_AGENT в конфигурации на свои данные:")
        logger.warning('USER_AGENT: "yourcompany bgp.tools - contact@yourcompany.com"')
        logger.warning("=" * 60)

    # Запуск основного процесса
    try:
        updater = ASNPrefixesUpdater()
        success = updater.run()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.info("Процесс прерван пользователем")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}", exc_info=True)
        sys.exit(1)
