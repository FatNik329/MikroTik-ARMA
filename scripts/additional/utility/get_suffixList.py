#!/usr/bin/env python3
"""
Скрипт для скачивания и обновления Public Suffix List
Источники:
1. https://publicsuffix.org/list/public_suffix_list.dat (основной)
2. https://github.com/publicsuffix/list/blob/main/public_suffix_list.dat (резервный)
"""

import sys
import json
import hashlib
import shutil
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Optional
from abc import ABC, abstractmethod
import logging

# ==================== НАСТРОЙКИ ====================
CONFIG = {
    # Основные директории
    "DATA_DIR": Path("raw-data/path/to/public-suffix-list"),           # Директория для файлов
    "BACKUP_DIR": Path("raw-data/path/to/backups"),                    # Директория для бэкапов
    "LOG_DIR": Path("logs/additional/get_public_suffix_list"),        # Директория для логов

    # Настройки TTL (в минутах)
    "TTL_MINUTES": 3600,     # TTL для public_suffix_list.dat

    # Общие настройки
    "MAX_BACKUPS": 3,              # Максимальное количество бэкапов
    "DOWNLOAD_TIMEOUT": 30,        # Таймаут скачивания в секундах
    "MIN_FILE_SIZE": 51200,        # Минимальный размер файла в байтах (50KB)
    "LOG_LEVEL": "INFO",           # Уровень логирования (DEBUG, INFO, WARNING, ERROR)

    # Настройки User-Agent (изменить под себя)
    "USER_AGENT": "Mozilla/5.0 (compatible; PublicSuffixList-Updater/1.0; my-email@gmail.com)",

    # Источники данных
    "PRIMARY_URL": "https://publicsuffix.org/list/public_suffix_list.dat",
    "BACKUP_URL": "https://raw.githubusercontent.com/publicsuffix/list/main/public_suffix_list.dat",

    # Имя файла
    "FILENAME": "public_suffix_list.dat",
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

            # Ротация бэкапов
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


# ==================== КЛАСС ДЛЯ РАБОТЫ С PUBLIC SUFFIX LIST ====================

class PublicSuffixService:
    """Класс для работы с Public Suffix List"""

    def __init__(self, file_manager: FileManager):
        self.file_manager = file_manager
        self.primary_url = CONFIG["PRIMARY_URL"]
        self.backup_url = CONFIG["BACKUP_URL"]

    def _get_headers(self) -> Dict[str, str]:
        """Получение HTTP заголовков для запросов"""
        headers = {}

        if CONFIG.get("USER_AGENT"):
            headers["User-Agent"] = CONFIG["USER_AGENT"]
            logger.debug(f"Используется User-Agent: {CONFIG['USER_AGENT']}")
        else:
            logger.warning("User-Agent не настроен! Некоторые сервисы могут блокировать запросы.")

        return headers

    def _download_file(self, url: str, target_path: Path, source_type: str) -> bool:
        """Метод для скачивания файла"""
        try:
            logger.info(f"Скачивание из источника: {source_type} ({url})")

            headers = self._get_headers()
            response = requests.get(
                url,
                timeout=CONFIG["DOWNLOAD_TIMEOUT"],
                stream=True,
                headers=headers
            )
            response.raise_for_status()

            content_type = response.headers.get('content-type', '')
            if 'text/html' in content_type.lower():
                logger.error(f"Сервер вернул HTML вместо данных. Возможно, URL недоступен.")
                logger.error(f"Content-Type: {content_type}")
                return False

            total_size = int(response.headers.get('content-length', 0))
            if total_size > 0:
                logger.info(f"Общий размер файла: {total_size / 1024:.2f} KB")

            downloaded = 0
            with open(target_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100
                            if percent % 10 < 0.1:
                                logger.info(f" Загружено {percent:.0f}% ({downloaded / 1024:.2f} KB)")

            logger.info(f"Успешно скачано из источника: {source_type}")
            return True

        except requests.RequestException as e:
            logger.error(f"Ошибка при скачивании {url}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"HTTP статус: {e.response.status_code}")
                if e.response.status_code == 403:
                    logger.error("Доступ запрещен (403). Проверьте User-Agent.")
                elif e.response.status_code == 404:
                    logger.error("Файл не найден (404). Возможно, URL изменился.")
                elif e.response.status_code == 429:
                    logger.error("Слишком много запросов (429). Увеличьте TTL.")
            return False
        except Exception as e:
            logger.error(f"Неожиданная ошибка при скачивании: {e}")
            return False

    def download_public_suffix_list(self, target_path: Path) -> bool:
        """
        Скачивание Public Suffix List с приоритетом:
        1. Основной источник (publicsuffix.org)
        2. Резервный источник (GitHub)
        """
        # Скачивание с основного источника
        if self._download_file(self.primary_url, target_path, "PRIMARY (publicsuffix.org)"):
            return True

        logger.warning("Не удалось скачать с основного источника. Пробуем резервный (GitHub)...")

        # Скачивание с резервного источника
        if self._download_file(self.backup_url, target_path, "BACKUP (GitHub)"):
            return True

        logger.error("Не удалось скачать файл ни с одного источника")
        return False

    def validate_public_suffix_list(self, file_path: Path) -> bool:
        """Валидация Public Suffix List файла"""
        try:
            # Проверка содержимого файла
            if file_path.stat().st_size < CONFIG["MIN_FILE_SIZE"]:
                logger.error(f"Файл слишком маленький: {file_path.stat().st_size} байт")
                return False

            lines_checked = 0
            has_version = False
            has_icann_section = False

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read(5000)

                if '<!DOCTYPE html>' in content or '<html' in content:
                    logger.error("Файл содержит HTML, а не ожидаемые данные")
                    return False

                # Проверка наличия комментариев с версией
                if '// VERSION:' in content:
                    has_version = True
                    logger.debug("Найдена строка с версией")

                # Проверка наличия секции ICANN
                if '// ===BEGIN ICANN DOMAINS===' in content:
                    has_icann_section = True
                    logger.debug("Найдена секция ICANN DOMAINS")

                f.seek(0)
                for i, line in enumerate(f):
                    if i >= 20:  # Проверка первых 20 строк
                        break

                    line = line.strip()
                    if line and not line.startswith('//'):
                        if any(c.isalpha() for c in line):
                            lines_checked += 1

            if not has_version:
                logger.warning("Не найдена строка с версией в файле")

            if not has_icann_section:
                logger.warning("Не найдена секция ICANN DOMAINS в файле")

            if lines_checked == 0:
                logger.error("Файл не содержит строк с доменами/правилами")
                return False

            logger.info(f"Проверка структуры пройдена: найдены версия={has_version}, ICANN секция={has_icann_section}, проверено строк={lines_checked}")
            return True

        except UnicodeDecodeError as e:
            logger.error(f"Ошибка кодировки файла: {e}")
            return False
        except Exception as e:
            logger.error(f"Ошибка при валидации Public Suffix List: {e}")
            return False


# ==================== ОСНОВНОЙ КЛАСС ПРИЛОЖЕНИЯ ====================

class PublicSuffixUpdater:
    """Основной класс для обновления Public Suffix List"""

    def __init__(self):
        self.file_manager = FileManager(
            data_dir=CONFIG["DATA_DIR"],
            backup_dir=CONFIG["BACKUP_DIR"],
            max_backups=CONFIG["MAX_BACKUPS"]
        )
        self.service = PublicSuffixService(self.file_manager)

    def update_public_suffix_list(self) -> bool:
        """Обновление Public Suffix List"""
        filename = CONFIG["FILENAME"]
        file_path = CONFIG["DATA_DIR"] / filename

        logger.info("Обновление Public Suffix List из источников:")
        logger.info(f"  PRIMARY: {CONFIG['PRIMARY_URL']}")
        logger.info(f"  BACKUP:  {CONFIG['BACKUP_URL']}")

        # Проверка TTL
        if self.file_manager.is_fresh(file_path, CONFIG["TTL_MINUTES"]):
            logger.info(f"Файл {filename} актуален (возраст менее {CONFIG['TTL_MINUTES']} мин), пропуск скачивания")
            return True

        # Создание бэкапа
        backup_path = self.file_manager.create_backup(file_path)

        # Скачивание файла (с приоритетом основного источника)
        if not self.service.download_public_suffix_list(file_path):
            logger.error(f"Не удалось скачать {filename}")
            if backup_path:
                logger.info("Восстановление предыдущей версии из бэкапа")
                self.file_manager.restore_backup(file_path)
            return False

        # Проверка минимального размера
        if file_path.stat().st_size < CONFIG["MIN_FILE_SIZE"]:
            logger.error(f"Файл недостаточного размера: {file_path.stat().st_size} байт (мин: {CONFIG['MIN_FILE_SIZE']})")
            if backup_path:
                logger.info("Восстановление предыдущей версии из бэкапа")
                self.file_manager.restore_backup(file_path)
            return False

        # Валидация файла
        if not self.service.validate_public_suffix_list(file_path):
            logger.error(f"Валидация {filename} не пройдена")
            if backup_path:
                logger.info("Восстановление предыдущей версии из бэкапа")
                self.file_manager.restore_backup(file_path)
            return False

        # Сохранение контрольной суммы
        self.file_manager.save_checksum(file_path, "public_suffix_list")

        logger.info(f"Файл {filename} успешно обновлен")
        return True

    def run(self) -> bool:
        """Запуск процесса обновления"""
        logger.info("=" * 73)
        logger.info("Запуск get_public_suffix_list - получение Public Suffix List")
        logger.info("=" * 73)

        # Вывод конфигурации
        logger.info("Текущая конфигурация:")
        logger.info(f"  DATA_DIR: {CONFIG['DATA_DIR']}")
        logger.info(f"  BACKUP_DIR: {CONFIG['BACKUP_DIR']}")
        logger.info(f"  TTL: {CONFIG['TTL_MINUTES']} мин")
        logger.info(f"  MAX_BACKUPS: {CONFIG['MAX_BACKUPS']}")
        logger.info(f"  PRIMARY_URL: {CONFIG['PRIMARY_URL']}")
        logger.info(f"  BACKUP_URL: {CONFIG['BACKUP_URL']}")
        logger.info(f"  FILENAME: {CONFIG['FILENAME']}")
        logger.info(f"  DOWNLOAD_TIMEOUT: {CONFIG['DOWNLOAD_TIMEOUT']} сек")
        logger.info(f"  MIN_FILE_SIZE: {CONFIG['MIN_FILE_SIZE']} байт")
        logger.info(f"  USER_AGENT: {CONFIG['USER_AGENT']}")
        logger.info("=" * 73)

        success = self.update_public_suffix_list()

        # Итоговый вывод
        logger.info("=" * 58)
        if success:
            logger.info("Процесс обновления Public Suffix List успешно завершен")
        else:
            logger.warning("Процесс обновления завершен с ошибками")
            logger.warning("  - Не удалось обновить Public Suffix List")
        logger.info("=" * 58)

        return success


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

    if CONFIG["USER_AGENT"] == "Mozilla/5.0 (compatible; PublicSuffixList-Updater/1.0; +https://example.com)":
        logger.warning("=" * 60)
        logger.warning("ВНИМАНИЕ: Используется стандартный User-Agent.")
        logger.warning("Рекомендуется заменить USER_AGENT в конфигурации на свои данные:")
        logger.warning('USER_AGENT: "Mozilla/5.0 (compatible; YourCompany-Updater/1.0; +https://yourcompany.com)"')
        logger.warning("=" * 60)

    try:
        updater = PublicSuffixUpdater()
        success = updater.run()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.info("Процесс прерван пользователем")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}", exc_info=True)
        sys.exit(1)
