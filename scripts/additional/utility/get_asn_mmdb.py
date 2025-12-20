#!/usr/bin/env python3
"""
Скрипт для скачивания и проверки MMDB (ip-to-asn) базы ASN от iplocate.io
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

# Настройки скрипта
CONFIG = {
    # Ссылки для скачивания MMDB базы (в порядке возрастания приоритета)
    "DOWNLOAD_URLS": [
        "https://www.iplocate.io/download/ip-to-asn.mmdb?apikey=<YOUR_API_KEY>&variant=daily",  # оф. сайт сервиса IPLocate.io - требуется регистрация аккаунта. Вместо <YOUR_API_KEY> указать API Key из личного кабинета (после регистрации).
        "https://github.com/iplocate/ip-address-databases/raw/refs/heads/main/ip-to-asn/ip-to-asn.mmdb?download=",  # Официальный репозиторий
    ],

    # Пути для файлов
    "MMDB_DIR": Path("raw-data/ASN-db/"),  # Директория для MMDB файлов
    "BACKUP_DIR": Path("raw-data/ASN-db/backups"),  # Директория для бэкапов
    "MMDB_FILENAME": "ip-to-asn.mmdb",  # Имя MMDB файла

    # Параметры бэкапов
    "MAX_BACKUPS": 3,  # Максимальное количество хранимых бэкапов

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

    # Проверка структуры MMDB файла
    "EXPECTED_FIELDS": [
        "network",
        "asn",
        "country_code",
        "name",
        "org",
        "domain"
    ]
}

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


class MMDBDownloader:
    """Класс для скачивания и управления MMDB базой"""

    def __init__(self, config: Dict):
        self.config = config
        self.mmdb_path = config["MMDB_DIR"] / config["MMDB_FILENAME"]
        self.backup_dir = config["BACKUP_DIR"]

        # Создание необходимых директорий
        self.mmdb_path.parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

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

            # Удаление лишних бэкапов
            for backup in backups[self.config["MAX_BACKUPS"]:]:
                backup.unlink()
                logger.info(f"Удален старый бэкап: {backup}")

        except Exception as e:
            logger.error(f"Ошибка при очистке бэкапов: {e}")

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

                        # Логируем каждые N секунды
                        current_time = datetime.now()
                        time_since_last_log = (current_time - last_log_time).total_seconds()

                        if time_since_last_log >= 10.0:  # Каждые 10 секунды
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
                logger.info(f"✓ Загружено 100% ({self._format_size(total_size)})")

            logger.info(f"✓ Время загрузки: {elapsed_time:.1f} сек")

            return temp_path

        except Exception as e:
            logger.error(f"Ошибка скачивания MMDB - IPLocate: {e}")
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

    def validate_mmdb_structure(self, mmdb_path: Path) -> bool:
        """Проверка структуры MMDB файла"""
        if not mmdb_path.exists():
            logger.error(f"Файл для проверки не существует: {mmdb_path}")
            return False

        try:
            logger.info("Проверка структуры MMDB файла...")

            with maxminddb.open_database(str(mmdb_path)) as reader:
                # Тестирование IP для проверки структуры MMDB
                test_ips = [
                    "8.8.8.8",  # Google DNS
                    "1.1.1.1",  # Cloudflare
                    "77.88.8.8",  # Yandex
                    "208.67.222.222",  # OpenDNS
                ]

                valid_records = 0
                for ip in test_ips:
                    try:
                        data = reader.get(ip)
                        if data:
                            # Наличие ожидаемых полей
                            missing_fields = []
                            for field in self.config["EXPECTED_FIELDS"]:
                                if field not in data:
                                    missing_fields.append(field)

                            if not missing_fields:
                                valid_records += 1
                                logger.debug(f"IP {ip}: OK - {data.get('asn', 'N/A')} {data.get('name', 'N/A')}")
                            else:
                                logger.warning(f"IP {ip}: отсутствуют поля {missing_fields}")
                        else:
                            logger.debug(f"IP {ip}: нет данных в базе")

                    except Exception as e:
                        logger.warning(f"Ошибка при проверке IP {ip}: {e}")

                # Проверка успешна, если найдено хотя бы N валидных записи
                if valid_records >= 2: # 2 валидных записи
                    logger.info(f"Проверка структуры пройдена: {valid_records}/4 тестовых IP имеют корректную структуру")
                    return True
                else:
                    logger.error(f"Проверка структуры не пройдена: {valid_records}/4 тестовых IP имеют корректную структуру")
                    return False

        except Exception as e:
            logger.error(f"Ошибка при проверке MMDB файла: {e}")
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

        # Создание бэкапа текущего файла
        backup_path = self.create_backup()

        # Попытка скачивания из каждого источника
        downloaded_file = None
        download_url = None

        for url in self.config["DOWNLOAD_URLS"]:
            downloaded_file = self.download_mmdb(url)
            if downloaded_file:
                download_url = url
                logger.info(f"Успешно скачано из: {url}")
                break

        if not downloaded_file:
            logger.error("Не удалось скачать файл ни из одного источника")
            return False

        # Проверка структуры скачанного файла
        if not self.validate_mmdb_structure(downloaded_file):
            logger.error("Скачанный файл не прошел проверку структуры")

            # Если есть бэкап - восстанавливаем его
            if backup_path and backup_path.exists():
                logger.info("Восстановление файла бэкапа")
                shutil.copy2(backup_path, self.mmdb_path)

            downloaded_file.unlink()
            return False

        # Вычисление хэша нового файла
        new_file_hash = self.calculate_file_hash(downloaded_file)
        if new_file_hash:
            logger.info(f"SHA256 нового файла: {new_file_hash}")

        # Замена текущего файла новым
        try:
            # Удаляем старый файл если существует
            if self.mmdb_path.exists():
                self.mmdb_path.unlink()

            # Перемещаем временный файл на место основного
            shutil.move(downloaded_file, self.mmdb_path)

            logger.info(f"Файл успешно обновлен: {self.mmdb_path}")
            logger.info(f"Размер файла: {self.mmdb_path.stat().st_size} байт")

            # Проверяем хэш после перемещения
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


def main():
    """Основная функция скрипта"""
    try:
        logger.info("\n")
        logger.info("=" * 62)
        logging.info("Запуск %s - скачивание и проверка MMDB базы IPLocate", script_name)
        logger.info("=" * 62)
        logger.info(f"Текущая конфигурация:")
        for key, value in CONFIG.items():
            if key != "DOWNLOAD_URLS":
                logger.info(f"  {key}: {value}")

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
