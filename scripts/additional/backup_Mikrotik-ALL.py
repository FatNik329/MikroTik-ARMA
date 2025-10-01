#!/usr/bin/env python3
import paramiko
import logging
from pathlib import Path
from datetime import datetime
import sys
import socket

# ===== КОНФИГУРАЦИЯ СКРИПТА =====
# Учетные данные по умолчанию
DEFAULT_USERNAME = 'MyUsername'
DEFAULT_PASSWORD = 'MyPasswordUser'

# Настройки подключения
SSH_TIMEOUT = 30  # Таймаут подключения в секундах
DEFAULT_PORT = 22 # Порт SSH по умолчанию

# Индивидуальные учетные данные для конкретных устройств
# Формат: "IP": ("username", "password", SSH порт)
SPECIAL_CREDENTIALS = {
    "192.168.0.1": ("User1", "PasswordUser1"),
    "192.168.1.1": ("User2", "PasswordUser2"),
    "192.168.2.1": ("User3", "PasswordUser3"),
}


# Список устройств для резервного копирования
DEVICES = [
    "192.168.0.1",     # Device1
    "192.168.1.1",     # Device2
    "192.168.2.2",     # Device3
]

# Настройки резервного копирования
BACKUP_PATH = "/path/to/mikrotik/backup"  # Путь для сохранения бэкапов
BACKUP_MODE = "only"  # Режимы: "only" - единственный файл с перезаписью, "tmps" - с timestamp
COMMAND_EXPORT = "/export terse"  # Команда для выгрузки конфигурации. "/export", "/export terse", "/export verbose", "/export show-sensitive"

# Настройки логирования
script_name = Path(__file__).stem
log_filename = f"{script_name}.log"
log_path = Path(f'logs/additional/backup_Mikrotik/{log_filename}')
log_path.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)

# Уровень логирования Paramiko
logging.getLogger("paramiko").setLevel(logging.WARNING)

# ===== КОД СКРИПТА =====

class MikroTikBackup:
    def __init__(self, host, username, password, port=22, backup_path="./backups"):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.backup_path = Path(backup_path)
        self.ssh_client = None
        self.device_name = None

    def connect(self):
        """Установка SSH подключения к устройству"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            logging.info(f"Подключение к {self.host}:{self.port}")
            self.ssh_client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=SSH_TIMEOUT,
                look_for_keys=False,
                allow_agent=False
            )
            return True

        except paramiko.AuthenticationException:
            logging.error(f"Ошибка авторизации на устройстве {self.host}")
            return False
        except paramiko.SSHException as e:
            logging.error(f"SSH ошибка на {self.host}: {str(e)}")
            return False
        except socket.timeout:
            logging.error(f"Timeout подключения к {self.host}")
            return False
        except Exception as e:
            logging.error(f"Ошибка при подключении к {self.host}: {str(e)}")
            return False

    def get_device_name(self):
        """Получение имени устройства"""
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(':local DeviceName [/system identity get name]; :put $DeviceName')
            device_name = stdout.read().decode('utf-8').strip()

            if device_name:
                self.device_name = device_name
                logging.info(f"Имя устройства {self.host}: {device_name}")
                return True
            else:
                logging.warning(f"Не удалось получить имя устройства {self.host}")
                self.device_name = f"unknown_{self.host.replace('.', '_')}"
                return True

        except Exception as e:
            logging.error(f"Ошибка при получении имени устройства {self.host}: {str(e)}")
            self.device_name = f"error_{self.host.replace('.', '_')}"
            return False

    def is_valid_backup(self, file_path):
        """Проверка валидности бэкап-файла"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                first_lines = [f.readline().strip() for _ in range(6)]

            # Проверяем характерные признаки RSC файла MikroTik
            valid_indicators = [
                any('by RouterOS' in line for line in first_lines),  # версия ОС
                any('software id =' in line for line in first_lines),  # ID ПО
                any('serial number =' in line for line in first_lines) # серийный номер
            ]

            logging.debug(f"Проверка файла {file_path}:")
            logging.debug(f"  - by RouterOS: {valid_indicators[0]}")
            logging.debug(f"  - software id: {valid_indicators[1]}")
            logging.debug(f"  - serial number: {valid_indicators[2]}")

            # ВСЕ три условия должны быть True
            is_valid = all(valid_indicators)

            if is_valid:
                logging.debug(f"Бэкап валиден: обнаружены характерные признаки RouterOS")
            else:
                logging.error(f"Бэкап невалиден - отсутствуют характерные признаки RouterOS")
                logging.debug(f"Первые строки файла: {first_lines}")

            return is_valid

        except Exception as e:
            logging.error(f"Ошибка при проверке файла {file_path}: {str(e)}")
            return False

    def export_configuration(self):
        """Экспорт конфигурации устройства"""
        try:
            logging.info(f"Экспорт конфигурации {self.host}")

            # Выполнение команды export
            stdin, stdout, stderr = self.ssh_client.exec_command(COMMAND_EXPORT)
            config_data = stdout.read().decode('utf-8')

            if not config_data:
                logging.error(f"Пустой ответ от устройства {self.host}")
                return False

            # Создание директории для бэкапов с именем устройства
            device_backup_path = self.backup_path / self.device_name
            device_backup_path.mkdir(parents=True, exist_ok=True)

            # Формирование имени файла в зависимости от режима
            if BACKUP_MODE == "only":
                filename = f"{self.device_name}.rsc"
            else:  # режим "tmps"
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{self.device_name}_{timestamp}.rsc"

            file_path = device_backup_path / filename

            # Сохранение конфигурации в файл
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(config_data)

            # Проверка валидности бэкапа
            if self.is_valid_backup(file_path):
                logging.info(f"Конфигурация сохранена и проверена: {file_path}")
                return True
            else:
                logging.error(f"Бэкап файл невалиден: {file_path}")
                # Удаляем невалидный файл
              #  try:
              #      file_path.unlink()
              #  except:
              #      pass
                return False

        except Exception as e:
            logging.error(f"Ошибка при экспорте конфигурации {self.host}: {str(e)}")
            return False

    def backup(self):
        """Основной метод выполнения бэкапа"""
        logging.info(f"--- Начало бэкапа устройства {self.host} ---")

        if not self.connect():
            return False

        try:
            if not self.get_device_name():
                return False

            if not self.export_configuration():
                return False

            return True

        finally:
            self.disconnect()

    def disconnect(self):
        """Закрытие SSH подключения"""
        if self.ssh_client:
            self.ssh_client.close()
            logging.info(f"Отключение от {self.host}")

def main():
    """Основная функция скрипта"""
    logging.info("\n=== Запуск %s - резервное копирование MikroTik (RSC) ===", script_name)

    logging.info(f"Количество устройств для бэкапа: {len(DEVICES)}")
    logging.info(f"Путь сохранения бэкапов: {BACKUP_PATH}")
    logging.info(f"Режим бэкапа: {BACKUP_MODE}")
    logging.info(f"Команда экспорта: {COMMAND_EXPORT}")

    successful_backups = 0
    failed_backups = 0

    for device_ip in DEVICES:
        try:
            # Проверяем, есть ли индивидуальные учетные данные для устройства
            if device_ip in SPECIAL_CREDENTIALS:
                creds = SPECIAL_CREDENTIALS[device_ip]
                username = creds[0]
                password = creds[1]
                port = creds[2] if len(creds) > 2 else DEFAULT_PORT
                logging.info(f"Используются индивидуальные учетные данные для {device_ip} (порт: {port})")
            else:
                username = DEFAULT_USERNAME
                password = DEFAULT_PASSWORD
                port = DEFAULT_PORT
                logging.info(f"Используются учетные данные по умолчанию для {device_ip}")

            backup_manager = MikroTikBackup(
                host=device_ip,
                username=username,
                password=password,
                port=port,
                backup_path=BACKUP_PATH
            )

            if backup_manager.backup():
                successful_backups += 1
            else:
                failed_backups += 1

        except Exception as e:
            logging.error(f"Критическая ошибка при работе с {device_ip}: {str(e)}")
            failed_backups += 1

    # Итоговая статистика
    logging.info("--- Статистика выполнения ---")
    logging.info(f"Успешные бэкапы: {successful_backups}")
    logging.info(f"Неудачные бэкапы: {failed_backups}")
    logging.info(f"Всего устройств: {len(DEVICES)}")

    if failed_backups == 0:
        logging.info("Все бэкапы выполнены успешно")
        logging.info("=== Выполнение завершено ===")
        return 0
    else:
        logging.warning(f"Имеются неудачные бэкапы: {failed_backups}")
        logging.info("=== Выполнение завершено ===")
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logging.info("Скрипт прерван пользователем")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"Непредвиденная ошибка: {str(e)}")
        sys.exit(1)
