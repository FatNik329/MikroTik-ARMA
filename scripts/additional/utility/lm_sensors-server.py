#!/usr/bin/env python3
"""
Скрипт для мониторинга температуры серверов через lm_sensors (должен быть установлен на проверяемом хосте).
Автоматически определяет критические компоненты (CPU, GPU, Memory, SSD/HDD)
и проверяет их температуру на предмет превышения пороговых значений.
"""

import logging
import paramiko
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# ===== КОНФИГУРАЦИЯ СКРИПТА =====

# Учетные данные по умолчанию
DEFAULT_USERNAME = 'MyUsername'
DEFAULT_PASSWORD = 'MyPasswordUser'

# Настройки подключения
SSH_TIMEOUT = 6  # Таймаут подключения в секундах
DEFAULT_PORT = 22  # Порт SSH по умолчанию

# Критические температурные пороги по умолчанию (в градусах Цельсия),
DEFAULT_TEMP_THRESHOLDS = {
    'cpu': 65.0,      # Процессор
    'gpu': 65.0,      # Видеокарта
    'memory': 65.0,   # Память
    'ssd': 65.0,      # SSD
    'nvme': 65.0,     # NVMe
    'general': 70.0   # Общий порог для неизвестных компонентов
}

# Индивидуальные учетные данные для конкретных устройств
# Формат: "IP": ("username", "password", SSH порт) - порт можно не указывать
SPECIAL_CREDENTIALS = {
    "192.168.0.100": ("User1", "PassUser1"),
    "192.168.100.1": ("User2", "PassUser2"),
}

# Список устройств для мониторинга
DEVICES = [
    "192.168.0.100", # Server1 - example
    "192.168.100.1", # Server2 - example
]

# ===== НАСТРОЙКА ЛОГИРОВАНИЯ =====

script_name = Path(__file__).stem
log_filename = f"{script_name}.log"
log_path = Path(f'logs/additional/lm_sensors/{log_filename}')
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

logger = logging.getLogger(__name__)

# ===== КЛАСС ДЛЯ ОБРАБОТКИ ДАТЧИКОВ =====

class TemperatureMonitor:
    def __init__(self, thresholds: Dict[str, float] = None):
        self.thresholds = thresholds or DEFAULT_TEMP_THRESHOLDS
        # Паттерны для идентификации компонентов
        self.component_patterns = {
            'cpu': ['k10temp', 'coretemp', 'cpu', 'Tctl', 'acpitz'],
            'gpu': ['amdgpu', 'nvidia', 'gpu', 'edge', 'vddgfx'],
            'memory': ['spd5118', 'dimm', 'mem', 'memory'],
            'nvme': ['nvme', 'Composite'],
            'ssd': ['ssd', 'sata'],
            'network': ['r8169', 'net', 'eth', 'lan']
        }

    def classify_component(self, sensor_name: str, value_name: str) -> str:
        """Классифицирует компонент по имени датчика и значения"""
        sensor_lower = sensor_name.lower()
        value_lower = value_name.lower()

        for comp_type, patterns in self.component_patterns.items():
            for pattern in patterns:
                if pattern.lower() in sensor_lower or pattern.lower() in value_lower:
                    return comp_type

        return 'general'

    def parse_sensors_output(self, output: str) -> List[Dict]:
        """Парсит вывод команды sensors и возвращает структурированные данные"""
        sensors_data = []
        current_sensor = None

        for line in output.split('\n'):
            line = line.strip()

            # Пропускаем пустые строки и разделители
            if not line or line.startswith('---') or line == 'Adapter:' or 'Adapter:' in line:
                continue

            # Обнаружение нового датчика (строка без двоеточия в начале)
            if not line.startswith(' ') and ':' not in line:
                if current_sensor:
                    sensors_data.append(current_sensor)
                current_sensor = {'name': line, 'values': {}}
                continue

            # Если у нас есть текущий датчик, парсим значения температуры
            if current_sensor:
                # Обрабатываем строки с температурными значениями (содержат + и C)
                if ':' in line and any(x in line for x in ['+', '°C']) and 'C' in line:
                    try:
                        key_part, value_part = line.split(':', 1)
                        key = key_part.strip()
                        value_text = value_part.strip()

                        # Извлекаем числовое значение температуры
                        temp_value = self.extract_temperature(value_text)
                        if temp_value is not None:
                            component_type = self.classify_component(current_sensor['name'], key)
                            threshold = self.thresholds.get(component_type, self.thresholds['general'])

                            current_sensor['values'][key] = {
                                'temperature': temp_value,
                                'component_type': component_type,
                                'threshold': threshold,
                                'is_critical': temp_value > threshold,
                                'raw_line': line
                            }
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Ошибка парсинга строки: {line} - {e}")

        # Добавляем последний датчик
        if current_sensor:
            sensors_data.append(current_sensor)

        return sensors_data

        # Добавляем последний датчик
        if current_sensor:
            sensors_data.append(current_sensor)

        return sensors_data

    def extract_temperature(self, text: str) -> Optional[float]:
       """Извлекает числовое значение температуры из текста"""
       try:
           # Более простое регулярное выражение для поиска температур
           import re
           # Ищем шаблон типа "+29.5", "34.8" и т.д.
           match = re.search(r'([+-]?\d+\.?\d*)\s*°?C', text)
           if match:
               return float(match.group(1))

           # Альтернативный поиск для случаев без символа C
           match = re.search(r'([+-]?\d+\.?\d*)\s*\(', text)
           if match:
               return float(match.group(1))

       except (ValueError, TypeError):
           pass
       return None

# ===== SSH ПОДКЛЮЧЕНИЯ =====

class SSHClient:
    def __init__(self, timeout: int = SSH_TIMEOUT):
        self.timeout = timeout

    def get_credentials(self, host: str) -> Tuple[str, str, int]:
        """Возвращает учетные данные для указанного хоста"""
        if host in SPECIAL_CREDENTIALS:
            creds = SPECIAL_CREDENTIALS[host]
            if len(creds) == 3:
                return creds[0], creds[1], creds[2]
            elif len(creds) == 2:
                return creds[0], creds[1], DEFAULT_PORT
        return DEFAULT_USERNAME, DEFAULT_PASSWORD, DEFAULT_PORT

    def execute_command(self, host: str, command: str) -> Tuple[bool, str]:
        """Выполняет команду на удаленном хосте через SSH"""
        username, password, port = self.get_credentials(host)

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                look_for_keys=False
            )

            stdin, stdout, stderr = client.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8').strip()
            error_output = stderr.read().decode('utf-8').strip()

            client.close()

            if exit_status != 0:
                return False, f"Ошибка выполнения команды (код {exit_status}): {error_output}"

            return True, output

        except paramiko.AuthenticationException:
            return False, "Ошибка авторизации"
        except paramiko.SSHException as e:
            return False, f"SSH ошибка: {str(e)}"
        except Exception as e:
            return False, f"Ошибка при подключении: {str(e)}"

# ===== ОСНОВНАЯ ЛОГИКА =====

def monitor_temperatures():
    """Основная функция мониторинга температуры"""
    ssh_client = SSHClient()
    temp_monitor = TemperatureMonitor()

    logger.info("\n")
    logger.info("=" * 62)
    logging.info("Запуск %s - мониторинг температуры компонентов", script_name)
    logger.info("=" * 62)

    critical_issues = []

    logger.info("Исполнение скрипта...")

    for device in DEVICES:
        logger.debug(f"\n----- Мониторинг устройства: {device} -----")

        # Проверяем доступность устройства
        success, result = ssh_client.execute_command(device, "echo 'Connection test'")
        if not success:
            logger.debug(f"Устройство {device} недоступно: {result}")
            critical_issues.append(f"{device}: недоступно - {result}")
            continue

        # Получаем данные с датчиков температуры
        success, sensors_output = ssh_client.execute_command(device, "sensors")
        if not success:
            logger.debug(f"Ошибка выполнения команды sensors на {device}: {sensors_output}")
            critical_issues.append(f"{device}: ошибка sensors - {sensors_output}")
            continue

        if not sensors_output:
            logger.debug(f"Нет данных от датчиков на устройстве {device}")
            continue

        # Парсим вывод датчиков
        try:
            sensors_data = temp_monitor.parse_sensors_output(sensors_output)

            device_critical = False
            temp_readings = []

            for sensor in sensors_data:
                for value_name, value_data in sensor['values'].items():
                    temp = value_data['temperature']
                    comp_type = value_data['component_type']
                    threshold = value_data['threshold']
                    is_critical = value_data['is_critical']

                    reading_info = {
                        'sensor': sensor['name'],
                        'value': value_name,
                        'temperature': temp,
                        'component': comp_type,
                        'threshold': threshold,
                        'critical': is_critical
                    }
                    temp_readings.append(reading_info)

                    if is_critical:
                        device_critical = True
                        critical_msg = (f"превышение °C: {device} - {sensor['name']}/{value_name}: "
                                      f"{temp}°C > {threshold}°C ({comp_type.upper()})")
                        logger.debug(critical_msg)
                        critical_issues.append(critical_msg)
                    else:
                        logger.info(f"{device} - {sensor['name']}/{value_name}: {temp}°C (макс. порог = {threshold}°C) [{comp_type}]")

            # Сводка по устройству
            if not temp_readings:
                logger.debug(f"На устройстве {device} не найдено температурных датчиков")
            elif not device_critical:
                logger.info(f"Устройство {device}: все температуры в норме")
        except Exception as e:
            error_msg = f"Ошибка обработки данных с {device}: {str(e)}"
            logger.error(error_msg)
            critical_issues.append(error_msg)

    # Итоговая сводка
    logger.info("=" * 17)
    logger.info("ИТОГИ МОНИТОРИНГА")
    logger.info("=" * 17)

    if critical_issues:
        # Группируем проблемы по устройствам
        device_issues = {}
        for issue in critical_issues:
            # Извлекаем имя устройства из сообщения
            for device in DEVICES:
                if issue.startswith(device) or f" {device} " in issue or device in issue:
                    if device not in device_issues:
                        device_issues[device] = []
                    device_issues[device].append(issue)
                    break

        # Выводим статистику по каждому устройству
        for device in DEVICES:
            logger.info(f"----- Статистика устройства {device} -----")
            if device in device_issues and device_issues[device]:
                for issue in device_issues[device]:
                    logger.critical(f"{issue}")
            else:
                logger.info(f"  Температурный режим в норме")
    else:
        logger.info("Все системы работают в нормальном режиме")

    logger.info("===== Скрипт успешно выполнен =====")

if __name__ == "__main__":
    try:
        exit_code = monitor_temperatures()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Мониторинг прерван пользователем")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Неожиданная ошибка: {str(e)}")
        sys.exit(1)
