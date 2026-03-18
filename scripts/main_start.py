import os
import sys
import yaml
import json
import logging
import subprocess
import socket
import time
import argparse
from typing import Dict, Any, List, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import signal
import smtplib
from email.mime.text import MIMEText
import glob
import re


# Создание директории logs/main_start
log_path = Path('logs/main_start/main_start.log')
log_path.parent.mkdir(parents=True, exist_ok=True)

# Настройка логгера
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Глобальные переменные
hostname = socket.gethostname() # получение имени хоста

class ScriptCache:
    def __init__(self, base_dir: Path):
        self.cache_dir = base_dir / 'cache' / 'main_start'
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Директория кэша: {self.cache_dir}")
        except Exception as e:
            logger.error(f"Ошибка создания директории кэша: {e}")
            raise

    def _parse_interval(self, interval: str) -> timedelta:
        """Парсит строку интервала (1m, 5h и т.д.)"""
        interval = interval.lower()
        if interval == 'false':
            return None

        try:
            value = int(interval[:-1])
            unit = interval[-1]

            if unit == 'm':
                return timedelta(minutes=value)
            elif unit == 'h':
                return timedelta(hours=value)
            elif unit == 'd':
                return timedelta(days=value)
            else:
                raise ValueError(f"Unknown time unit: {unit}")
        except Exception as e:
            logger.error(f"Ошибка парсинга интервала '{interval}': {e}")
            return None

    def is_script_required(self, script_category: str, script_name: str, interval: str) -> bool:
        """Проверяет необходимость запуска скрипта с учётом категории"""
        delta = self._parse_interval(interval)
        if delta is None:
            return True

        cache_file = self._get_cache_path(script_category, script_name)

        # Если файл кэша отсутсвует -> запуск
        if not cache_file.exists():
            logger.debug(f"Файл кэша не найден: {cache_file}")
            return True

        # Проверка времени последнего изменения
        last_run = datetime.fromtimestamp(cache_file.stat().st_mtime)
        now = datetime.now()

        logger.debug(f"Проверка кэша: {script_category}/{script_name}, последний запуск: {last_run}, интервал: {delta}")
        return (now - last_run) > delta

    def _get_cache_path(self, script_category: str, script_name: str) -> Path:
        """Генерирует путь к файлу кэша с учётом категории"""
        category_dir = self.cache_dir / script_category
        category_dir.mkdir(exist_ok=True)
        return category_dir / f"{script_name}.timestamp"

    def update_script_timestamp(self, script_category: str, script_name: str):
        """Обновлят временную метку скрипта"""
        try:
            cache_file = self._get_cache_path(script_category, script_name)
            cache_file.touch()
            logger.debug(f"Обновлён кэш для {script_category}/{script_name}: {cache_file}")
        except Exception as e:
            logger.error(f"Ошибка обновления кэша {script_category}/{script_name}: {e}")

class ErrorCache:
    def __init__(self, base_dir: Path):
        self.cache_dir = base_dir / 'cache' / 'main_start' / 'errors'
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Директория кэша ошибок: {self.cache_dir}")
        except Exception as e:
            logger.error(f"Ошибка создания директории кэша ошибок: {e}")
            raise

    def _get_cache_path(self, script_category: str, script_name: str) -> Path:
        """Генерирует путь к файлу кэша ошибки"""
        return self.cache_dir / f"{script_category}__{script_name}.error"

    def get_last_error_time(self, script_category: str, script_name: str) -> datetime | None:
        """Получает время последней ошибки"""
        cache_file = self._get_cache_path(script_category, script_name)

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, 'r') as f:
                timestamp_str = f.read().strip()
                return datetime.fromisoformat(timestamp_str)
        except Exception as e:
            logger.error(f"Ошибка чтения кэша ошибки для {script_category}/{script_name}: {e}")
            return None

    def set_last_error_time(self, script_category: str, script_name: str, error_time: datetime):
        """Сохраняет время последней ошибки"""
        try:
            cache_file = self._get_cache_path(script_category, script_name)
            with open(cache_file, 'w') as f:
                f.write(error_time.isoformat())
            logger.debug(f"Сохранено время ошибки для {script_category}/{script_name}: {error_time}")
        except Exception as e:
            logger.error(f"Ошибка сохранения кэша ошибки для {script_category}/{script_name}: {e}")

    def clear_error_time(self, script_category: str, script_name: str):
        """Очищает время ошибки (при успешном выполнении)"""
        try:
            cache_file = self._get_cache_path(script_category, script_name)
            if cache_file.exists():
                cache_file.unlink()
                logger.debug(f"Очищен кэш ошибки для {script_category}/{script_name}")
        except Exception as e:
            logger.error(f"Ошибка очистки кэша ошибки для {script_category}/{script_name}: {e}")

class ProjectOrchestrator:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.execution_order = []
        self.config: Dict[str, Any] = {}
        self.telegram_config: Dict[str, str] = {}

        # Определение порядка выполнения скриптов по категориям
        self.script_categories = {
            'base': [],
            'additional': [],
            'maintenance': [],
        }

        # Необходимые директории
        self.required_dirs = {
            'configs': ['AddressLists'],
            'cache': ['main_start'],
            'raw-data': [],
            'output-data': [],
            'logs': [],
            'security': []
        }
        self.script_cache = ScriptCache(self.base_dir)
        self.notify_config = {}
        self.error_cache = None

        # Инициализация флага завершения
        self._shutdown_requested = False
        # Регистрация обработчиков сигналов
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _discover_additional_scripts(self) -> List[Tuple[str, str]]:
        """Автоматическое обнаружение скриптов в additional/*/"""
        additional_scripts = []
        additional_dir = self.base_dir / 'scripts' / 'additional'

        if not additional_dir.exists():
            logger.warning(f"Директория additional не найдена: {additional_dir}")
            return additional_scripts

        # Получение паттерна из configs/config.yaml
        patterns = self.config.get('scripts_discovery', {}).get('additional', {}).get('patterns', [])
        if not patterns:
            logger.error("Не найдены паттерны для обнаружения скриптов в конфиге (scripts_discovery.additional.patterns)")
            return additional_scripts

        for pattern in patterns:
            found_scripts = glob.glob(str(additional_dir / '**' / pattern), recursive=True)
            for script_path in found_scripts:
                script_name = Path(script_path).stem
                base_name = self._get_base_script_name(script_name)
                additional_scripts.append((base_name, script_name))
                logger.debug(f"Обнаружен дополнительный скрипт: {script_name} (базовое: {base_name})")

        return additional_scripts

    def _discover_base_scripts(self) -> List[Tuple[str, str]]:
        """Автоматическое обнаружение скриптов в base директории"""
        base_scripts = []
        base_dir = self.base_dir / 'scripts' / 'base'

        if not base_dir.exists():
            logger.warning(f"Директория base не найдена: {base_dir}")
            return base_scripts

        # Получение паттерна из configs/config.yaml
        patterns = self.config.get('scripts_discovery', {}).get('base', {}).get('patterns', ['*.py'])
        if not patterns:
            logger.error("Не найдены паттерны для обнаружения скриптов в конфиге (scripts_discovery.base.patterns)")
            return base_scripts

        found_scripts = []
        for pattern in patterns:
            found_scripts.extend(glob.glob(str(base_dir / pattern)))

        # Получает порядок из base_name_patterns
        base_name_patterns = self.config.get('scripts_discovery', {}).get('base', {}).get('base_name_patterns', {})

        if base_name_patterns:
            # Сортирует согласно порядку в base_name_patterns
            for base_name in base_name_patterns.keys():
                for script_path in found_scripts:
                    script_name = Path(script_path).stem
                    if not script_name.startswith('__'):
                        extracted_base = self._get_base_script_name(script_name)
                        if extracted_base == base_name:
                            base_scripts.append((base_name, script_name))
                            logger.debug(f"Обнаружен базовый скрипт: {script_name} (базовое: {base_name})")
                            break

            for script_path in found_scripts:
                script_name = Path(script_path).stem
                if not script_name.startswith('__'):
                    base_name = self._get_base_script_name(script_name)
                    if not any(script_name == full_name for _, full_name in base_scripts):
                        base_scripts.append((base_name, script_name))
                        logger.debug(f"Обнаружен дополнительный скрипт (вне порядка): {script_name}")
        else:
            for script_path in sorted(found_scripts):
                script_name = Path(script_path).stem
                if not script_name.startswith('__'):
                    base_name = self._get_base_script_name(script_name)
                    base_scripts.append((base_name, script_name))
                    logger.debug(f"Обнаружен базовый скрипт: {script_name} (базовое: {base_name})")

        return base_scripts

    def _discover_maintenance_scripts(self) -> List[Tuple[str, str]]:
        """Автоматическое обнаружение скриптов в maintenance директории"""
        maintenance_scripts = []
        maintenance_dir = self.base_dir / 'scripts' / 'maintenance'

        if not maintenance_dir.exists():
            logger.warning(f"Директория maintenance не найдена: {maintenance_dir}")
            return maintenance_scripts

        # Получение паттерна из configs/config.yaml
        patterns = self.config.get('scripts_discovery', {}).get('maintenance', {}).get('patterns', ['*.py'])
        if not patterns:
            logger.error("Не найдены паттерны для обнаружения скриптов в конфиге (scripts_discovery.maintenance.patterns)")
            return maintenance_scripts
        found_scripts = []
        for pattern in patterns:
            found_scripts.extend(glob.glob(str(maintenance_dir / pattern)))

        # Получает порядок из base_name_patterns
        base_name_patterns = self.config.get('scripts_discovery', {}).get('maintenance', {}).get('base_name_patterns', {})

        if base_name_patterns:
            for maintenance_name in base_name_patterns.keys():
                for script_path in found_scripts:
                    script_name = Path(script_path).stem
                    if not script_name.startswith('__'):
                        extracted_base = self._get_base_script_name(script_name)
                        if extracted_base == maintenance_name:
                            maintenance_scripts.append((maintenance_name, script_name))
                            logger.debug(f"Обнаружен обслуживающий скрипт: {script_name} (базовое: {maintenance_name})")
                            break

            for script_path in found_scripts:
                script_name = Path(script_path).stem
                if not script_name.startswith('__'):
                    maintenance_name = self._get_base_script_name(script_name)
                    if not any(script_name == full_name for _, full_name in maintenance_scripts):
                        maintenance_scripts.append((maintenance_name, script_name))
                        logger.debug(f"Обнаружен обслуживающий скрипт (вне порядка): {script_name}")
        else:
            for script_path in sorted(found_scripts):
                script_name = Path(script_path).stem
                if not script_name.startswith('__'):
                    maintenance_name = self._get_base_script_name(script_name)
                    maintenance_scripts.append((maintenance_name, script_name))
                    logger.debug(f"Обнаружен скрипт: {script_name} (базовое: {maintenance_name})")

        return maintenance_scripts

    def _get_base_script_name(self, full_name: str) -> str:
        """Извлекает базовое имя скрипта из полного имени на основе правил из конфига"""

        # Получение правила из configs/config.yaml
        base_name_patterns = self.config.get('scripts_discovery', {}).get('additional', {}).get('base_name_patterns', {})

        for base_name, pattern in base_name_patterns.items():
            if re.match(pattern, full_name):
                return base_name
        return full_name

    def _handle_signal(self, signum, frame):
        """Обработчик сигналов завершения"""
        logger.warning(f"Получен сигнал {signum}, инициирую завершение...")
        self._shutdown_requested = True
        self.send_notification(f"Получен сигнал завершения {signum}", True)

    def load_configs(self) -> bool:
        try:
            config_path = self.base_dir / 'configs' / 'config.yaml'
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f).get('main_start', {})

            # Загружает порядок исполнения (из конфига) или использует порядок по умолчанию
            self.execution_order = self.config.get('execution_order', ['additional', 'base', 'maintenance'])
            logger.info(f"Порядок выполнения групп: {self.execution_order}")

            return True
        except Exception as e:
            logger.error(f"Ошибка загрузки конфигурации: {e}")
            return False

    def load_notify_config(self) -> bool:
        """Загрузка конфигурации уведомлений"""
        try:
            notify_path = self.base_dir / 'security' / 'notify.yaml'
            if not notify_path.exists():
                logger.error(f"Файл уведомлений не найден: {notify_path}")
                return False

            with open(notify_path, 'r') as f:
                self.notify_config = yaml.safe_load(f)

            # Проверка конфигурации Telegram
            if self.config.get('settings_notify', {}).get('telegram') == 'true':
                if not self.notify_config.get('telegram'):
                    logger.error("Telegram уведомления включены, но конфиг отсутствует")
                    return False

            # Проверка конфигурации Email
            if self.config.get('settings_notify', {}).get('email') == 'true':
                if not self.notify_config.get('email'):
                    logger.error("Email уведомления включены, но конфиг отсутствует")
                    return False
                required_keys = {'smtp_server', 'smtp_port', 'login', 'password', 'from_addr', 'to_addr'}
                if not all(k in self.notify_config['email'] for k in required_keys):
                    logger.error("Email конфиг неполный")
                    return False

            return True
        except Exception as e:
            logger.error(f"Ошибка загрузки конфига уведомлений: {e}", exc_info=True)
            return False

    def should_notify(self, is_error: bool) -> bool:
        """Определяет необходимость отправки уведомления"""
        notify_type = self.config.get('settings_notify', {}).get('type', 'all').lower()

        logger.debug(f"Проверка уведомления: тип={notify_type}, is_error={is_error}")

        if notify_type == 'all':
            return True
        elif notify_type == 'failure':
            return is_error
        elif notify_type == 'success':
            return not is_error
        return False

    def send_notification(self, message: str, is_error: bool = False) -> None:
        """Общий метод отправки уведомлений"""
        logger.debug(f"Проверка уведомления: {message[:50]}... (is_error={is_error})")

        if not self.should_notify(is_error):
            logger.debug(f"Уведомление пропущено по настройкам: {message[:50]}...")
            return

        # Telegram уведомления
        if self.config.get('settings_notify', {}).get('telegram', 'false').lower() == 'true':
            logger.debug("Попытка отправки Telegram...")
            self._send_telegram(message, is_error)

        # Email уведомления
        if self.config.get('settings_notify', {}).get('email', 'false').lower() == 'true':
            logger.debug("Попытка отправки Email...")
            self._send_email(message, is_error)
        else:
            logger.debug("Email уведомления отключены в конфиге")

    def _send_telegram(self, message: str, is_error: bool) -> None:
        """Отправка в Telegram"""
        if not self.notify_config.get('telegram'):
            logger.error("Telegram конфиг не найден в notify.yaml")
            return

        try:
            import requests
            emoji = "❌" if is_error else "✅"
            url = f"https://api.telegram.org/bot{self.notify_config['telegram']['bot_token']}/sendMessage"
            payload = {
                'chat_id': self.notify_config['telegram']['chat_id'],
                'text': f"{emoji} <b>MikroTik-ARMA ({hostname})</b>: <i>{message}</i>",
                'parse_mode': 'HTML'
            }

            logger.debug(f"Отправка Telegram: {url} с payload: {payload}")
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            logger.debug(f"Telegram ответ: {response.status_code} {response.text}")

        except Exception as e:
            logger.error(f"Ошибка отправки Telegram: {str(e)}", exc_info=True)

    def _send_email(self, message: str, is_error: bool) -> None:
        """Отправка email через SMTP"""
        logger.debug("Начало отправки email...")

        if not self.notify_config.get('email'):
            logger.error("Email конфиг не найден в notify.yaml")
            return

        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.utils import formatdate

            email_cfg = self.notify_config['email']
            logger.debug(f"Конфиг email: {email_cfg}")

            subject = f"❌ MikroTik-ARMA: Failure ({hostname})" if is_error else f"✅ MikroTik-ARMA: Success ({hostname})"
            logger.debug(f"Тема письма: {subject}")

            msg = MIMEText(message, 'plain', 'utf-8')
            msg['Subject'] = subject
            msg['From'] = email_cfg['from_addr']
            msg['To'] = email_cfg['to_addr']
            msg['Date'] = formatdate(localtime=True)

            logger.debug("Подготавливаем SMTP соединение...")

            with smtplib.SMTP_SSL(
                host=email_cfg['smtp_server'],
                port=email_cfg['smtp_port'],
                timeout=10
            ) as server:
                logger.debug("Устанавливаем debug уровень...")
              #  server.set_debuglevel(1)  # DEBUG подробное логирование

                logger.debug(f"Логин на сервере {email_cfg['smtp_server']}...")
                server.login(email_cfg['login'], email_cfg['password'])

                logger.debug(f"Отправка письма на {email_cfg['to_addr']}...")
                server.sendmail(
                    email_cfg['from_addr'],
                    [email_cfg['to_addr']],
                    msg.as_string()
                )

            logger.info(f"Email успешно отправлен на {email_cfg['to_addr']}")

        except Exception as e:
            logger.error(f"Ошибка отправки email: {str(e)}", exc_info=True)

    def ensure_directories(self) -> bool:
        """Проверка и создание директорий"""
        try:
            for dir_name, subdirs in self.required_dirs.items():
                dir_path = self.base_dir / dir_name
                if not dir_path.exists():
                    dir_path.mkdir()
                    logger.info(f"Создана директория: {dir_path}")

                for subdir in subdirs:
                    subdir_path = dir_path / subdir
                    if not subdir_path.exists():
                        subdir_path.mkdir()
                        logger.info(f"Создана поддиректория: {subdir_path}")
            return True
        except Exception as e:
            logger.error(f"Ошибка создания директорий: {e}")
            return False

    def find_script_path(self, script_category: str, script_name: str) -> Path:
        """Поиск пути к скрипту в зависимости от категории"""
        if script_category == 'base':
            return self.base_dir / 'scripts' / 'base' / f"{script_name}.py"
        elif script_category == 'additional':
            additional_dir = self.base_dir / 'scripts' / 'additional'
            patterns = [f"**/{script_name}.py"]
            for pattern in patterns:
                found_paths = glob.glob(str(additional_dir / pattern), recursive=True)
                if found_paths:
                    return Path(found_paths[0])
            return None
        elif script_category == 'maintenance':
            return self.base_dir / 'scripts' / 'maintenance' / f"{script_name}.py"
        else:
            return self.base_dir / 'scripts' / script_category / f"{script_name}.py"

    def is_script_enabled(self, script_category: str, base_name: str) -> bool:
        """Проверяет включение скрипта в конфигурации по базовому имени"""
        category_config = self.config.get('launch_chain', {}).get(script_category, {})
        return category_config.get(base_name, False)

    def get_cache_interval(self, script_category: str, base_name: str) -> str:
        """Получает интервал кэширования для скрипта по базовому имени"""
        cache_config = self.config.get('settings_cache', {}).get(script_category, {})
        return cache_config.get(base_name, 'false')

    def should_restart_after_error(self, script_category: str, script_name: str) -> bool:
        """Проверяет, можно ли перезапустить скрипт после ошибки"""
        restart_delay = self.config.get('settings_cache', {}).get('restart_after_error', 0)

        # Если параметр не задан или равен 0 - всегда запуск
        if restart_delay <= 0:
            return True

        if self.error_cache is None:
            return True

        last_error_time = self.error_cache.get_last_error_time(script_category, script_name)

        if last_error_time is None:
            return True

        # Проверяет срок времени ошибки
        time_since_error = (datetime.now() - last_error_time).total_seconds() / 3600  # в часах
        logger.debug(f"Проверка ошибки для {script_category}/{script_name}: прошло {time_since_error:.2f} часов, осталось {restart_delay}")
        return time_since_error >= restart_delay

    def get_hostname(self) -> str:
        """Возвращает имя хоста сервера"""
        try:
            import socket
            return socket.gethostname()
        except:
            return "UnknownHost"

    def setup_log_monitoring(self) -> None:
        """Настройка мониторинга логов по шаблонам"""
        log_monitoring_config = self.config.get('log_monitoring', {})
        if not log_monitoring_config.get('enabled', False):
            logger.info(f"Мониторинг логов отключен")
            return

        self.log_patterns = log_monitoring_config.get('pattern_alerts', [])
        if self.log_patterns:
            logger.info(f"Мониторинг логов активен. Шаблоны: {len(self.log_patterns)}")

    def check_log_patterns(self, line: str, script_category: str, script_name: str) -> None:
        """Проверяет строку лога на совпадение с шаблонами"""
        if not hasattr(self, 'log_patterns') or not self.log_patterns:
            return

        for pattern in self.log_patterns:
            if pattern in line:
                self.send_log_alert(pattern, line, script_category, script_name)
                break

    def send_log_alert(self, pattern: str, line: str, script_category: str, script_name: str) -> None:
        """Отправляет уведомление о найденном шаблоне в логах (тип WARNING)"""
        message = (f"Обнаружен шаблон в логах скрипта {script_category}/{script_name}\n"
                  f"Шаблон: {pattern}\n"
                  f"Строка лога: {line.strip()}")

        logger.warning(f"Мониторинг логов: {message}")

        self.send_log_monitoring_notification(message)

    def send_log_monitoring_notification(self, message: str) -> None:
        """Отправляет уведомление от мониторинга логов (отдельный тип)"""
        if self.config.get('settings_notify', {}).get('telegram', 'false').lower() == 'true':
            self._send_telegram_log_monitoring(message)

        if self.config.get('settings_notify', {}).get('email', 'false').lower() == 'true':
            self._send_email_log_monitoring(message)

    def _send_telegram_log_monitoring(self, message: str) -> None:
        """Отправка в Telegram от мониторинга логов"""
        if not self.notify_config.get('telegram'):
            logger.error("Telegram конфиг не найден в notify.yaml")
            return

        try:
            import requests
            url = f"https://api.telegram.org/bot{self.notify_config['telegram']['bot_token']}/sendMessage"
            payload = {
                'chat_id': self.notify_config['telegram']['chat_id'],
                'text': f"⚠️ <b>MikroTik-ARMA: Log Monitor ({hostname})</b>: <i>{message}</i>",
                'parse_mode': 'HTML'
            }
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            logger.debug(f"Telegram Log Monitor отправлен: {response.status_code}")

        except Exception as e:
            logger.error(f"Ошибка отправки Telegram для мониторинга логов: {str(e)}")

    def _send_email_log_monitoring(self, message: str) -> None:
        """Отправка email от мониторинга логов"""
        logger.debug("Отправка email для мониторинга логов...")

        if not self.notify_config.get('email'):
            logger.error("Email конфиг не найден в notify.yaml")
            return

        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.utils import formatdate

            email_cfg = self.notify_config['email']

            # Отдельная тема для мониторинга логов
            subject = f"⚠️ MikroTik-ARMA: Log Monitoring Alert ({hostname})"

            msg = MIMEText(message, 'plain', 'utf-8')
            msg['Subject'] = subject
            msg['From'] = email_cfg['from_addr']
            msg['To'] = email_cfg['to_addr']
            msg['Date'] = formatdate(localtime=True)

            with smtplib.SMTP_SSL(
                host=email_cfg['smtp_server'],
                port=email_cfg['smtp_port'],
                timeout=10
            ) as server:
                server.login(email_cfg['login'], email_cfg['password'])
                server.sendmail(
                    email_cfg['from_addr'],
                    [email_cfg['to_addr']],
                    msg.as_string()
                )

            logger.info(f"Email для мониторинга логов отправлен на {email_cfg['to_addr']}")

        except Exception as e:
            logger.error(f"Ошибка отправки email для мониторинга логов: {str(e)}")

    def run_script(self, script_category: str, script_name: str, base_name: str) -> bool:
        """Запуск отдельного скрипта с учётом категории"""
        if getattr(self, '_shutdown_requested', False):
            logger.warning("Запуск скрипта отменён (идёт завершение работы)")
            return False

        script_path = self.find_script_path(script_category, script_name)
        if not script_path or not script_path.exists():
            logger.error(f"[FAIL] Скрипт {script_category}/{script_name} не найден по пути: {script_path}")
            return False

        try:
            logger.info(f"[START] Запуск {script_category}/{script_name}...")
            start_time = time.time()

            # Запуск процесса с отдельным выводом
            process = subprocess.Popen(
                [sys.executable, str(script_path)],
                cwd=self.base_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                bufsize=1
            )

            # Читает вывод скрипта в реальном времени
            output_lines = []
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    line = line.strip()
                    if line:
                        print(line)
                        output_lines.append(line)

                        # Проверка шаблонов ТОЛЬКО в логах внешнего скрипта
                        self.check_log_patterns(line, script_category, script_name)

            process.wait()
            exec_time = time.time() - start_time

            if process.returncode == 0:
                logger.info(f"[DONE] Скрипт {script_category}/{script_name} успешно выполнен за {exec_time:.1f} сек")
                if self.error_cache is not None:
                    self.error_cache.clear_error_time(script_category, script_name)
                return True
            else:
                logger.error(f"[FAIL] Скрипт {script_category}/{script_name} завершился с ошибкой (код {process.returncode})")
                # Сохраняет время ошибки
                if self.error_cache is not None:
                    self.error_cache.set_last_error_time(script_category, script_name, datetime.now())
                return False

        except Exception as e:
            logger.error(f"[ERROR] Неожиданная ошибка в {script_category}/{script_name}: {str(e)}")
            return False

    def print_scripts_info(self) -> None:
        """Выводит информацию об обнаруженных скриптах и порядке запуска"""

        print("\n" + "="*60)
        print("MikroTik-ARMA Orchestrator: Информация о скриптах")
        print("="*60)

        # Информация о порядке выполнения
        print(f"\n📋 Порядок выполнения групп: {', '.join(self.execution_order)}")

        # Статистика по группам
        total_all = 0
        total_enabled = 0

        for category in self.execution_order:
            if category not in self.script_categories:
                print(f"\n⚠️  Группа '{category}' не содержит скриптов")
                continue

            scripts = self.script_categories[category]
            if not scripts:
                print(f"\n📁 {category.upper()}: нет скриптов")
                continue

            print(f"\n📁 {category.upper()} ({len(scripts)} скриптов):")

            for base_name, full_name in sorted(scripts):
                enabled = self.is_script_enabled(category, base_name)
                cache_interval = self.get_cache_interval(category, base_name)

                status = "✅" if enabled else "❌"
                total_all += 1
                if enabled:
                    total_enabled += 1

                cache_info = f", кэш: {cache_interval}" if cache_interval != 'false' else ""

                print(f"  {status} {full_name} (базовое: {base_name}{cache_info})")

        # Общая статистика
        print("\n" + "="*60)
        print(f"ИТОГО:")
        print(f"   Всего скриптов: {total_all}")
        print(f"   Активных: {total_enabled} ✅")
        print(f"   Отключено: {total_all - total_enabled} ❌")
        print("="*60 + "\n")


    def print_scripts_info(self) -> None:
        """Выводит информацию об обнаруженных скриптах и порядке запуска"""

        print("\n" + "="*60)
        print("🔍 MikroTik-ARMA Orchestrator: Информация о скриптах")
        print("="*60)

        # Информация о порядке выполнения
        print(f"\n📋 Порядок выполнения групп: {', '.join(self.execution_order)}")

        # Статистика по группам
        total_all = 0
        total_enabled = 0

        for category in self.execution_order:
            if category not in self.script_categories:
                print(f"\n⚠️  Группа '{category}' не содержит скриптов")
                continue

            scripts = self.script_categories[category]
            if not scripts:
                print(f"\n📁 {category.upper()}: нет скриптов")
                continue

            print(f"\n📁 {category.upper()} ({len(scripts)} скриптов):")

            for base_name, full_name in sorted(scripts):
                enabled = self.is_script_enabled(category, base_name)
                cache_interval = self.get_cache_interval(category, base_name)

                status = "✅" if enabled else "❌"
                total_all += 1
                if enabled:
                    total_enabled += 1

                # Строка с информацией о кэше
                cache_info = f", кэш: {cache_interval}" if cache_interval != 'false' else ""

                print(f"  {status} {full_name} (базовое: {base_name}{cache_info})")

                # Время последнего запуска из кэша
                if enabled and cache_interval != 'false':
                    cache_file = self.script_cache._get_cache_path(category, full_name)
                    if cache_file.exists():
                        last_run = datetime.fromtimestamp(cache_file.stat().st_mtime)
                        print(f"      ⏱ Последний запуск: {last_run.strftime('%Y-%m-%d %H:%M')}")

        # Общая статистика
        print("\n" + "="*60)
        print(f"📊 ИТОГО:")
        print(f"   Всего скриптов: {total_all}")
        print(f"   Активных: {total_enabled} ✅")
        print(f"   Отключено: {total_all - total_enabled} ❌")
        print("="*60 + "\n")

    def run(self, check_only: bool = False) -> None:
        """Основной метод запуска оркестратора
        check_only: если True, только показать информацию о скриптах без выполнения
        """

        # Инициализация (для загрузки конфигурации)
        if not all([
            self.load_configs(),
            self.load_notify_config(),
            self.ensure_directories()
        ]):
            self.send_notification("Ошибка инициализации!", True)
            sys.exit(1)

        # Обнаружение скриптов
        self.script_categories['additional'] = self._discover_additional_scripts()
        self.script_categories['base'] = self._discover_base_scripts()
        self.script_categories['maintenance'] = self._discover_maintenance_scripts()

        logger.info(f"Обнаружено дополнительных скриптов: {len(self.script_categories['additional'])}")
        logger.info(f"Обнаружено базовых скриптов: {len(self.script_categories['base'])}")
        logger.info(f"Обнаружено обслуживающих скриптов: {len(self.script_categories['maintenance'])}")

        # Режим проверки -> вывод информации
        if check_only:
            self.print_scripts_info()
            return

        logger.info(f"\n")
        logger.info("=" * 33)
        logger.info("MikroTik-ARMA Orchestrator: START")
        logger.info("=" * 33)

        logger.debug(f"Проверка конфига: email={self.config.get('settings_notify', {}).get('email')}")
        logger.debug(f"Полный конфиг: {json.dumps(self.config, indent=2, default=str)}")
        logger.debug(f"Конфиг уведомлений: {json.dumps(self.notify_config, indent=2)}")

        if self.config.get('settings_notify', {}).get('email') == 'true':
            logger.debug("Проверка конфигурации email...")
            email_cfg = self.notify_config.get('email', {})
            logger.debug(f"SMTP сервер: {email_cfg.get('smtp_server')}:{email_cfg.get('smtp_port')}")
            logger.debug(f"Логин: {email_cfg.get('login')}")
            logger.debug(f"Получатель: {email_cfg.get('to_addr')}")

        # Настройка мониторинга логов
        self.setup_log_monitoring()

        # Доступность кэша
        try:
            self.script_cache = ScriptCache(self.base_dir)
        except Exception as e:
            logger.error(f"Ошибка инициализации кэша: {e}")
            self.send_notification("Ошибка инициализации кэша!", True)
            sys.exit(1)

        # Инициализация кэша ошибок
        try:
            self.error_cache = ErrorCache(self.base_dir)
        except Exception as e:
            logger.error(f"Ошибка инициализации кэша ошибок: {e}")
            self.send_notification("Ошибка инициализации кэша ошибок", True)
            sys.exit(1)

        # Подсчёт общего количества активных скриптов
        total_scripts = 0
        for category in self.execution_order:
            if category not in self.script_categories:
                continue

            if category == 'additional':
                # В additional учитывает только включеные в конфиге
                for base_name, full_name in self.script_categories[category]:
                    if self.is_script_enabled(category, base_name):
                        total_scripts += 1
            else:
                category_config = self.config.get('launch_chain', {}).get(category, {})
                for base_name, full_name in self.script_categories[category]:
                    if category_config.get(base_name, False):
                        total_scripts += 1

        logger.debug(f"Всего активных скриптов: {total_scripts}")

        # Сбор всех сообщений
        execution_log = []
        success_count = 0
        has_errors = False
        stop_on_error = self.config.get('settings_notify', {}).get('stop_on_error', 'true') == 'true'

        # Запуск скриптов по категориям
        for category in self.execution_order:
            if has_errors and stop_on_error:
                break

            # Заголовок группы
            if category == 'additional':
                logger.info("\n=== Исполняется группа скриптов дополнительного функционала ===")
            elif category == 'base':
                logger.info("\n=== Исполняется группа скриптов основного функционала ===")
            elif category == 'maintenance':
                logger.info("\n=== Исполняется группа скриптов обслуживания ===")

            if category == 'base':
                # Обработка base скриптов (аналогично additional)
                for base_name, full_name in self.script_categories[category]:
                    if not self.is_script_enabled(category, base_name):
                        msg = f"[SKIP] Скрипт {category}/{full_name} отключен в конфигурации"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    cache_interval = self.get_cache_interval(category, base_name)

                    if not self.script_cache.is_script_required(category, full_name, cache_interval):
                        msg = f"[CACHE] Скрипт {category}/{full_name} пропущен (кэш актуален)"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    if not self.should_restart_after_error(category, full_name):
                        msg = f"[ERROR_DELAY] Скрипт {category}/{full_name} пропущен (время до перезапуска после ошибки не истекло)"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    script_result = self.run_script(category, full_name, base_name)

                    if script_result:
                        success_count += 1
                        self.script_cache.update_script_timestamp(category, full_name)
                        execution_log.append(f"[OK] Скрипт {category}/{full_name} выполнен успешно")
                    else:
                        execution_log.append(f"[ERROR] Скрипт {category}/{full_name} завершился с ошибкой")
                        has_errors = True
                        if stop_on_error:
                            break

            elif category == 'additional':
                # Обработка additional скриптов
                for base_name, full_name in self.script_categories[category]:
                    if not self.is_script_enabled(category, base_name):
                        msg = f"[SKIP] Скрипт {category}/{full_name} отключен в конфигурации"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    cache_interval = self.get_cache_interval(category, base_name)

                    if not self.script_cache.is_script_required(category, full_name, cache_interval):
                        msg = f"[CACHE] Скрипт {category}/{full_name} пропущен (кэш актуален)"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    if not self.should_restart_after_error(category, full_name):
                        msg = f"[ERROR_DELAY] Скрипт {category}/{full_name} пропущен (время до перезапуска после ошибки не истекло)"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    script_result = self.run_script(category, full_name, base_name)

                    if script_result:
                        success_count += 1
                        self.script_cache.update_script_timestamp(category, full_name)
                        execution_log.append(f"[OK] Скрипт {category}/{full_name} выполнен успешно")
                    else:
                        execution_log.append(f"[ERROR] Скрипт {category}/{full_name} завершился с ошибкой")
                        has_errors = True
                        if stop_on_error:
                            break

            elif category == 'maintenance':
                # Обработка maintenance скриптов
                for base_name, full_name in self.script_categories[category]:
                    if not self.is_script_enabled(category, base_name):
                        msg = f"[SKIP] Скрипт {category}/{full_name} отключен в конфигурации"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    cache_interval = self.get_cache_interval(category, base_name)

                    if not self.script_cache.is_script_required(category, full_name, cache_interval):
                        msg = f"[CACHE] Скрипт {category}/{full_name} пропущен (кэш актуален)"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    if not self.should_restart_after_error(category, full_name):
                        msg = f"[ERROR_DELAY] Скрипт {category}/{full_name} пропущен (время до перезапуска после ошибки не истекло)"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    script_result = self.run_script(category, full_name, base_name)

                    if script_result:
                        success_count += 1
                        self.script_cache.update_script_timestamp(category, full_name)
                        execution_log.append(f"[OK] Скрипт {category}/{full_name} выполнен успешно")
                    else:
                        execution_log.append(f"[ERROR] Скрипт {category}/{full_name} завершился с ошибкой")
                        has_errors = True
                        if stop_on_error:
                            break

            if has_errors and self.config.get('settings_notify', {}).get('stop_on_error', 'true') == 'true':
                break

        # Итоговый отчет
        final_status = f"Успешно выполнено {success_count}/{total_scripts} скриптов"
        full_report = f"{final_status}\n\nДетальный лог:\n" + "\n".join(execution_log)

        # Отправка уведомлений
        if self.should_notify(has_errors):
            if self.config.get('settings_notify', {}).get('email', 'false') == 'true':
                self._send_email(full_report, has_errors)

            if self.config.get('settings_notify', {}).get('telegram', 'false') == 'true':
                self._send_telegram(final_status, has_errors)

        if has_errors:
            sys.exit(1)

        logger.info("=" * 36)
        logger.info("MikroTik-ARMA Orchestrator: FINISHED")
        logger.info("=" * 36)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='MikroTik-ARMA Orchestrator')
    parser.add_argument('--check-scripts', action='store_true',
                       help='Показать информацию об обнаруженных скриптах без выполнения')
    args = parser.parse_args()

    orchestrator = ProjectOrchestrator()

    if args.check_scripts:
        logging.getLogger().handlers = [h for h in logging.getLogger().handlers
                                       if not isinstance(h, logging.FileHandler)]
        logging.getLogger().setLevel(logging.ERROR)

    orchestrator.run(check_only=args.check_scripts)
