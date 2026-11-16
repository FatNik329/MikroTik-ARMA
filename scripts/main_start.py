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
from email.utils import formatdate
from email.mime.multipart import MIMEMultipart
import glob
import re
import fcntl
import atexit
import requests
import html

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

    def get_interval_delta(self, interval: str) -> timedelta | None:
        """Публичная обёртка: возвращает timedelta интервала или None"""
        return self._parse_interval(interval)

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
        # Буфер WARNING-уведомлений за текущий прогон конвейера.
        self._warning_events: List[Dict[str, Any]] = []

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

        # Атрибуты для runtime-лока
        self._lock_fd = None
        self._lock_path = self.base_dir / 'cache' / 'main_start' / 'shell.lock'

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
                logger.debug(f"Обнаружен дополнительный скрипт: {script_name} (шаблон: {base_name})")

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
                            logger.debug(f"Обнаружен базовый скрипт: {script_name} (шаблон: {base_name})")
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
                    logger.debug(f"Обнаружен базовый скрипт: {script_name} (шаблон: {base_name})")

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
                            logger.debug(f"Обнаружен обслуживающий скрипт: {script_name} (шаблон: {maintenance_name})")
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
                    logger.debug(f"Обнаружен скрипт: {script_name} (шаблон: {maintenance_name})")

        return maintenance_scripts

    def _get_base_script_name(self, full_name: str) -> str:
        """Извлекает шаблонное имя скрипта из полного имени на основе правил из конфига"""

        # Получение правила из configs/config.yaml
        base_name_patterns = self.config.get('scripts_discovery', {}).get('additional', {}).get('base_name_patterns', {})

        for base_name, pattern in base_name_patterns.items():
            if re.match(pattern, full_name):
                return base_name
        return full_name

    @staticmethod
    def _plural_scripts(n: int) -> str:
        """Возвращает правильную форму слова 'скрипт' для числа n"""
        if n % 10 == 1 and n % 100 != 11:
            return "скрипт"
        elif n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
            return "скрипта"
        else:
            return "скриптов"

    def _handle_signal(self, signum, frame):
        """Обработчик сигналов завершения"""
        logger.warning(f"Получен сигнал {signum}, инициируется завершение")
        self._shutdown_requested = True
        self.send_notification(f"Получен сигнал завершения {signum}", True)

    def _acquire_lock(self) -> bool:
        """Получение эксклюзивного неблокирующиего лока. True — лок взят."""
        try:
            self._lock_path.parent.mkdir(parents=True, exist_ok=True)
            self._lock_fd = open(self._lock_path, 'w')
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

            # Запись PID и время
            self._lock_fd.write(f"{os.getpid()} {datetime.now().isoformat()}\n")
            self._lock_fd.flush()

            logger.info(f"[LOCK] Runtime-лок захвачен: {self._lock_path} (PID {os.getpid()})")
            return True

        except BlockingIOError:
            logger.warning(f"[LOCK] Оркестратор уже выполняется (лок занят: {self._lock_path})")
            if self._lock_fd:
                self._lock_fd.close()
                self._lock_fd = None
            return False

        except Exception as e:
            logger.error(f"[LOCK] Ошибка захвата лока: {e}")
            if self._lock_fd:
                self._lock_fd.close()
                self._lock_fd = None
            return False

    def _release_lock(self) -> None:
        """Освобождение runtime-лок."""
        if self._lock_fd is None:
            return
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            self._lock_fd.close()
            logger.debug(f"[LOCK] Runtime-лок освобождён: {self._lock_path}")
        except Exception as e:
            logger.error(f"[LOCK] Ошибка освобождения лока: {e}")
        finally:
            self._lock_fd = None

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

    def send_push_heartbeat(self, is_fatal: bool = False) -> None:
        """push-heartbeat во внешний монитор.
        Отвечает только за рабочее состояние оркестратора:
          - дошёл до конца -> success
          - фатальный сбой оркестратора -> failure
        Поддерживает два режима (см. security/notify.yaml):
          - mode: 'query' — статус в query-параметрах (Uptime Kuma-подобные)
          - mode: 'path'  — статус в URL-пути (Healthchecks/Cronitor/Better Stack)
        """
        cfg = (self.notify_config or {}).get('push_monitor', {}) or {}

        if not cfg:
            try:
                notify_path = self.base_dir / 'security' / 'notify.yaml'
                if notify_path.exists():
                    with open(notify_path, 'r') as f:
                        disk_cfg = yaml.safe_load(f) or {}
                    cfg = disk_cfg.get('push_monitor', {}) or {}
            except Exception as e:
                logger.warning(f"[PUSH] Не удалось прочитать notify.yaml для heartbeat: {e}")
                cfg = {}

        if str(cfg.get('enabled', 'false')).lower() != 'true':
            return

        mode = str(cfg.get('mode', 'query')).lower()
        timeout = int(cfg.get('timeout', 10) or 10)
        state = 'failure' if is_fatal else 'success'

        try:
            if mode == 'path':
                url = (cfg.get('failure_url') if is_fatal else cfg.get('success_url')) or ''
                url = url.strip()
                if not url:
                    logger.warning(f"[PUSH] mode=path, но {state}_url пуст — пинг пропущен")
                    return
                resp = requests.get(url, timeout=timeout)

            elif mode == 'query':
                url = (cfg.get('push_url') or '').strip()
                if not url:
                    logger.warning("[PUSH] mode=query, но push_url пуст — пинг пропущен")
                    return
                status_value = cfg.get('failure_status', 'down') if is_fatal \
                               else cfg.get('success_status', 'up')
                params = {
                    'status': status_value,
                    'msg': cfg.get('msg', 'arma_is_alive'),
                }
                resp = requests.get(url, params=params, timeout=timeout)

            else:
                logger.warning(f"[PUSH] Неизвестный mode='{mode}' — пинг пропущен")
                return

            resp.raise_for_status()
            logger.info(f"[PUSH] Heartbeat отправлен: state={state}, mode={mode}")

        except Exception as e:
            logger.warning(f"[PUSH] Ошибка отправки heartbeat: {e}")

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

            email_cfg = self.notify_config['email']
            logger.debug(f"Конфиг email: {email_cfg}")

            subject = f"❌ MikroTik-ARMA: Failure ({hostname})" if is_error else f"✅ MikroTik-ARMA: Success ({hostname})"
            logger.debug(f"Тема письма: {subject}")

            msg = MIMEText(message, 'plain', 'utf-8')
            msg['Subject'] = subject
            msg['From'] = email_cfg['from_addr']
            msg['To'] = email_cfg['to_addr']
            msg['Date'] = formatdate(localtime=True)

            logger.debug("Подготовка SMTP соединения...")

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
        """Буферизует WARNING-событие из мониторинга логов."""
        message = (f"Обнаружен шаблон в логах скрипта {script_category}/{script_name}\n"
                   f"Шаблон: {pattern}\n"
                   f"Строка лога: {line.strip()}")

        logger.warning(f"Мониторинг логов: {message}")

        self._warning_events.append({
            "category":  script_category,
            "script":    script_name,
            "base_name": self._get_base_script_name(script_name),
            "pattern":   pattern,
            "line":      line.strip(),
            "time":      datetime.now(),
            "kind":      "log_pattern",
        })

    def _format_warning_report(self, events: List[Dict[str, Any]]) -> Tuple[str, str]:
        """Форматирование (plain_text, html) сгруппированного WARNING-отчёта."""
        from collections import defaultdict

        grouped: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
        for ev in events:
            grouped[ev["category"]][ev["base_name"]].append(ev)

        SEP = "─" * 57
        now = datetime.now()
        lines_plain: List[str] = []
        html_parts: List[str] = []

        lines_plain.append(f"⚠️  MikroTik-ARMA: WARNING-отчёт ({hostname})")
        lines_plain.append(f"Время: {now.strftime('%Y-%m-%d %H:%M:%S')}")
        lines_plain.append(f"Всего событий: {len(events)}")
        lines_plain.append("")

        html_parts.append(
            f"<h2>⚠️ MikroTik-ARMA: WARNING-отчёт "
            f"<small>({html.escape(hostname)})</small></h2>"
            f"<p>Время: <b>{now.strftime('%Y-%m-%d %H:%M:%S')}</b><br>"
            f"Всего событий: <b>{len(events)}</b></p>"
        )

        for category in self.execution_order:
            if category not in grouped:
                continue
            by_pattern = grouped[category]
            total_cat = sum(len(v) for v in by_pattern.values())

            lines_plain.append(f"📁 {category.upper()} ({total_cat} событий):")
            html_parts.append(f"<h3>📁 {category.upper()} ({total_cat})</h3>")

            first_pattern = True
            for base_name in sorted(by_pattern.keys()):
                evs = sorted(by_pattern[base_name], key=lambda e: e["time"])
                if not first_pattern:
                    lines_plain.append(f"  {SEP}")
                first_pattern = False

                lines_plain.append(f"  🔹 группа скрипта: {base_name} ({len(evs)})")
                html_parts.append(
                    f"<h4>🔹 группа скрипта: {html.escape(base_name)} ({len(evs)})</h4><ul>"
                )

                for ev in evs:
                    ts = ev["time"].strftime("%Y-%m-%d %H:%M:%S")
                    if ev["kind"] == "log_pattern":
                        lines_plain.append(f"      [{ts}] {ev['script']}")
                        lines_plain.append(f"         шаблон: {ev['pattern']}")
                        lines_plain.append(f"         строка: {ev['line']}")
                        html_parts.append(
                            f"<li><b>{html.escape(ev['script'])}</b> — "
                            f"<code>{ts}</code><br>"
                            f"шаблон: <code>{html.escape(str(ev['pattern']))}</code><br>"
                            f"строка: <code>{html.escape(str(ev['line']))}</code></li>"
                        )
                    else:
                        msg_txt = str(ev.get("message", ""))
                        lines_plain.append(f"      [{ts}] {ev['script']}: {msg_txt}")
                        html_parts.append(
                            f"<li><b>{html.escape(ev['script'])}</b> — "
                            f"<code>{ts}</code><br>{html.escape(msg_txt)}</li>"
                        )

                html_parts.append("</ul>")
            lines_plain.append("")

        return "\n".join(lines_plain), "\n".join(html_parts)

    def send_log_monitoring_notification(self, message: str) -> None:
        """Отправляет уведомление от мониторинга логов (отдельный тип)"""
        if self.config.get('settings_notify', {}).get('telegram', 'false').lower() == 'true':
            self._send_telegram_log_monitoring(message)

        if self.config.get('settings_notify', {}).get('email', 'false').lower() == 'true':
            self._send_email_log_monitoring(message)

    def _send_telegram_warning_single(self, event: Dict[str, Any]) -> None:
        """Отправляет ОДНО WARNING-событие в Telegram отдельным сообщением.
        Используется, когда событий за прогон меньше порога (см. flush_warning_notifications).
        """
        if not self.notify_config.get('telegram'):
            logger.error("Telegram конфиг не найден в notify.yaml")
            return

        try:
            import requests

            ts = event["time"].strftime('%Y-%m-%d %H:%M:%S')
            text = (
                f"⚠️ <b>MikroTik-ARMA: Log Monitor ({html.escape(hostname)})</b>\n"
                f"<b>Скрипт:</b> <code>{html.escape(event['category'])}/{html.escape(event['script'])}</code>\n"
                f"<b>Шаблон:</b> <code>{html.escape(str(event['pattern']))}</code>\n"
                f"<b>Строка:</b> <code>{html.escape(event['line'])}</code>\n"
                f"<b>Время:</b> <code>{ts}</code>"
            )

            MAX_LEN = 3500
            if len(text) > MAX_LEN:
                text = text[:MAX_LEN - 1] + "…"

            url = f"https://api.telegram.org/bot{self.notify_config['telegram']['bot_token']}/sendMessage"
            payload = {
                'chat_id': self.notify_config['telegram']['chat_id'],
                'text': text,
                'parse_mode': 'HTML',
            }
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            logger.debug(f"Telegram WARNING (single) отправлен: {response.status_code}")

        except Exception as e:
            logger.error(f"Ошибка отправки Telegram WARNING (single): {str(e)}")

    def _send_telegram_warning_file(self, plain_text: str) -> None:
        """Отправляет WARNING-отчёт в Telegram одним файлом (.log).
        Используется, когда событий за прогон >= порога.
        """
        if not self.notify_config.get('telegram'):
            logger.error("Telegram конфиг не найден в notify.yaml")
            return

        try:
            import requests

            ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            filename = f"arma_warnings_{ts}.log"
            content = plain_text.encode('utf-8')

            url = f"https://api.telegram.org/bot{self.notify_config['telegram']['bot_token']}/sendDocument"
            data = {
                'chat_id': self.notify_config['telegram']['chat_id'],
                'caption': f"⚠️ MikroTik-ARMA: WARNING-отчёт ({hostname})",
            }
            files = {
                'document': (filename, content, 'text/plain'),
            }
            response = requests.post(url, data=data, files=files, timeout=30)
            response.raise_for_status()
            logger.info(f"Telegram WARNING-файл отправлен: {filename} ({len(content)} байт)")

        except Exception as e:
            logger.error(f"Ошибка отправки Telegram WARNING-файла: {str(e)}")

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

    def _send_email_log_monitoring(self, plain: str, html_body: str) -> None:
        """Отправка сгруппированного WARNING-отчёта"""
        logger.debug("Отправка сгруппированного WARNING-отчёта...")

        if not self.notify_config.get('email'):
            logger.error("Email конфиг не найден в notify.yaml")
            return

        try:
            email_cfg = self.notify_config['email']

            subject = f"⚠️ MikroTik-ARMA: Log Monitoring Alert ({hostname})"

            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = email_cfg['from_addr']
            msg['To'] = email_cfg['to_addr']
            msg['Date'] = formatdate(localtime=True)
            msg.attach(MIMEText(plain, 'plain', 'utf-8'))
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))

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

            logger.info(f"Сгруппированный WARNING-отчёт отправлен на {email_cfg['to_addr']}")

        except Exception as e:
            logger.error(f"Ошибка отправки WARNING-отчёта: {str(e)}")

    def flush_warning_notifications(self) -> None:
        """Отправляет накопленные за прогон WARNING-события.

        Email: одним сгруппированным письмом.
        Telegram:
          - 0 событий          -> ничего
          - 1..9 событий       -> поштучно, каждое отдельным сообщением
          - >= 10 событий      -> одним файлом (.log)
        """
        if not self._warning_events:
            return

        plain, html_body = self._format_warning_report(self._warning_events)

        # Email — сгруппированный
        if self.config.get('settings_notify', {}).get('email', 'false').lower() == 'true':
            self._send_email_log_monitoring(plain, html_body)
        else:
            logger.debug("WARNING-буфер не отправлен на Email: email отключён в конфиге")

        # Telegram — маршрутизация по количеству событий
        if self.config.get('settings_notify', {}).get('telegram', 'false').lower() == 'true':
            TELEGRAM_FILE_THRESHOLD = 10
            if len(self._warning_events) >= TELEGRAM_FILE_THRESHOLD:
                self._send_telegram_warning_file(plain)
            else:
                for event in self._warning_events:
                    self._send_telegram_warning_single(event)
        else:
            logger.debug("WARNING-буфер не отправлен в Telegram: telegram отключён в конфиге")

        # Сброс буфера
        self._warning_events.clear()

    def run_script(self, script_category: str, script_name: str, base_name: str) -> bool:
        if getattr(self, '_shutdown_requested', False):
            logger.warning("Запуск скрипта отменён (завершение исполнения)")
            return False

        script_path = self.find_script_path(script_category, script_name)
        if not script_path or not script_path.exists():
            logger.error(f"[FAIL] Скрипт {script_category}/{script_name} не найден по пути: {script_path}")
            return False

        # Общий таймаут на запускаемый скрипт (сек). 0 = без таймаута.
        script_timeout = int(self.config.get('script_timeout', 0) or 0)

        try:
            logger.info(
                f"[START] Запуск {script_category}/{script_name}..."
                f"{f' (timeout={script_timeout}s)' if script_timeout else ''}"
            )
            start_time = time.time()

            process = subprocess.Popen(
                [sys.executable, str(script_path)],
                cwd=self.base_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                bufsize=1
            )

            output_lines = []
            timed_out = False
            aborted_by_shutdown = False

            import threading, queue
            q = queue.Queue()

            def _reader():
                try:
                    for ln in iter(process.stdout.readline, ''):
                        q.put(ln)
                finally:
                    q.put(None)

            threading.Thread(target=_reader, daemon=True).start()

            while True:
                # 1) Запрошено завершение оркестратора (Ctrl+C / SIGTERM)
                if getattr(self, '_shutdown_requested', False):
                    logger.warning(f"[ABORT] Запрошено завершение, остановка {script_category}/{script_name}")
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        logger.warning(
                            f"[ABORT] SIGTERM не сработал, применяется SIGKILL {script_category}/{script_name}"
                        )
                        process.kill()
                    timed_out = True
                    aborted_by_shutdown = True
                    break
                # 2) Общий таймаут скрипта
                if script_timeout and (time.time() - start_time) > script_timeout:
                    logger.error(
                        f"[TIMEOUT] Скрипт {script_category}/{script_name} "
                        f"превысил {script_timeout}s — принудительное завершение"
                    )
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        logger.warning(f"[TIMEOUT] SIGTERM не сработал, SIGKILL {script_category}/{script_name}")
                        process.kill()
                    timed_out = True
                    break

                # 3) Чтение строки с таймаутом 1 сек
                try:
                    line = q.get(timeout=1.0)
                except queue.Empty:
                    # 1 сек тишины
                    if process.poll() is not None and q.empty():
                        break
                    continue

                if line is None:
                    break

                line = line.strip()
                if line:
                    print(line)
                    output_lines.append(line)
                    self.check_log_patterns(line, script_category, script_name)

            process.wait()
            exec_time = time.time() - start_time

            if aborted_by_shutdown:
                # Остановка скрипта по SIGINT/SIGTERM — без инициализации ошибки.
                # Не пишет error-кэш (иначе ручной Ctrl+C заблокирует
                # перезапуск на restart_after_error часов) и не очищаем
                # существующую запись об ошибке — статус скрипта неизвестен.
                logger.warning(
                    f"[ABORT] Скрипт {script_category}/{script_name} "
                    f"прерван по запросу завершения оркестратора "
                    f"(отработал {exec_time:.1f}s)"
                )
                return False

            if timed_out:
                # Реальный таймаут {script_timeout} скрипта — фиксирует как ошибку.
                logger.error(
                    f"[FAIL] Скрипт {script_category}/{script_name} "
                    f"прерван (timeout={script_timeout}s, отработал {exec_time:.1f}s)"
                )
                if self.error_cache is not None:
                    self.error_cache.set_last_error_time(script_category, script_name, datetime.now())
                return False

            if process.returncode == 0:
                logger.info(f"[DONE] Скрипт {script_category}/{script_name} успешно выполнен за {exec_time:.1f} сек")
                if self.error_cache is not None:
                    self.error_cache.clear_error_time(script_category, script_name)
                return True
            else:
                logger.error(f"[FAIL] Скрипт {script_category}/{script_name} завершился с ошибкой (код {process.returncode})")
                if self.error_cache is not None:
                    self.error_cache.set_last_error_time(script_category, script_name, datetime.now())
                return False

        except Exception as e:
            logger.error(f"[ERROR] Неожиданная ошибка в {script_category}/{script_name}: {str(e)}")
            return False

    def print_scripts_info(self) -> None:
        """Выводит информацию об обнаруженных скриптах и порядке запуска"""

        SEP = "─" * 57  # ширина разделителя под шапку

        print("\n" + "=" * 60)
        print(f"🔍 MikroTik-ARMA Orchestrator: Информация о скриптах")
        print("=" * 60)

        # Информация о порядке выполнения
        print(f"\n📋 Порядок выполнения групп: {', '.join(self.execution_order)}")

        # Статистика по группам
        total_all = 0
        total_enabled = 0
        total_error_blocked = 0
        total_error_any = 0

        for category in self.execution_order:
            if category not in self.script_categories:
                print(f"\n⚠️  Группа '{category}' не содержит скриптов")
                continue

            scripts = self.script_categories[category]
            if not scripts:
                print(f"\n📁 {category.upper()}: нет скриптов")
                continue

            print(f"\n📁 {category.upper()} ({len(scripts)} {self._plural_scripts(len(scripts))}):")

            sorted_scripts = sorted(scripts)
            prev_base_name = None

            for idx, (base_name, full_name) in enumerate(sorted_scripts):
                enabled = self.is_script_enabled(category, base_name)
                cache_interval = self.get_cache_interval(category, base_name)

                # Разделитель при смене шаблона
                if idx > 0 and base_name != prev_base_name:
                    print(f"  {SEP}")
                prev_base_name = base_name

                status = "✅" if enabled else "❌"
                total_all += 1
                if enabled:
                    total_enabled += 1

                # Строка с информацией о кэше
                cache_info = f", кэш: {cache_interval}" if cache_interval != 'false' else ""

                print(f"  {status} {full_name} (шаблон: {base_name}{cache_info})")

                # Время последнего запуска из кэша + причина/статус следующего запуска
                if enabled and cache_interval != 'false':
                    cache_file = self.script_cache._get_cache_path(category, full_name)
                    interval_delta = self.script_cache.get_interval_delta(cache_interval)
                    now = datetime.now()

                    # 1) Кэш: когда последний запуск и когда следующий
                    cache_blocks_launch = False
                    next_run = None

                    if cache_file.exists() and interval_delta:
                        last_run = datetime.fromtimestamp(cache_file.stat().st_mtime)
                        next_run = last_run + interval_delta
                        print(f"      ⏱ Последний запуск: {last_run.strftime('%Y-%m-%d %H:%M')}")
                        if next_run > now:
                            cache_blocks_launch = True

                    # 2) Блокировка после ошибки
                    error_blocks_launch = False
                    restart_delay = self.config.get('settings_cache', {}).get('restart_after_error', 0)

                    if self.error_cache is not None:
                        last_error = self.error_cache.get_last_error_time(category, full_name)
                        if last_error is not None:
                            total_error_any += 1
                            if restart_delay > 0:
                                unblock_at = last_error + timedelta(hours=restart_delay)
                                if now < unblock_at:
                                    error_blocks_launch = True
                                    print(f"      ⚠️ Последняя ошибка: {last_error.strftime('%Y-%m-%d %H:%M')}, "
                                          f"разблокировка после {unblock_at.strftime('%Y-%m-%d %H:%M')}")
                            else:
                                print(f"      ⚠️ Последняя ошибка: {last_error.strftime('%Y-%m-%d %H:%M')} "
                                      f"(без блокировки, скрипт будет запущен)")

                    if error_blocks_launch:
                        total_error_blocked += 1

                    # 3) Итоговый статус: что произойдёт при следующем run()
                    if error_blocks_launch:
                        pass
                    elif cache_blocks_launch and next_run is not None:
                        remaining = next_run - now
                        hours, rem = divmod(int(remaining.total_seconds()), 3600)
                        minutes = rem // 60
                        print(f"      ⏭ Следующий запуск: {next_run.strftime('%Y-%m-%d %H:%M')} "
                              f"(через {hours}ч {minutes}м)")
                    else:
                        if cache_file.exists() and interval_delta:
                            print(f"      🔔 Следующий запуск: при следующем старте "
                                  f"(кэш просрочен с {next_run.strftime('%Y-%m-%d %H:%M')})")
                        else:
                            print(f"      🔔 Следующий запуск: при следующем старте (кэш отсутствует)")

        # Общая статистика
        print("\n" + "=" * 60)
        print(f"📊 ИТОГО:")
        print(f"   Всего скриптов: {total_all}")
        print(f"   Подключено: {total_enabled} ✅")
        print(f"   Отключено: {total_all - total_enabled} ❌")
        if total_error_any > 0:
            if total_error_blocked > 0:
                print(f"   Завершились с ошибкой: {total_error_blocked} ⚠️ "
                      f"(из них заблокированы от перезапуска)")
            else:
                print(f"   Завершились с ошибкой: {total_error_any} ⚠️ (блокировка не активна)")
        print("=" * 60 + "\n")

    def _run_category(self, category: str, stop_on_error: bool) -> tuple[bool, list[str]]:
        """Выполняет все скрипты одной категории.

        Возвращает (has_errors, messages) — флаг ошибок и строки для execution_log.
        """
        titles = {
            'additional': "Исполняется группа скриптов дополнительного функционала",
            'base': "Исполняется группа скриптов основного функционала",
            'maintenance': "Исполняется группа скриптов обслуживания",
        }
        title = titles.get(category)
        if title:
            logger.info(f"\n=== {title} ===")

        has_errors = False
        messages: list[str] = []

        for base_name, full_name in self.script_categories.get(category, []):
            if not self.is_script_enabled(category, base_name):
                msg = f"[SKIP] Скрипт {category}/{full_name} отключен в конфигурации"
                logger.info(msg)
                messages.append(msg)
                continue

            cache_interval = self.get_cache_interval(category, base_name)

            if not self.script_cache.is_script_required(category, full_name, cache_interval):
                msg = f"[CACHE] Скрипт {category}/{full_name} пропущен (кэш актуален)"
                logger.info(msg)
                messages.append(msg)
                continue

            if not self.should_restart_after_error(category, full_name):
                msg = (f"[ERROR_DELAY] Скрипт {category}/{full_name} пропущен "
                       f"(время до перезапуска после ошибки не истекло)")
                logger.info(msg)
                messages.append(msg)
                continue

            script_result = self.run_script(category, full_name, base_name)

            if script_result:
                self.script_cache.update_script_timestamp(category, full_name)
                messages.append(f"[OK] Скрипт {category}/{full_name} выполнен успешно")
            else:
                messages.append(f"[ERROR] Скрипт {category}/{full_name} завершился с ошибкой")
                has_errors = True
                if stop_on_error:
                    break

        return has_errors, messages

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
            self.send_push_heartbeat(is_fatal=True)
            sys.exit(1)

        # Обнаружение скриптов
        self.script_categories['additional'] = self._discover_additional_scripts()
        self.script_categories['base'] = self._discover_base_scripts()
        self.script_categories['maintenance'] = self._discover_maintenance_scripts()

        logger.info(f"Обнаружено дополнительных скриптов: {len(self.script_categories['additional'])}")
        logger.info(f"Обнаружено базовых скриптов: {len(self.script_categories['base'])}")
        logger.info(f"Обнаружено обслуживающих скриптов: {len(self.script_categories['maintenance'])}")

        # Инициализация кэшей
        try:
            self.script_cache = ScriptCache(self.base_dir)
        except Exception as e:
            logger.error(f"Ошибка инициализации кэша: {e}")
            self.send_notification("Ошибка инициализации кэша!", True)
            self.send_push_heartbeat(is_fatal=True)
            sys.exit(1)

        try:
            self.error_cache = ErrorCache(self.base_dir)
        except Exception as e:
            logger.error(f"Ошибка инициализации кэша ошибок: {e}")
            self.send_notification("Ошибка инициализации кэша ошибок", True)
            self.send_push_heartbeat(is_fatal=True)
            sys.exit(1)

        # Режим проверки -> вывод информации
        if check_only:
            self.print_scripts_info()
            return

        # Runtime-лок только для реального прогона
        if not self._acquire_lock():
            sys.exit(0)

        try:
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

            # Сбор всех сообщений
            execution_log = []
            has_errors = False
            stop_on_error = self.config.get('settings_notify', {}).get('stop_on_error', 'true') == 'true'

            # Запуск скриптов по категориям
            for category in self.execution_order:
                if has_errors and stop_on_error:
                    break

                cat_errors, cat_log = self._run_category(category, stop_on_error)
                execution_log.extend(cat_log)
                has_errors = has_errors or cat_errors

                if has_errors and stop_on_error:
                    break

            # Группа WARNING-уведомлений
            self.flush_warning_notifications()

            # Итоговый отчет (бинарный статус конвейера)
            if has_errors:
                final_status = "Конвейер выполнен с ошибками"
            else:
                final_status = "Конвейер выполнен успешно"

            full_report = f"{final_status}\n\nДетальный лог:\n" + "\n".join(execution_log)

            # Отправка уведомлений
            if self.should_notify(has_errors):
                if self.config.get('settings_notify', {}).get('email', 'false') == 'true':
                    self._send_email(full_report, has_errors)

                if self.config.get('settings_notify', {}).get('telegram', 'false') == 'true':
                    self._send_telegram(final_status, has_errors)

            # Push-heartbeat: "оркестратор жив"
            self.send_push_heartbeat(is_fatal=False)

            if has_errors:
                sys.exit(1)

            logger.info("=" * 36)
            logger.info("MikroTik-ARMA Orchestrator: FINISHED")
            logger.info("=" * 36)

        finally:
            # Освобождает лок
            self._release_lock()

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
