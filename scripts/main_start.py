#!/usr/bin/env python3
import os
import sys
import yaml
import json
import logging
import subprocess
import time
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
        """Парсим строку интервала (1m, 5h и т.д.)"""
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

class ProjectOrchestrator:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.config: Dict[str, Any] = {}
        self.telegram_config: Dict[str, str] = {}

        # Определение порядка выполнения скриптов по категориям
        self.script_categories = {
            'base': [
                'dns_fwd',
                'fetch_as_prefixes',
                'converter_addressLists',
                'sync_master',
                'sync_slave',
                'logs_rotate'
            ],
            'additional': [],
            'maintenance': [
                'logs_rotate'  # добавляем сюда
            ]
        }

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

    def _get_base_script_name(self, full_name: str) -> str:
        """Извлекает базовое имя скрипта из полного имени на основе правил из конфига"""

        # Получение правила из configs/config.yaml
        base_name_patterns = self.config.get('scripts_discovery', {}).get('additional', {}).get('base_name_patterns', {})

        for base_name, pattern in base_name_patterns.items():
            if re.match(pattern, full_name):
                return base_name
        return full_name  # если правило не нашли, используем полное имя

    def _handle_signal(self, signum, frame):
        """Обработчик сигналов завершения"""
        logger.warning(f"Получен сигнал {signum}, инициирую завершение...")
        self._shutdown_requested = True
        self.send_notification(f"Получен сигнал завершения {signum}", True)

    def load_configs(self) -> bool:
        """Загрузка конфигурационного файла"""
        try:
            config_path = self.base_dir / 'configs' / 'config.yaml'
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f).get('main_start', {})

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
                'text': f"{emoji} <b>MikroTik-ARMA</b>: <i>{message}</i>",
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

            subject = "❌ MikroTik-ARMA: Failure" if is_error else "✅ MikroTik-ARMA: Success"
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
                break  # Отправляем одно уведомление на строку

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
                'text': f"⚠️ <b>MikroTik-ARMA: Log Monitor</b>: <i>{message}</i>",
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
            subject = "⚠️ MikroTik-ARMA: Log Monitoring Alert"

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
                return True
            else:
                logger.error(f"[FAIL] Скрипт {script_category}/{script_name} завершился с ошибкой (код {process.returncode})")
                return False

        except Exception as e:
            logger.error(f"[ERROR] Неожиданная ошибка в {script_category}/{script_name}: {str(e)}")
            return False

    def run(self) -> None:
        """Основной метод запуска оркестратора"""
        logger.info(f"\n")
        logger.info("=" * 25)
        logger.info("MikroTik-ARMA Orchestrator: START")
        logger.info("=" * 25)

        logger.debug(f"Проверка конфига: email={self.config.get('settings_notify', {}).get('email')}")
        logger.debug(f"Полный конфиг: {json.dumps(self.config, indent=2, default=str)}")
        logger.debug(f"Конфиг уведомлений: {json.dumps(self.notify_config, indent=2)}")

        if self.config.get('settings_notify', {}).get('email') == 'true':
            logger.debug("Проверка конфигурации email...")
            email_cfg = self.notify_config.get('email', {})
            logger.debug(f"SMTP сервер: {email_cfg.get('smtp_server')}:{email_cfg.get('smtp_port')}")
            logger.debug(f"Логин: {email_cfg.get('login')}")
            logger.debug(f"Получатель: {email_cfg.get('to_addr')}")

        # Инициализация
        if not all([
            self.load_configs(),
            self.load_notify_config(),
            self.ensure_directories()
        ]):
            self.send_notification("Ошибка инициализации!", True)
            sys.exit(1)

        # Настройка мониторинга логов
        self.setup_log_monitoring()

        # Заполняет список additional скриптов на основе configs/config.yaml
        self.script_categories['additional'] = self._discover_additional_scripts()
        logger.info(f"Обнаружено дополнительных скриптов: {len(self.script_categories['additional'])}")

        # Доступность кэша
        try:
            self.script_cache = ScriptCache(self.base_dir)
        except Exception as e:
            logger.error(f"Ошибка инициализации кэша: {e}")
            self.send_notification("Ошибка инициализации кэша!", True)
            sys.exit(1)

        # Подсчёт общего количества активных скриптов
        total_scripts = 0
        for category in ['additional', 'base', 'maintenance']:
            if category not in self.script_categories:
                continue

            if category == 'additional':
                # В additional учитываем только включеные в конфиге
                for base_name, full_name in self.script_categories[category]:
                    if self.is_script_enabled(category, base_name):
                        total_scripts += 1
            else:
                category_config = self.config.get('launch_chain', {}).get(category, {})
                for script in self.script_categories[category]:
                    if category_config.get(script, False):
                        total_scripts += 1

        logger.debug(f"Всего активных скриптов: {total_scripts}")

        # Сбор всех сообщений
        execution_log = []
        success_count = 0
        has_errors = False

        # Запуск скриптов по категориям
        for category in ['additional', 'base', 'maintenance']:  # Порядок исполнения категорий скриптов: additional -> base -> maintenance
            if category not in self.script_categories:
                continue

            # Заголовок группы
            if category == 'additional':
                logger.info("\n=== Исполняется группа скриптов дополнительного функционала ===")
            elif category == 'base':
                logger.info("\n=== Исполняется группа скриптов основного функционала ===")
            elif category == 'maintenance':
                logger.info("\n=== Исполняется группа скриптов обслуживания ===")

            if category == 'base':
                # Обработка base скриптов
                for script_name in self.script_categories[category]:
                    if not self.is_script_enabled(category, script_name):
                        msg = f"[SKIP] Скрипт {category}/{script_name} отключен в конфигурации"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    cache_interval = self.get_cache_interval(category, script_name)

                    if not self.script_cache.is_script_required(category, script_name, cache_interval):
                        msg = f"[CACHE] Скрипт {category}/{script_name} пропущен (кэш актуален)"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    script_result = self.run_script(category, script_name, script_name)
                    if script_result:
                        success_count += 1
                        self.script_cache.update_script_timestamp(category, script_name)
                        execution_log.append(f"[OK] Скрипт {category}/{script_name} выполнен успешно")
                    else:
                        execution_log.append(f"[ERROR] Скрипт {category}/{script_name} завершился с ошибкой")
                        has_errors = True
                        if self.config.get('settings_notify', {}).get('stop_on_error', 'true') == 'true':
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

                    script_result = self.run_script(category, full_name, base_name)
                    if script_result:
                        success_count += 1
                        self.script_cache.update_script_timestamp(category, full_name)
                        execution_log.append(f"[OK] Скрипт {category}/{full_name} выполнен успешно")
                    else:
                        execution_log.append(f"[ERROR] Скрипт {category}/{full_name} завершился с ошибкой")
                        has_errors = True
                        if self.config.get('settings_notify', {}).get('stop_on_error', 'true') == 'true':
                            break

            elif category == 'maintenance':
                # Обработка maintenance скриптов (аналогично base)
                for script_name in self.script_categories[category]:
                    if not self.is_script_enabled(category, script_name):
                        msg = f"[SKIP] Скрипт {category}/{script_name} отключен в конфигурации"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    cache_interval = self.get_cache_interval(category, script_name)

                    if not self.script_cache.is_script_required(category, script_name, cache_interval):
                        msg = f"[CACHE] Скрипт {category}/{script_name} пропущен (кэш актуален)"
                        logger.info(msg)
                        execution_log.append(msg)
                        continue

                    script_result = self.run_script(category, script_name, script_name)
                    if script_result:
                        success_count += 1
                        self.script_cache.update_script_timestamp(category, script_name)
                        execution_log.append(f"[OK] Скрипт {category}/{script_name} выполнен успешно")
                    else:
                        execution_log.append(f"[ERROR] Скрипт {category}/{script_name} завершился с ошибкой")
                        has_errors = True
                        if self.config.get('settings_notify', {}).get('stop_on_error', 'true') == 'true':
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

        logger.info("=" * 27)
        logger.info("MikroTik-ARMA Orchestrator: FINISHED")
        logger.info("=" * 27)

if __name__ == "__main__":
    orchestrator = ProjectOrchestrator()
    orchestrator.run()
