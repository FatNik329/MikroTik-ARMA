#!/usr/bin/env python3
"""
Скрипт динамического анонсирования BGP-маршрутов для ExaBGP на основе TXT файлов (простой список)
"""

import sys
import os
import time
import logging
from pathlib import Path
from ipaddress import ip_network
import signal
import json
import hashlib
import select
from datetime import datetime
import threading
import socket
import json as json_module
from http.server import HTTPServer, BaseHTTPRequestHandler

# ============
# КОНФИГУРАЦИЯ
# ============
DEFAULT_CONFIG = {
# ОБЩИЕ ПАРАМЕТРЫ ХРАНЕНИЯ И ОБРАБОТКИ ДАННЫХ
    # Настройки логирования
    'logging': {
        'log_level': 'INFO',  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    },
    # Директория хранения логов (указать абсолютный путь)
    'logs_dir': '/path/to/MikroTik-ARMA/logs/daemon/bgp_announce_routes',

    # Мониторинг система
    'monitoring': {
        'listen_port': 55144,         # TCP порт для health check (0 = отключить)
        'health_check_interval': 30,  # Интервал проверки состояния ExaBGP (секунды)
        'exabgp_response_timeout': 5, # Таймаут ожидания ответа от ExaBGP
    },

    # Обязательные параметры - пути к TXT файлам с IP (указать абсолютный путь)
    ## Каждый путь - отдельный лист маршрутизации
    'path_list_announce': {
        'Example-list-1': '/path/to/MikroTik-ARMA/raw-data/Example-list-1/TXT',
        'Example-list-2': '/path/to/MikroTik-ARMA/raw-data/Example-list-2/TXT',
        'Example-list-3': '/path/to/MikroTik-ARMA/raw-data/Example-list-3/TXT',
		#'...'
   },

    # Директория хранения кэш файла JSON (указать абсолютный путь)
    'cache_dir': '/path/to/MikroTik-ARMA/cache/bgp_announce_routes',
    # Интервал обновления в секундах (3600 = 1 час)
    'update_interval': 300,
    #'update_interval': 60,

    # Настройки поиска и обработки маршрутов
    'recursive_search': True,   # Рекурсивный поиск TXT файлов в поддиректориях

    'remove_duplicates': True,  # Удаление дубликатов IP адресов в пределах обрабатываемого листа.
                                # Пересечение адресов (между маршрутными листами) не учитывается.

#------------------------------------------------------------------------
# ПАРАМЕТРЫ МАРШРУТНЫХ ЛИСТОВ И АТРИБУТОВ
    # Переопределения атрибутов для конкретных групп (при необходимости)
    'group_attributes': {
        'Example-list-1': {
            'communities': ['64512:100'],
            'as_path': ['65001 65002'],
            'local_preference': 200,
        },
        'Example-list-2': {
            'communities': ['64512:200'],
        },
        'Example-list-3': {
            'communities': ['64512:300'],
        },
    },

    # Общие BGP-атрибуты (используются по умолчанию)
    'next_hop': 'self',        # Использовать локальный IP роутера
    'communities': 'none',     # или в формате ['65001:100']
    'as_path': [],             # Пустой список по умолчанию
    'local_preference': None,  # По умолчанию не установлено
    'med': None,               # По умолчанию не установлено
    'origin': 'igp',           # igp|egp|incomplete

#----------------------------------------------------------------------------
# ПАРАМЕТРЫ ВЗАИМОДЕЙСТВИЯ С ExaBGP
# ИЗМЕНЯТЬ С ОСТОРОЖНОСТЬЮ - подобраны и выставлены оптимальные параметры

    # Настройки ограничения скорости отправки команд
    'rate_limiting': {
        'routes_per_second': 100,         # Максимальное количество маршрутов в секунду
        'batch_size': 50,                 # Размер пачки перед паузой
        'delay_between_batches': 0.5,     # Задержка между пачками (секунды)
        'delay_between_routes': 0.01,     # Базовая задержка между маршрутами
        'max_delay_between_routes': 0.1,  # Максимальная задержка при перегрузке
    },
    # Режим отправки маршрутов
    'announce_mode': 'bulk',           # 'bulk' или 'individual'
    'bulk_size': 100,                  # Максимальное количество маршрутов в одной bulk команде
    'use_bulk_for_withdrawals': True,  # Использовать bulk для отзыва
}

# ================
# МОНИТОРИНГ
# ================
class HealthCheckHandler(BaseHTTPRequestHandler):
    """Обработчик HTTP запросов для health check"""
    def do_GET(self):
        if self.path == '/health':
            health_status = get_health_status()

            self.send_response(200 if health_status['status'] == 'healthy' else 503)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            response = json_module.dumps(health_status, indent=2, ensure_ascii=False)
            self.wfile.write(response.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

health_status = {
    'status': 'starting',  # starting, healthy, degraded, unhealthy
    'exabgp_alive': False,
    'last_exabgp_check': None,
    'last_successful_operation': None,
    'errors': [],
    'statistics': {
        'total_routes_announced': 0,
        'total_routes_withdrawn': 0,
        'last_update_time': None,
        'update_cycles': 0,
    }
}

health_lock = threading.Lock()
exabgp_last_response_time = None

def check_exabgp_health():
    """Упрощенная проверка ExaBGP"""
    global exabgp_last_response_time

    # Если последняя операция была успешной менее чем N секунд назад,
    # считается ExaBGP -> is alive
    last_op = health_status.get('last_successful_operation')

    if last_op:
        try:
            last_op_time = datetime.fromisoformat(last_op['time']).timestamp()
            if time.time() - last_op_time < 300:  # 5 минут
                with health_lock:
                    health_status['exabgp_alive'] = True
                    health_status['last_exabgp_check'] = datetime.now().isoformat()
                return True
        except:
            pass

    script_uptime = time.time() - script_start_time
    if script_uptime < 600:  # Первые 10 минут после старта
        with health_lock:
            health_status['exabgp_alive'] = True
            health_status['last_exabgp_check'] = datetime.now().isoformat()
        return True

    return False

def get_health_status():
    """Возвращает текущий статус здоровья системы"""
    global health_status

    with health_lock:
        # Общий статус
        status = 'healthy'

        # Для мониторинга - простой статус up/down
        monitoring_status = 'up'

        # Проверка ExaBGP
        if not health_status['exabgp_alive']:
            status = 'unhealthy'
            monitoring_status = 'down'
        elif health_status['status'] == 'degraded':
            status = 'degraded'
            monitoring_status = 'down'

        response = health_status.copy()
        response['status'] = status

        # Поля для мониторинга
        response['monitoring'] = {
            'status': monitoring_status,
            'response_time': 0,
            'timestamp': datetime.now().isoformat()
        }

        # Числовые метрики
        response['metrics'] = {
            'routes_total': response['statistics']['total_routes_announced'] - response['statistics']['total_routes_withdrawn'],
            'routes_announced': response['statistics']['total_routes_announced'],
            'routes_withdrawn': response['statistics']['total_routes_withdrawn'],
            'update_cycles': response['statistics']['update_cycles'],
            'errors_count': len(response['errors']),
            'uptime_seconds': time.time() - script_start_time
        }

        response['timestamp'] = datetime.now().isoformat()
        response['script_uptime'] = time.time() - script_start_time

        response['groups'] = {}
        total_active_routes = 0

        for group_name in DEFAULT_CONFIG['path_list_announce'].keys():
            group_info = {
                'enabled': True,
                'last_checked': None,
                'routes_count': 0,
                'status': 'unknown'
            }

            cache_data = load_cache()
            if 'groups' in cache_data and group_name in cache_data['groups']:
                group_info['last_checked'] = cache_data['groups'][group_name].get('last_updated')
                group_info['routes_count'] = cache_data['groups'][group_name].get('total_routes', 0)
                group_info['status'] = 'active'
                total_active_routes += group_info['routes_count']

            response['groups'][group_name] = group_info

        # Общее количество активных маршрутов
        response['metrics']['active_routes'] = total_active_routes

        # Информация о конфигурации
        response['config'] = {
            'update_interval': DEFAULT_CONFIG['update_interval'],
            'groups_count': len(DEFAULT_CONFIG['path_list_announce']),
            'monitoring_port': DEFAULT_CONFIG['monitoring']['listen_port']
        }

        return response

def update_health_statistics(operation_type, count=1, success=True, error=None):
    """Обновляет статистику здоровья"""
    global health_status

    with health_lock:
        if operation_type == 'announce':
            health_status['statistics']['total_routes_announced'] += count
        elif operation_type == 'withdraw':
            health_status['statistics']['total_routes_withdrawn'] += count
        elif operation_type == 'update_cycle':
            health_status['statistics']['update_cycles'] += 1
            health_status['statistics']['last_update_time'] = datetime.now().isoformat()

        if success:
            health_status['last_successful_operation'] = {
                'type': operation_type,
                'time': datetime.now().isoformat(),
                'count': count
            }
        elif error:
            # Сохраняет последние N ошибок
            if len(health_status['errors']) > 10: # 10 ошибок
                health_status['errors'] = health_status['errors'][-10:]
            health_status['errors'].append({
                'time': datetime.now().isoformat(),
                'error': error,
                'operation': operation_type
            })

            # Если много ошибок - меняет статус
            if len(health_status['errors']) > 5:
                health_status['status'] = 'degraded'

def start_health_check_server():
    """Запускает HTTP сервер для health check в отдельном потоке"""
    port = DEFAULT_CONFIG['monitoring']['listen_port']

    if port == 0:
        logger.info("Health check сервер отключен (port=0)")
        return None

    def run_server():
        server = HTTPServer(('0.0.0.0', port), HealthCheckHandler)
        server.allow_reuse_address = True
        logger.info(f"Health check сервер запущен на порту {port}")
        console_logger.info(f"Health check endpoint: http://localhost:{port}/health")

        try:
            server.serve_forever()
        except Exception as e:
            logger.error(f"Ошибка health check сервера: {e}")
        finally:
            server.server_close()

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    return server_thread

# =========================
# ДОПОЛНИТЕЛЬНЫЙ ФУНКЦИОНАЛ
# =========================
# Управление выполнением цикла
running = True

# Автоматическое определение имени лог файла и кэш файла
script_name = Path(__file__).stem
log_filename = f"{script_name}.log"
cache_filename = f"{script_name}_cache.json"

# Создание директории для логов
log_path = Path(DEFAULT_CONFIG['logs_dir']) / log_filename
log_path.parent.mkdir(parents=True, exist_ok=True)

# Создание директории для кэша
cache_path = Path(DEFAULT_CONFIG['cache_dir']) / cache_filename
cache_path.parent.mkdir(parents=True, exist_ok=True)

# Настройка логирования
logging.basicConfig(
    level=getattr(logging, DEFAULT_CONFIG['logging']['log_level']),
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_path, encoding='utf-8'),
    ]
)

logger = logging.getLogger(__name__)

console_logger = logging.getLogger('console')
console_logger.addHandler(logging.StreamHandler(sys.stderr))
console_logger.setLevel(logging.INFO)

def signal_handler(signum, frame):
    """Обработчик сигналов для корректного завершения"""
    global running
    logger.info(f"Получен сигнал {signum}. Инициировано graceful shutdown")
    console_logger.info(f"Получен сигнал {signum}. Начинаем graceful shutdown...")

    # SIGTERM/SIGINT запускает graceful shutdown
    if signum in (signal.SIGTERM, signal.SIGINT):
        running = False
        time.sleep(0.5)
        graceful_shutdown()
        sys.exit(0)

# Обработчики сигналов
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def wait_for_exabgp_ready(timeout=10):
    """
    Ждёт подтверждения от ExaBGP, что он готов принимать команды.
    Читает сообщения 'initialized' или 'ready' от ExaBGP.
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            # Неблокирующая проверка stdin
            ready, _, _ = select.select([sys.stdin], [], [], 0.1)
            if ready:
                line = sys.stdin.readline().strip()
                if line:
                    logger.debug(f"ExaBGP сообщение: {line}")
                    if 'ready' in line.lower() or 'initialized' in line.lower():
                        logger.info("ExaBGP готов")
                        return True
        except Exception as e:
            logger.error(f"Ошибка при ожидании ExaBGP: {e}")
            break
        time.sleep(0.01)

    logger.warning("Таймаут ожидания готовности ExaBGP, ожидание...")
    return False

def normalize_prefix(prefix: str) -> str:
    """Нормализует префикс/IP"""
    prefix = prefix.strip()

    # Удаляет комментарии
    if '#' in prefix:
        prefix = prefix.split('#')[0].strip()

    # Пропуск пустых строк
    if not prefix:
        return None

    # Наличие CIDR
    if '/' not in prefix:
        prefix = f"{prefix}/32"

    try:
        network = ip_network(prefix, strict=False)
        return str(network)
    except ValueError:
        return None

def calculate_file_hash(file_path: Path) -> str:
    """Вычисляет хеш файла для отслеживания изменений"""
    try:
        with open(file_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception as e:
        logger.error(f"Ошибка вычисления хеша файла {file_path}: {e}")
        return None

def calculate_directory_state(directory_path: str) -> dict:
    """Вычисляет состояние директории: список файлов и их хеши"""
    state = {'files': {}, 'total_files': 0}
    dir_path = Path(directory_path)

    if not dir_path.exists() or not dir_path.is_dir():
        return state

    # Поиск файлов рекурсивно
    if DEFAULT_CONFIG['recursive_search']:
        txt_files = sorted(dir_path.rglob("*.txt"))
    else:
        txt_files = sorted(dir_path.glob("*.txt"))

    for txt_file in txt_files:
        try:
            file_hash = calculate_file_hash(txt_file)
            if file_hash:
                # Относительный путь для сравнения
                rel_path = str(txt_file.relative_to(dir_path))
                state['files'][rel_path] = {
                    'hash': file_hash,
                    'size': txt_file.stat().st_size,
                    'mtime': txt_file.stat().st_mtime
                }
                state['total_files'] += 1
        except Exception as e:
            logger.error(f"Ошибка обработки файла {txt_file}: {e}")

    return state

def load_cache() -> dict:
    """Загружает кэш из файла"""
    if not cache_path.exists():
        console_logger.info("Кэш-файл не найден, будет создан новый")
        logger.info("Кэш-файл не найден, создаётся новый")
        return {}

    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Ошибка загрузки кэша: {e}")
        console_logger.error(f"Ошибка загрузки кэша: {e}")
        return {}

def save_cache(cache_data: dict):
    """Сохраняет кэш в файл"""
    try:
        # Добавляет метаданные
        cache_data['_metadata'] = {
            'last_update': datetime.now().isoformat(),
            'script': script_name,
            'config_used': {
                'recursive_search': DEFAULT_CONFIG['recursive_search'],
                'remove_duplicates': DEFAULT_CONFIG['remove_duplicates']
            }
        }

        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)

        # Устанавливает корректные права на файл кэша
        os.chmod(cache_path, 0o755)

        logger.debug(f"Кэш сохранён: {cache_path}")
    except Exception as e:
        logger.error(f"Ошибка сохранения кэша: {e}")
        console_logger.error(f"Ошибка сохранения кэша: {e}")

def compare_states(old_state: dict, new_state: dict) -> tuple:
    """Сравнивает два состояния и возвращает изменения"""
    changes = {
        'added': [],
        'modified': [],
        'removed': []
    }

    old_files = set(old_state.get('files', {}).keys())
    new_files = set(new_state.get('files', {}).keys())

    changes['added'] = sorted(new_files - old_files)

    changes['removed'] = sorted(old_files - new_files)

    common_files = old_files.intersection(new_files)
    for file in common_files:
        if old_state['files'][file]['hash'] != new_state['files'][file]['hash']:
            changes['modified'].append(file)

    return changes

def graceful_shutdown():
    """Выполняет корректное завершение с отзывом всех маршрутов"""
    global running, health_status

    with health_lock:
        health_status['status'] = 'shutting_down'

    console_logger.info("=" * 64)
    console_logger.info("Graceful shutdown - отзыв всех маршрутов")
    console_logger.info("=" * 64)

    logger.info("Graceful shutdown")

    cache_data = load_cache()

    # Отзывает маршруты для всех групп
    if 'groups' in cache_data:
        for group_name in cache_data['groups'].keys():
            if group_name in DEFAULT_CONFIG['path_list_announce']:
                routes = cache_data['groups'][group_name].get('routes', [])
                if routes:
                    console_logger.info(f"Отзыв маршрутов группы '{group_name}' ({len(routes)} маршрутов)")
                    logger.info(f"Отзыв маршрутов группы '{group_name}': {len(routes)} маршрутов")

                    try:
                        # Использует bulk для быстрого отзыва
                        withdraw_routes_bulk(group_name, routes)
                    except Exception as e:
                        logger.error(f"Ошибка при отзыве маршрутов группы '{group_name}': {e}")
                        console_logger.error(f"Ошибка отзыва группы '{group_name}': {e}")

    console_logger.info("Все маршруты отозваны")
    logger.info("Graceful shutdown завершен")

    with health_lock:
        health_status['status'] = 'stopped'

# ===================
# ОСНОВНОЙ ФУНКЦИОНАЛ
# ===================
def withdraw_route(route: str, group_name: str):
    """Отзывает маршрут с теми же атрибутами, что и при анонсе"""
    # Получает все атрибуты - аналогичные при анонсировании
    next_hop = get_group_attribute(group_name, 'next_hop')
    communities = get_group_attribute(group_name, 'communities')
    as_path = get_group_attribute(group_name, 'as_path')
    local_pref = get_group_attribute(group_name, 'local_preference')
    med = get_group_attribute(group_name, 'med')
    origin = get_group_attribute(group_name, 'origin')

    # Формирует команду отзыва
    cmd = f"withdraw route {route} next-hop {next_hop}"

    # Добавляет атрибуты
    if communities and communities != 'none':
        if isinstance(communities, list):
            comm_str = ' '.join([f"[{comm}]" for comm in communities])
        else:
            comm_str = f"[{communities}]"
        cmd += f" community {comm_str}"

    if as_path and isinstance(as_path, list) and len(as_path) > 0:
        as_str = ' '.join([str(asn) for asn in as_path])
        cmd += f" as-path [{as_str}]"

    if local_pref is not None and isinstance(local_pref, (int, float)):
        cmd += f" local-preference {int(local_pref)}"

    if med is not None and isinstance(med, (int, float)):
        cmd += f" med {int(med)}"

    if origin and origin != 'igp':
        cmd += f" origin {origin}"

    # Полная команда для лога
    logger.debug(f"Отправка команды отзыва: {cmd}")

    sys.stdout.write(cmd + "\n")
    sys.stdout.flush()

    # Подтверждение отправки команды - успех
    logger.debug(f"Команда отзыва отправлена: {route}")

    console_logger.debug(f"Отозван {route} из группы '{group_name}'")
    logger.debug(f"Отозван маршрут {route} группы '{group_name}'")

def withdraw_routes_individual(group_name: str, routes: list):
    """Отзывает список маршрутов с ограничением скорости"""
    if not routes:
        return

    # Выбирает режим отзыва
    use_bulk = DEFAULT_CONFIG.get('use_bulk_for_withdrawals', True)

    if use_bulk and len(routes) > 5:  # Для 5+ маршрутов использует bulk
        withdraw_routes_bulk(group_name, routes)
        return

    console_logger.info(f"Отзыв {len(routes)} маршрутов из группы {group_name}")
    logger.info(f"Начало отзыва группы '{group_name}': {len(routes)} маршрутов")

    sent_count = 0
    batch_size = 100
    delay_between_batches = 0.3
    delay_between_routes = 0.005  # Отзыв может быть быстрее чем анонс

    for i, route in enumerate(routes):
        try:
            withdraw_route(route, group_name)
            sent_count += 1

            # Проверка сообщения от ExaBGP
            try:
                ready, _, _ = select.select([sys.stdin], [], [], 0.001)
                if ready:
                    message = sys.stdin.readline().strip()
                    if message:
                        logger.debug(f"ExaBGP сообщение во время отзыва: {message}")
            except Exception:
                pass

            # Задержка между маршрутами
            if i % 20 == 0:  # Каждые 20 маршрутов
                time.sleep(delay_between_routes)

            # Задержка между пачками
            if sent_count % batch_size == 0:
                time.sleep(delay_between_batches)

                if not running:
                    console_logger.warning("Получен сигнал остановки, прерывание отзыва")
                    break

        except BrokenPipeError:
            logger.error(f"BrokenPipeError при отзыве маршрута {route}")
            console_logger.error("ExaBGP перестал читать команды! Прерываем отзыв.")
            update_health_statistics('withdraw', sent_count, success=False, error='BrokenPipeError: ExaBGP stopped responding')
            break
        except Exception as e:
            logger.error(f"Ошибка при отзыве маршрута {route}: {e}")
            console_logger.error(f"Ошибка отзыва: {e}")
            break

    console_logger.info(f"Завершён отзыв группы {group_name}: отозвано {sent_count}/{len(routes)} маршрутов")
    logger.info(f"Завершён отзыв группы '{group_name}': отозвано {sent_count}/{len(routes)} маршрутов")
    update_health_statistics('withdraw', sent_count, success=True)

def withdraw_routes_bulk(group_name: str, routes: list):
    """Отзывает маршруты пачками через bulk commands"""
    if not routes:
        return

    if not running:
        logger.debug(f"Пропуск отзыва для {group_name}, т.к. running=False")
        return

    console_logger.info(f"Bulk отзыв {len(routes)} маршрутов из группы {group_name}")
    logger.info(f"Начало bulk отзыва группы '{group_name}': {len(routes)} маршрутов")

    # Получает атрибуты для группы (для withdraw может потребоваться next-hop)
    next_hop = get_group_attribute(group_name, 'next_hop')
    communities = get_group_attribute(group_name, 'communities')

    # Строка атрибутов для withdraw
    # Обычно для withdraw достаточно next-hop, но если в конфиге указаны communities, их тоже указать
    attributes_parts = []

    # Включает next-hop если он не 'self' или если специфично требуется
    if next_hop != 'self':
        attributes_parts.append(f"next-hop {next_hop}")

    # Включает communities если они есть
    if communities and communities != 'none':
        if isinstance(communities, list):
            comm_str = ' '.join([f"[{comm}]" for comm in communities])
        else:
            comm_str = f"[{communities}]"
        attributes_parts.append(f"community {comm_str}")

    attributes_str = ' '.join(attributes_parts) if attributes_parts else ''

    # Разбивает маршруты на пачки
    bulk_size = DEFAULT_CONFIG.get('bulk_size', 100)
    total_sent = 0
    batch_count = 0

    for i in range(0, len(routes), bulk_size):
        batch = routes[i:i + bulk_size]
        batch_count += 1

        # Формирует bulk команду withdraw
        nlri_list = ' '.join(batch)
        if attributes_str:
            cmd = f"withdraw attributes {attributes_str} nlri {nlri_list}"
        else:
            cmd = f"withdraw attributes nlri {nlri_list}"

        # Логирует информацию о пачке
        console_logger.debug(f"Bulk отзыв пачка {batch_count}: {len(batch)} маршрутов")
        logger.debug(f"Группа '{group_name}': bulk отзыв пачка {batch_count}, размер {len(batch)}")

        try:
            # Отправляет команду
            sys.stdout.write(cmd + "\n")
            sys.stdout.flush()
            total_sent += len(batch)

            # Проверяет сообщения от ExaBGP
            try:
                ready, _, _ = select.select([sys.stdin], [], [], 0.001)
                if ready:
                    message = sys.stdin.readline().strip()
                    if message:
                        logger.debug(f"ExaBGP сообщение во время bulk отзыва: {message}")
            except Exception:
                pass

            # Задержка между пачками
            if batch_count % 20 == 0:  # Каждые 20 пачек
                time.sleep(0.05)

            if not running:
                console_logger.warning("Получен сигнал остановки, прерываем bulk отзыв")
                break

        except BrokenPipeError:
            logger.error(f"BrokenPipeError при bulk отзыве пачки {batch_count}")
            console_logger.error("ExaBGP перестал читать команды! Прерываем отзыв.")
            update_health_statistics('withdraw', total_count, success=False, error='BrokenPipeError: ExaBGP stopped responding')
            break
        except Exception as e:
            logger.error(f"Ошибка при bulk отзыве пачки {batch_count}: {e}")
            console_logger.error(f"Ошибка bulk отзыва: {e}")
            break

    console_logger.info(f"Завершён bulk отзыв '{group_name}': {total_sent}/{len(routes)} маршрутов в {batch_count} пачках")
    logger.info(f"Завершён bulk отзыв группы '{group_name}': {total_sent} маршрутов, {batch_count} пачек")
    update_health_statistics('withdraw', total_sent, success=True)

def flush_all_routes(group_name: str):
    """Отзывает все маршруты группы"""
    cmd = f"flush route {group_name}"
    sys.stdout.write(cmd + "\n")
    sys.stdout.flush()

    console_logger.info(f"Отозваны все маршруты группы {group_name}")
    logger.info(f"Отозваны все маршруты группы '{group_name}'")

def update_routes_for_group(group_name: str, directory: str, cache_data: dict) -> tuple:
    """
    Обновляет маршруты для группы на основе изменений в файлах.
    Возвращает кортеж: (новые_маршруты, удалённые_маршруты, обновлён_ли)
    """
    current_state = calculate_directory_state(directory)

    previous_state = cache_data.get('groups', {}).get(group_name, {}).get('state', {})

    changes = compare_states(previous_state, current_state)

    current_routes = read_routes_from_directory(directory, group_name)

    previous_routes = set(cache_data.get('groups', {}).get(group_name, {}).get('routes', []))

    # Поиск изменений в маршрутах
    current_routes_set = set(current_routes)
    routes_to_withdraw = sorted(list(previous_routes - current_routes_set))
    routes_to_announce = sorted(list(current_routes_set - previous_routes))

    # Проверка на изменения
    has_changes = any([
        len(changes['added']) > 0,
        len(changes['modified']) > 0,
        len(changes['removed']) > 0,
        len(routes_to_withdraw) > 0,
        len(routes_to_announce) > 0
    ])

    if has_changes:
        if changes['added']:
            logger.info(f"Группа '{group_name}': добавлено файлов: {len(changes['added'])}")
            console_logger.info(f"В группе '{group_name}' добавлено {len(changes['added'])} файлов")

        if changes['modified']:
            logger.info(f"Группа '{group_name}': изменено файлов: {len(changes['modified'])}")
            console_logger.info(f"В группе '{group_name}' изменено {len(changes['modified'])} файлов")

        if changes['removed']:
            logger.info(f"Группа '{group_name}': удалено файлов: {len(changes['removed'])}")
            console_logger.info(f"В группе '{group_name}' удалено {len(changes['removed'])} файлов")

        if routes_to_withdraw:
            logger.info(f"Группа '{group_name}': маршрутов к отзыву: {len(routes_to_withdraw)}")
            console_logger.info(f"В группе '{group_name}' будет отозвано {len(routes_to_withdraw)} маршрутов")

        if routes_to_announce:
            logger.info(f"Группа '{group_name}': маршрутов к анонсу: {len(routes_to_announce)}")
            console_logger.info(f"В группе '{group_name}' будет анонсировано {len(routes_to_announce)} маршрутов")

    # Обновление кэша для обрабатываемой группы
    if 'groups' not in cache_data:
        cache_data['groups'] = {}

    cache_data['groups'][group_name] = {
        'state': current_state,
        'routes': current_routes,
        'last_updated': datetime.now().isoformat(),
        'total_routes': len(current_routes)
    }

    return (routes_to_announce, routes_to_withdraw, has_changes)

def read_routes_from_directory(directory_path: str, group_name: str) -> list:
    """Читает все маршруты из TXT файлов в директории"""
    all_routes = set()
    dir_path = Path(directory_path)

    if not dir_path.exists() or not dir_path.is_dir():
        console_logger.error(f"Директория не найдена: {directory_path}")
        return []

    # Поиск файлов с учетом рекурсивности
    if DEFAULT_CONFIG['recursive_search']:
        txt_files = sorted(dir_path.rglob("*.txt"))
        console_logger.info(f"Рекурсивный поиск TXT файлов в {directory_path}")
    else:
        txt_files = sorted(dir_path.glob("*.txt"))

    if not txt_files:
        console_logger.warning(f"TXT файлы не найдены в {directory_path}")
        return []

    console_logger.info(f"Найдено {len(txt_files)} TXT файлов в {directory_path}")

    # Счетчики для статистики
    total_lines = 0
    duplicate_count = 0

    for txt_file in txt_files:
        try:
            with open(txt_file, 'r', encoding='utf-8') as f:
                for line in f:
                    normalized = normalize_prefix(line.strip())
                    if normalized:
                        total_lines += 1

                        route_count_before = len(all_routes)
                        all_routes.add(normalized)
                        route_count_after = len(all_routes)

                        if route_count_after == route_count_before:
                            duplicate_count += 1
                            logger.debug(f"Дубликат найден: {normalized} в файле {txt_file.name}")

        except Exception as e:
            console_logger.error(f"Ошибка чтения файла {txt_file}: {e}")
            logger.error(f"Ошибка чтения файла {txt_file}: {e}")

    # Всегда возвращает список
    routes = sorted(list(all_routes))
    unique_count = len(routes)

    # Логирует статистику по дубликатам
    if DEFAULT_CONFIG['remove_duplicates'] and duplicate_count > 0:
        console_logger.info(
            f"В маршрутном листе '{group_name}': "
            f"было {total_lines} строк -> "
            f"удалено {duplicate_count} дублей -> "
            f"осталось {unique_count} уникальных маршрутов"
        )
        logger.info(
            f"Группа '{group_name}': "
            f"обработано {total_lines} строк, "
            f"найдено {duplicate_count} дубликатов, "
            f"уникальных маршрутов: {unique_count}"
        )
    else:
        console_logger.info(f"В маршрутном листе '{group_name}': {unique_count} уникальных маршрутов")

    return routes

def get_group_attribute(group_name: str, attribute_name: str):
    """Получает атрибут для группы или использует значение по умолчанию"""
    # Проверяет переопределения в group_attributes
    if (group_name in DEFAULT_CONFIG['group_attributes'] and
        attribute_name in DEFAULT_CONFIG['group_attributes'][group_name]):
        return DEFAULT_CONFIG['group_attributes'][group_name][attribute_name]

    return DEFAULT_CONFIG[attribute_name]

def announce_routes_individual(group_name: str, routes: list):
    """Анонсирует маршруты для группы с ограничением скорости"""
    if not routes:
        console_logger.info(f"Нет маршрутов для группы {group_name}")
        logger.info(f"Группа '{group_name}': маршрутов для анонсирования нет")
        return

    # Выбирает режим анонса
    announce_mode = DEFAULT_CONFIG.get('announce_mode', 'bulk')

    if announce_mode == 'bulk' and len(routes) > 5:  # Для 5+ маршрутов использует bulk
        announce_routes_bulk(group_name, routes)
        return

    console_logger.info(f"Анонсирование {len(routes)} маршрутов из группы {group_name}")
    logger.info(f"Начало анонсирования группы '{group_name}': {len(routes)} маршрутов")

    # Получает атрибуты для группы
    next_hop = get_group_attribute(group_name, 'next_hop')
    communities = get_group_attribute(group_name, 'communities')
    as_path = get_group_attribute(group_name, 'as_path')
    local_pref = get_group_attribute(group_name, 'local_preference')
    med = get_group_attribute(group_name, 'med')
    origin = get_group_attribute(group_name, 'origin')

    # Вывод полученные атрибуты
    console_logger.debug(f"Атрибуты для группы '{group_name}': next_hop={next_hop}, "
                f"communities={communities}, as_path={as_path}, "
                f"local_pref={local_pref}, med={med}, origin={origin}")

    # Счётчики для статистики
    sent_count = 0
    batch_size = 100  # Размер пачки маршрутов
    delay_between_batches = 0.5  # Задержка между пачками (секунды)
    delay_between_routes = 0.01  # Задержка между отдельными маршрутами (секунды)

    for i, route in enumerate(routes):
        # Формирует базовую команду
        cmd = f"announce route {route} next-hop {next_hop}"

        # Добавляет communities если есть и не 'none'
        if communities and communities != 'none':
            if isinstance(communities, list):
                comm_str = ' '.join([f"[{comm}]" for comm in communities])
            else:
                comm_str = f"[{communities}]"
            cmd += f" community {comm_str}"

        # Добавляет as-path если есть и не пустой
        if as_path and isinstance(as_path, list) and len(as_path) > 0:
            as_str = ' '.join([str(asn) for asn in as_path])
            cmd += f" as-path [{as_str}]"

        # Добавляет local-preference если есть (число)
        if local_pref is not None and isinstance(local_pref, (int, float)):
            cmd += f" local-preference {int(local_pref)}"

        # Добавляет MED если есть (число)
        if med is not None and isinstance(med, (int, float)):
            cmd += f" med {int(med)}"

        # Добавляет origin если не стандартный
        if origin and origin != 'igp':
            cmd += f" origin {origin}"

        # Полная команда
        logger.debug(f"Отправка команды анонса: {cmd}")

        try:
            # Отправляет команду в stdout для ExaBGP
            sys.stdout.write(cmd + "\n")
            sys.stdout.flush()

            # Проверка, на необходимость приостановки
            # Перехват сообщений от ExaBGP о перегрузке
            try:
                ready, _, _ = select.select([sys.stdin], [], [], 0.001)
                if ready:
                    message = sys.stdin.readline().strip()
                    if message:
                        logger.debug(f"ExaBGP сообщение во время анонса: {message}")
                        # Если ExaBGP перегружен - замедляет исполнение
                        if 'overload' in message.lower() or 'busy' in message.lower():
                            console_logger.warning("ExaBGP сообщает о перегрузке, увеличение задержки")
                            delay_between_routes = min(delay_between_routes * 2, 0.1)  # Увеличивает до 100мс максимум
            except Exception as e:
                # Игнорирует ошибки при неблокирующем чтении
                pass

            # Подтверждение отправки команды
            logger.debug(f"Команда анонса отправлена: {route}")
            sent_count += 1

        except BrokenPipeError:
            logger.error(f"BrokenPipeError при отправке маршрута {route}")
            console_logger.error("ExaBGP перестал читать команды! Прерываем анонс.")
            update_health_statistics('announce', sent_count, success=False, error='BrokenPipeError: ExaBGP stopped responding')
            break
        except Exception as e:
            logger.error(f"Ошибка при отправке маршрута {route}: {e}")
            console_logger.error(f"Ошибка отправки: {e}")
            break

        # Задержка между маршрутами
        if i % 10 == 0:  # Каждые 10 маршрутов
            time.sleep(delay_between_routes)

        # Задержка между пачками и вывод прогресса
        if sent_count % batch_size == 0:
            console_logger.info(f"Прогресс группы '{group_name}': отправлено {sent_count}/{len(routes)} маршрутов")
            time.sleep(delay_between_batches)

            # Периодическая проверка флага running
            if not running:
                console_logger.warning("Получен сигнал остановки, прерываем анонс")
                break

    logger.info(f"Завершено анонсирование группы '{group_name}': отправлено {sent_count}/{len(routes)} маршрутов")
    update_health_statistics('announce', sent_count, success=True)

def announce_routes_bulk(group_name: str, routes: list):
    """Анонсирует маршруты пачками через bulk commands"""
    if not routes:
        console_logger.info(f"Нет маршрутов для группы {group_name}")
        logger.info(f"Группа '{group_name}': маршрутов для анонсирования нет")
        return

    console_logger.info(f"Bulk анонсирование {len(routes)} маршрутов из группы {group_name}")
    logger.info(f"Начало bulk анонсирования группы '{group_name}': {len(routes)} маршрутов")

    # Получает атрибуты группы
    next_hop = get_group_attribute(group_name, 'next_hop')
    communities = get_group_attribute(group_name, 'communities')
    as_path = get_group_attribute(group_name, 'as_path')
    local_pref = get_group_attribute(group_name, 'local_preference')
    med = get_group_attribute(group_name, 'med')
    origin = get_group_attribute(group_name, 'origin')

    # Формирование строки атрибутов
    attributes_parts = [f"next-hop {next_hop}"]

    # Добавляет communities если есть и не 'none'
    if communities and communities != 'none':
        if isinstance(communities, list):
            comm_str = ' '.join([f"[{comm}]" for comm in communities])
        else:
            comm_str = f"[{communities}]"
        attributes_parts.append(f"community {comm_str}")

    # Добавляет as-path если есть и не пустой
    if as_path and isinstance(as_path, list) and len(as_path) > 0:
        as_str = ' '.join([str(asn) for asn in as_path])
        attributes_parts.append(f"as-path [{as_str}]")

    # Добавляет local-preference если есть (число)
    if local_pref is not None and isinstance(local_pref, (int, float)):
        attributes_parts.append(f"local-preference {int(local_pref)}")

    # Добавляет MED если есть (число)
    if med is not None and isinstance(med, (int, float)):
        attributes_parts.append(f"med {int(med)}")

    # Добавляет origin если не стандартный
    if origin and origin != 'igp':
        attributes_parts.append(f"origin {origin}")

    attributes_str = ' '.join(attributes_parts)

    # Разбиваем маршруты на пачки
    bulk_size = DEFAULT_CONFIG.get('bulk_size', 100)
    total_sent = 0
    batch_count = 0

    for i in range(0, len(routes), bulk_size):
        batch = routes[i:i + bulk_size]
        batch_count += 1

        # Формирует bulk команду
        nlri_list = ' '.join(batch)
        cmd = f"announce attributes {attributes_str} nlri {nlri_list}"

        # Логирует информацию о пачке
        console_logger.debug(f"Bulk пачка {batch_count}: {len(batch)} маршрутов")
        logger.debug(f"Группа '{group_name}': bulk пачка {batch_count}, размер {len(batch)}")

        try:
            # Отправляет команду
            sys.stdout.write(cmd + "\n")
            sys.stdout.flush()
            total_sent += len(batch)

            # Проверяет сообщения от ExaBGP
            try:
                ready, _, _ = select.select([sys.stdin], [], [], 0.001)
                if ready:
                    message = sys.stdin.readline().strip()
                    if message:
                        logger.debug(f"ExaBGP сообщение во время bulk анонса: {message}")
            except Exception:
                pass

            # Задержка между пачками (меньше, т.к. bulk эффективнее)
            if batch_count % 10 == 0:  # Каждые 10 пачек
                console_logger.info(f"Прогресс '{group_name}': отправлено {total_sent}/{len(routes)} маршрутов")
                time.sleep(0.1)

            if not running:
                console_logger.warning("Получен сигнал остановки, прерываем bulk анонс")
                break

        except BrokenPipeError:
            logger.error(f"BrokenPipeError при bulk анонсе пачки {batch_count}")
            console_logger.error("ExaBGP перестал читать команды! Прерываем анонс.")
            update_health_statistics('announce', total_count, success=False, error='BrokenPipeError: ExaBGP stopped responding')
            break
        except Exception as e:
            logger.error(f"Ошибка при bulk анонсе пачки {batch_count}: {e}")
            console_logger.error(f"Ошибка bulk анонса: {e}")
            break

    console_logger.info(f"Завершён bulk анонс '{group_name}': {total_sent}/{len(routes)} маршрутов в {batch_count} пачках")
    logger.info(f"Завершён bulk анонс группы '{group_name}': {total_sent} маршрутов, {batch_count} пачек")
    update_health_statistics('announce', total_sent, success=True)

def initial_announcement():
    """Выполняет первоначальный анонс всех маршрутов"""
    console_logger.info("-" * 64)
    console_logger.info("Первоначальный анонс маршрутов")
    console_logger.info("-" * 64)

    cache_data = {}
    total_routes = 0

    for group_name, directory in DEFAULT_CONFIG['path_list_announce'].items():
        console_logger.info(f"Обработка группы: {group_name}")

        # Читает маршруты
        routes = read_routes_from_directory(directory, group_name)

        if routes:
            # Анонсирует маршруты
            announce_routes_individual(group_name, routes)
            total_routes += len(routes)

            # Фиксирует в кэш файл
            if 'groups' not in cache_data:
                cache_data['groups'] = {}

            cache_data['groups'][group_name] = {
                'state': calculate_directory_state(directory),
                'routes': routes,
                'last_updated': datetime.now().isoformat(),
                'total_routes': len(routes)
            }

    # Сохраняет кэш файл
    save_cache(cache_data)

    console_logger.info(f"Первоначальный анонс завершён. Всего анонсировано {total_routes} маршрутов")
    logger.info(f"Первоначальный анонс завершён: анонсировано {total_routes} маршрутов")

    return cache_data

def periodic_update(last_check_time: float, cache_data: dict) -> tuple:
    """
    Выполняет периодическую проверку обновлений.
    """
    global running

    # Проверка на запрос завершение работы
    if not running:
        return (last_check_time, cache_data)

    current_time = time.time()

    # Проверяет прошёл ли интервал обновления
    if current_time - last_check_time < DEFAULT_CONFIG['update_interval']:
        return (last_check_time, cache_data)

    console_logger.info("-" * 81)
    console_logger.info("Цикл проверки обновлений маршрутных листов")
    console_logger.info("-" * 81)

    console_logger.info("Ожидание готовности ExaBGP перед обновлением...")
    wait_for_exabgp_ready(timeout=5)
    time.sleep(1)

    last_check_time = current_time
    total_withdrawn = 0
    total_announced = 0
    has_global_changes = False

    updated_cache = cache_data.copy()

    for group_name, directory in DEFAULT_CONFIG['path_list_announce'].items():
        # Проверяет, не запрошено ли завершение работы перед каждой итерацией
        if not running:
            break

        console_logger.info(f"Проверка обновлений для группы: {group_name}")

        # Обновляет маршруты для группы
        routes_to_announce, routes_to_withdraw, has_changes = update_routes_for_group(
            group_name, directory, updated_cache
        )

        if has_changes:
            has_global_changes = True

            # Сначала отзыв старых маршрутов
            if routes_to_withdraw:
                withdraw_routes_individual(group_name, routes_to_withdraw)
                total_withdrawn += len(routes_to_withdraw)

            # Затем анонс новых
            if routes_to_announce:
                announce_routes_individual(group_name, routes_to_announce)
                total_announced += len(routes_to_announce)

    # Сохраняет обновлённый кэш
    if has_global_changes and running:
        save_cache(updated_cache)
        logger.info(f"Обновления применены: отозвано {total_withdrawn}, анонсировано {total_announced} маршрутов")
    elif running:
        console_logger.info("Изменений не обнаружено")
        logger.info("Периодическая проверка: изменений не обнаружено")

    return (last_check_time, updated_cache)

def main():
    """Основная функция скрипта"""
    global running, health_status, script_start_time

    script_start_time = time.time()

    # Инициализирует статус
    with health_lock:
        health_status = {
            'status': 'starting',
            'exabgp_alive': False,
            'last_exabgp_check': None,
            'last_successful_operation': None,
            'errors': [],
            'statistics': {
                'total_routes_announced': 0,
                'total_routes_withdrawn': 0,
                'last_update_time': None,
                'update_cycles': 0,
            }
        }

    console_logger.info("=" * 64)
    console_logger.info("Запуск %s - динамический анонс маршрутов ExaBGP", script_name)
    console_logger.info("=" * 64)

    # Логирование конфигурации
    console_logger.info(f"Используемая конфигурация:"
              f" рекурсивный поиск = {DEFAULT_CONFIG['recursive_search']}, "
              f"удаление дубликатов = {DEFAULT_CONFIG['remove_duplicates']}")
    console_logger.info(f"Интервал обновления: {DEFAULT_CONFIG['update_interval']} секунд")

    # Запускает health check сервер
    health_server_thread = start_health_check_server()

    # Проверяет доступность порта мониторинга
    monitor_port = DEFAULT_CONFIG['monitoring']['listen_port']
    if monitor_port > 0:
        console_logger.info(f"Мониторинг доступен на порту {monitor_port}")
        console_logger.info(f"Health check endpoint: http://localhost:{monitor_port}/health")

    logger.info(f"Параметры запуска: recursive_search={DEFAULT_CONFIG['recursive_search']}, "
                f"remove_duplicates={DEFAULT_CONFIG['remove_duplicates']}, "
                f"update_interval={DEFAULT_CONFIG['update_interval']}")

    time.sleep(3)
    console_logger.info("ExaBGP готов к запуску")

    # Выполняет первоначальный анонс
    try:
        cache_data = initial_announcement()
        # Обновляет статус после успешного старта
        with health_lock:
            health_status['status'] = 'healthy'
            health_status['exabgp_alive'] = True
            health_status['last_exabgp_check'] = datetime.now().isoformat()
    except Exception as e:
        logger.error(f"Ошибка при первоначальном анонсе: {e}")
        console_logger.error(f"Ошибка при запуске: {e}")
        with health_lock:
            health_status['status'] = 'unhealthy'
            health_status['errors'].append({
                'time': datetime.now().isoformat(),
                'error': f'Initial announcement failed: {e}'
            })
        sys.exit(1)

    # Инициализирует время последней проверки
    last_check_time = time.time()
    last_health_check = time.time()
    health_check_interval = DEFAULT_CONFIG['monitoring']['health_check_interval']

    console_logger.info("Переход в режим мониторинга изменений...")
    logger.info("Скрипт перешёл в режим мониторинга изменений")

    try:
        # Основной цикл с проверкой флага running
        while running:
            try:

                # Активное чтение сообщений от ExaBGP
                try:
                    ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                    if ready:
                        message = sys.stdin.readline().strip()
                        if message:
                            logger.debug(f"ExaBGP сообщение: {message}")

                            # Реагирование на сообщения
                            if 'shutdown' in message.lower() or 'stopping' in message.lower():
                                logger.info("ExaBGP сообщает о shutdown, производится graceful shutdown")
                                console_logger.info("ExaBGP инициировал shutdown, производится отзыв маршрутов")
                                running = False
                                graceful_shutdown()
                                break
                            elif 'overload' in message.lower() or 'busy' in message.lower():
                                logger.warning("ExaBGP сообщает о перегрузке, увеличиваем задержки")
                except Exception as e:
                    # Игнорирует ошибки при неблокирующем чтении
                    logger.debug(f"Ошибка чтения STDIN: {e}")

                last_check_time, cache_data = periodic_update(last_check_time, cache_data)

                # Обновляет статистику после успешного цикла обновления
                update_health_statistics('update_cycle', success=True)

            except BrokenPipeError:
                logger.error("BrokenPipeError: ExaBGP прекратил чтение команд!")
                console_logger.error("Критическая ошибка: ExaBGP не отвечает. Завершение работы.")

                # Обновляет статус ошибки
                update_health_statistics('update_cycle', success=False,
                                       error='BrokenPipeError: ExaBGP stopped responding')

                with health_lock:
                    health_status['exabgp_alive'] = False
                    health_status['status'] = 'unhealthy'

                running = False
                break

            except Exception as e:
                logger.error(f"Ошибка в periodic_update: {e}", exc_info=True)
                console_logger.error(f"Ошибка обновления: {e}")

                # Обновляет статус ошибки
                update_health_statistics('update_cycle', success=False, error=str(e))

                with health_lock:
                    if health_status['status'] == 'healthy':
                        health_status['status'] = 'degraded'

            # Периодическая проверка здоровья ExaBGP
            current_time = time.time()
            if current_time - last_health_check > health_check_interval:
                if check_exabgp_health():
                    logger.debug("ExaBGP health check пройден")
                    # Если была деградация и ExaBGP снова отвечает - возвращает статус
                    with health_lock:
                        if health_status['status'] == 'degraded' and health_status['exabgp_alive']:
                            health_status['status'] = 'healthy'
                else:
                    logger.warning("ExaBGP health check не пройден")
                    with health_lock:
                        health_status['status'] = 'unhealthy' if not health_status['exabgp_alive'] else 'degraded'

                last_health_check = current_time

            # Короткий цикл сна с проверкой running
            for _ in range(60):
                if not running:
                    break
                time.sleep(1)

    except KeyboardInterrupt:
        console_logger.info("Получен сигнал KeyboardInterrupt")
        logger.info("Завершение по KeyboardInterrupt")

    except Exception as e:
        console_logger.error(f"Неожиданная ошибка в основном цикле: {e}")
        logger.error(f"Неожиданная ошибка в основном цикле: {e}", exc_info=True)

        with health_lock:
            health_status['status'] = 'unhealthy'
            health_status['errors'].append({
                'time': datetime.now().isoformat(),
                'error': f'Unexpected error in main loop: {e}'
            })

    finally:
        # Проверяет, не был ли уже выполнен graceful shutdown
        with health_lock:
            if health_status['status'] not in ['stopped', 'shutting_down']:
                console_logger.warning("Неожиданное завершение, выполняем emergency graceful shutdown")
                logger.warning("Неожиданное завершение, запуск emergency graceful shutdown")
                graceful_shutdown()

        # Финальное сообщение о завершении
        console_logger.info("-" * 60)
        console_logger.info("Завершение работы")
        console_logger.info("-" * 60)

        # Обновляет финальный статус
        with health_lock:
            health_status['status'] = 'stopped'

        sys.exit(0)

if __name__ == "__main__":
    main()
