"""
Модуль мониторинга MikroTik-ARMA
"""
import json
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional
import logging


class BaseHealthCheckHandler(BaseHTTPRequestHandler):
    """Базовый обработчик HTTP запросов для health check"""

    def do_GET(self):
        if self.path == '/health':
            health_status = self.get_health_status()

            self.send_response(200 if health_status['status'] == 'healthy' else 503)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            response = json.dumps(health_status, indent=2, ensure_ascii=False)
            self.wfile.write(response.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def get_health_status(self) -> Dict[str, Any]:
        raise NotImplementedError("Метод должен быть реализован в дочернем классе")

    def log_message(self, format, *args):
        pass


class MonitoringCore:
    """Базовое ядро мониторинга"""

    def __init__(self, script_name: str, config: Dict[str, Any]):
        self.script_name = script_name
        self.config = config
        self.health_status = self._get_default_health_status()
        self.health_lock = threading.Lock()
        self.server_thread: Optional[threading.Thread] = None
        self.logger = logging.getLogger(__name__)
        self.script_start_time = time.time()

    def _get_default_health_status(self) -> Dict[str, Any]:
        """Базовая структура health status"""
        return {
            'status': 'starting',
            'last_successful_operation': None,
            'errors': [],
            'statistics': {
                'update_cycles': 0,
                'last_update_time': None,
            },
            'monitoring': {
                'status': 'starting',
                'response_time': 0,
                'timestamp': None
            },
            'metrics': {
                'errors_count': 0,
                'uptime_seconds': 0
            },
            'timestamp': None,
            'script_uptime': 0
        }

    def update_statistics(self, operation_type: str, count: int = 1,
                         success: bool = True, error: Optional[str] = None):
        """Базовое обновление статистики"""
        with self.health_lock:
            if operation_type == 'update_cycle':
                self.health_status['statistics']['update_cycles'] += 1
                self.health_status['statistics']['last_update_time'] = datetime.now().isoformat()

            if success:
                self.health_status['last_successful_operation'] = {
                    'type': operation_type,
                    'time': datetime.now().isoformat(),
                    'count': count
                }
            elif error:
                # Сохраняет последние N ошибок
                if len(self.health_status['errors']) > 10:
                    self.health_status['errors'] = self.health_status['errors'][-10:]
                self.health_status['errors'].append({
                    'time': datetime.now().isoformat(),
                    'error': error,
                    'operation': operation_type
                })

                if len(self.health_status['errors']) > 5:
                    self.health_status['status'] = 'degraded'

            # Обновление метрик
            self.health_status['metrics']['errors_count'] = len(self.health_status['errors'])
            self.health_status['metrics']['uptime_seconds'] = time.time() - self.script_start_time

    def start_health_check_server(self, handler_class) -> Optional[threading.Thread]:
        """Запуск HTTP сервера health check"""
        port = self.config.get('monitoring', {}).get('listen_port', 0)

        if port == 0:
            self.logger.info("Health check сервер отключен (port=0)")
            return None

        def run_server():
            try:
                server = HTTPServer(('0.0.0.0', port), handler_class)
                server.allow_reuse_address = True
                self.logger.info(f"Health check сервер запущен на порту {port}")

                server.serve_forever()
            except Exception as e:
                self.logger.error(f"Ошибка health check сервера: {e}")
            finally:
                if 'server' in locals():
                    server.server_close()

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

        return self.server_thread

    def get_base_health_status(self) -> Dict[str, Any]:
        """Возвращает базовую часть health status"""
        with self.health_lock:
            # Копирует базовые поля
            base_status = {
                'status': self.health_status['status'],
                'last_successful_operation': self.health_status['last_successful_operation'],
                'errors': self.health_status['errors'].copy(),
                'statistics': self.health_status['statistics'].copy(),
                'monitoring': {
                    'status': 'up',
                    'response_time': 0,
                    'timestamp': datetime.now().isoformat()
                },
                'metrics': self.health_status['metrics'].copy(),
                'timestamp': datetime.now().isoformat(),
                'script_uptime': time.time() - self.script_start_time
            }

            return base_status
