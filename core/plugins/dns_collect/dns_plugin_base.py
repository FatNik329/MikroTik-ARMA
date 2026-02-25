from abc import ABC, abstractmethod
from datetime import datetime
import json
from typing import Dict, Any, List, Optional

class DNSPluginBase(ABC):
    """Базовый класс для всех DNS плагинов"""

    @property
    @abstractmethod
    def SERVICE_NAME(self) -> str:
        """Имя сервиса (например, 'dnscrypt-proxy')"""
        pass

    @abstractmethod
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Парсит строку лога и возвращает стандартизованную запись
        Возвращает None если строка не может быть распарсена
        """
        pass

    def normalize_timestamp(self, ts: Any) -> str:
        """Конвертирует timestamp в ISO 8601 UTC"""
        try:
            if isinstance(ts, (int, float)):
                # Unix timestamp
                dt = datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
            elif isinstance(ts, str):
                formats = [
                    '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%dT%H:%M:%S',
                    '%Y-%m-%dT%H:%M:%S.%f',
                    '%b %d %H:%M:%S',  # Feb  5 16:59:48
                ]

                for fmt in formats:
                    try:
                        dt = datetime.strptime(ts, fmt)
                        if dt.year == 1900:
                            dt = dt.replace(year=datetime.now().year)
                        dt = dt.astimezone(datetime.timezone.utc)
                        break
                    except ValueError:
                        continue
                else:
                    return ts
            elif isinstance(ts, datetime):
                dt = ts.astimezone(datetime.timezone.utc)
            else:
                return str(ts)

            return dt.isoformat()
        except Exception:
            return str(ts)

    def normalize_response_status(self, status: str) -> str:
        """Нормализует статус ответа"""
        if not status:
            return "UNKNOWN"

        status = str(status).strip().upper()

        mapping = {
            # dnscrypt-proxy
            'PASS': 'RESOLVED',
            'FORWARD': 'FORWARDED',
            'BLOCK': 'BLOCKED',
            'CACHE': 'CACHED',
            'CACHED': 'CACHED',

            # dnsmasq
            'QUERY': 'FORWARDED',
            'REPLY': 'RESOLVED',

            # Общие
            'RESOLVE': 'RESOLVED',
            'RESOLVED': 'RESOLVED',
            'FORWARDED': 'FORWARDED',
            'BLOCKED': 'BLOCKED',
            'FILTERED': 'FILTERED',
            'FAILED': 'FAILED',
            'NXDOMAIN': 'FAILED',
            'SERVFAIL': 'FAILED',
            'TIMEOUT': 'FAILED',
        }

        return mapping.get(status, "UNKNOWN")

    def extract_response_ips(self, data: Dict[str, Any]) -> List[str]:
        """Извлекает IP-адреса из ответа"""
        # В базовом классе возвращается пустой список
        # Каждый плагин должен переопределить этот метод
        return []

    def create_record(self, **kwargs) -> Dict[str, Any]:
        """
        Создает стандартизованную запись с заполнением обязательных полей
        """
        record = {
            # Обязательные поля
            "timestamp": self.normalize_timestamp(kwargs.get("timestamp")),
            "server": self.SERVICE_NAME,
            "client_ip": kwargs.get("client_ip", ""),
            "query_name": kwargs.get("query_name", ""),
            "query_type": kwargs.get("query_type", ""),
            "response": self.normalize_response_status(kwargs.get("response", "")),
            "response_ip": self.extract_response_ips(kwargs),
            "cached": bool(kwargs.get("cached", False)),
            "processing_time_ms": kwargs.get("processing_time_ms"),
            "raw": kwargs.get("raw", ""),

            # Опциональные поля
            "server_ip": kwargs.get("server_ip"),
            "server_port": kwargs.get("server_port"),
            "upstream": kwargs.get("upstream"),
            "dnssec": kwargs.get("dnssec"),
            "protocol": kwargs.get("protocol"),
            "client_id": kwargs.get("client_id"),
            "policy": kwargs.get("policy"),
            "rule": kwargs.get("rule"),
            "answer_raw": kwargs.get("answer_raw"),
        }

        # Сбор метаданных из полей, начинающихся с _
        metadata = {}
        for key, value in kwargs.items():
            if key.startswith('_') and key != '_original':
                metadata[key[1:]] = value

        # Добавляет оригинальные данные (если имеются)
        if '_original' in kwargs:
            metadata['original'] = kwargs['_original']

        if metadata:
            record["metadata"] = metadata

        for key in list(record.keys()):
            if record[key] is None:
                del record[key]

        return record
