import re
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum

from dns_plugin_base import DNSPluginBase

class DNSCryptLogFormat(Enum):
    """Форматы логов dnscrypt-proxy"""
    UNKNOWN = "unknown"
    TSV = "tsv"
    LTSV = "ltsv"

class DNSCryptProxyPlugin(DNSPluginBase):
    """Плагин для обработки логов dnscrypt-proxy"""

    @property
    def SERVICE_NAME(self) -> str:
        return "dnscrypt-proxy"

    def __init__(self):
        self.supported_formats = ['tsv', 'ltsv']

        # Паттерны для определения формата
        self.TSV_PATTERN = re.compile(r'^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]')
        self.LTSV_PATTERN = re.compile(r'^time:\d+')

        # Для извлечения IP из доменов
        self.IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

        logging.info(f"Инициализирован плагин {self.SERVICE_NAME}")

    def detect_format(self, line: str) -> DNSCryptLogFormat:
        """Определить формат лога по строке"""
        line = line.strip()
        if not line:
            return DNSCryptLogFormat.UNKNOWN

        if self.TSV_PATTERN.match(line):
            return DNSCryptLogFormat.TSV
        elif self.LTSV_PATTERN.match(line):
            return DNSCryptLogFormat.LTSV
        else:
            return DNSCryptLogFormat.UNKNOWN

    def parse_tsv_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Парсинг TSV формата"""
        try:
            line = line.strip()
            if not line.startswith('['):
                return None

            # Извлекает timestamp
            timestamp_end = line.find(']')
            if timestamp_end == -1:
                return None

            timestamp_str = line[1:timestamp_end].strip()
            rest = line[timestamp_end + 1:].strip()

            # Разбивает на поля (tab-разделитель)
            parts = [p.strip() for p in rest.split('\t') if p.strip()]

            if len(parts) < 6:
                return None

            # Основные поля
            client_ip = parts[0]
            query_name = parts[1]
            query_type = parts[2]
            response_raw = parts[3]
            response_time = parts[4]
            server_info = parts[5]

            # Извлекает provider из server_info
            dnscrypt_provider = None
            if server_info and server_info != '-':
                dnscrypt_provider = server_info

            # Извлекает processing_time
            processing_time_ms = 0
            if response_time:
                try:
                    time_str = response_time.lower().replace('ms', '')
                    processing_time_ms = float(time_str)
                except (ValueError, TypeError):
                    pass

            # Определяет cached
            cached = response_raw.upper() in ['CACHE', 'CACHED']

            # Создает стандартизованную запись
            return self.create_record(
                timestamp=timestamp_str,
                client_ip=client_ip,
                query_name=query_name,
                query_type=query_type,
                response=response_raw,
                cached=cached,
                processing_time_ms=processing_time_ms,
                raw=line,
                _original={
                    "client_ip": client_ip,
                    "domain": query_name,
                    "query_type": query_type,
                    "response": response_raw,
                    "response_time": response_time,
                    "server_info": server_info,
                },
                _dnscrypt_provider=dnscrypt_provider,
                _response_time_str=response_time
            )

        except Exception as e:
            logging.debug(f"Ошибка парсинга TSV: {e}, строка: {line}")
            return None

    def parse_ltsv_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Парсинг LTSV формата"""
        try:
            line = line.strip()
            if not line:
                return None

            # Парсинг LTSV полей
            fields = {}
            for field in line.split('\t'):
                if ':' not in field:
                    continue
                key, value = field.split(':', 1)
                fields[key.strip()] = value.strip()

            # Обязательные поля
            if 'message' not in fields or 'type' not in fields:
                return None

            # Unix timestamp
            timestamp = None
            if 'time' in fields:
                try:
                    timestamp = int(fields['time'])
                except (ValueError, TypeError):
                    pass

            # Processing time
            processing_time_ms = 0
            if 'duration' in fields:
                try:
                    processing_time_ms = float(fields['duration'])
                except (ValueError, TypeError):
                    pass

            # Cached flag
            cached = False
            if 'cached' in fields:
                cached_val = fields['cached'].lower()
                cached = cached_val in ['1', 'true', 'yes', 'y']

            # Provider
            dnscrypt_provider = fields.get('server', '-')
            if dnscrypt_provider == '-':
                dnscrypt_provider = None

            # Создает стандартизованную запись
            return self.create_record(
                timestamp=timestamp,
                client_ip=fields.get('host', ''),
                query_name=fields.get('message', ''),
                query_type=fields.get('type', ''),
                response=fields.get('return', ''),
                cached=cached,
                processing_time_ms=processing_time_ms,
                raw=line,
                _original=fields.copy(),
                _dnscrypt_provider=dnscrypt_provider
            )

        except Exception as e:
            logging.debug(f"Ошибка парсинга LTSV: {e}, строка: {line}")
            return None

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Основной метод парсинга"""
        if not line.strip():
            return None

        format_type = self.detect_format(line)

        if format_type == DNSCryptLogFormat.TSV:
            return self.parse_tsv_line(line)
        elif format_type == DNSCryptLogFormat.LTSV:
            return self.parse_ltsv_line(line)
        else:
            result = self.parse_tsv_line(line)
            if result is None:
                result = self.parse_ltsv_line(line)
            return result

    def extract_response_ips(self, data: Dict[str, Any]) -> List[str]:
        """
        Извлекает IP-адреса из ответа, если присутствует.
        """
        ips = []

        if 'query_name' in data:
            found_ips = self.IP_PATTERN.findall(data['query_name'])
            ips.extend(found_ips)

        # Проверяет metadata
        if 'metadata' in data:
            metadata = data['metadata']
            for key, value in metadata.items():
                if isinstance(value, str):
                    found_ips = self.IP_PATTERN.findall(value)
                    ips.extend(found_ips)

        return list(set(ips))
