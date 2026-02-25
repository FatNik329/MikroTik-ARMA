import re
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum

from dns_plugin_base import DNSPluginBase

class DnsmasqLogFormat(Enum):
    """Форматы логов dnsmasq"""
    UNKNOWN = "unknown"
    SYSLOG = "syslog"

class DnsmasqPlugin(DNSPluginBase):
    """Плагин для обработки логов dnsmasq"""

    @property
    def SERVICE_NAME(self) -> str:
        return "dnsmasq"

    def __init__(self):
        # Основные паттерны для dnsmasq логов
        # Формат: Feb  4 12:53:52 dnsmasq[2696859]: query[A] example.net from 127.0.0.1
        self.SYSLOG_PATTERN = re.compile(
            r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+'
            r'dnsmasq\[(\d+)\]:\s+(.+)$'
        )

        # Паттерны для типов сообщений dnsmasq
        self.QUERY_PATTERN = re.compile(
            r'^query\[([A-Z]+)\]\s+([^\s]+)\s+from\s+([\d\.:]+)$'
        )
        self.REPLY_PATTERN = re.compile(
            r'^reply\s+([^\s]+)\s+is\s+(.+)$'
        )
        self.CACHED_PATTERN = re.compile(
            r'^cached\s+([^\s]+)\s+is\s+(.+)$'
        )
        self.FORWARDED_PATTERN = re.compile(
            r'^forwarded\s+([^\s]+)\s+to\s+([\d\.:]+)$'
        )
        self.CONFIG_PATTERN = re.compile(
            r'^read\s+(.+)$'
        )
        self.SERVER_PATTERN = re.compile(
            r'^using\s+(.+)$'
        )

        # Извлечение IP из ответов
        self.IPV4_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        self.IPV6_PATTERN = re.compile(r'\b([0-9a-fA-F:]+)\b')

        logging.info(f"Инициализирован плагин {self.SERVICE_NAME}")

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Основной метод парсинга строки лога dnsmasq"""
        if not line.strip():
            return None

        result = self._parse_syslog_line(line)
        return result

    def _parse_syslog_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Парсинг строки в syslog формате"""
        try:
            match = self.SYSLOG_PATTERN.match(line.strip())
            if not match:
                return None

            month_str, day_str, time_str, pid_str, message = match.groups()

            current_year = datetime.now().year
            dt_str = f"{month_str} {day_str} {current_year} {time_str}"

            try:
                dt = datetime.strptime(dt_str, '%b %d %Y %H:%M:%S')
                timestamp = dt.isoformat()
            except Exception:
                timestamp = f"{current_year}-{month_str}-{day_str} {time_str}"

            # Парсинг сообщения dnsmasq
            message_data = self._parse_dnsmasq_message(message)
            if not message_data:
                return None

            message_type = message_data.get('message_type', '')
            domain = message_data.get('domain', '')
            query_type = message_data.get('query_type', '')
            client_ip = message_data.get('client_ip', '')
            answer = message_data.get('answer', '')
            dns_server = message_data.get('dns_server', '')

            # Определяет статус ответа
            response_status = self._determine_response_status(message_type, answer)

            # Определяет cached
            cached = message_type in ['cached', 'reply_cached']

            # Дополнительные поля
            metadata = {
                'pid': int(pid_str) if pid_str.isdigit() else pid_str,
                'month': month_str,
                'day': day_str,
                'time': time_str,
                'original_message': message,
                'message_type': message_type,
            }

            # Добавляет специфичные поля
            if answer:
                metadata['answer_raw'] = answer

            if dns_server:
                metadata['dns_server'] = dns_server

            if message_type == 'config':
                metadata['config_info'] = message_data.get('config_info', '')

            if message_type == 'server':
                metadata['server_info'] = message_data.get('server_info', '')

            return self.create_record(
                timestamp=timestamp,
                client_ip=client_ip,
                query_name=domain,
                query_type=query_type,
                response=response_status,
                cached=cached,
                processing_time_ms=None,
                raw=line,
                _original={
                    'pid': pid_str,
                    'message': message,
                    'month': month_str,
                    'day': day_str,
                    'time': time_str
                },
                **metadata
            )

        except Exception as e:
            logging.debug(f"Ошибка парсинга dnsmasq syslog: {e}, строка: {line}")
            return None

    def _parse_dnsmasq_message(self, message: str) -> Optional[Dict[str, Any]]:
        """Парсинг сообщения dnsmasq"""
        result = {'raw_message': message}

        # Query: query[A] example.com from 127.0.0.1
        query_match = self.QUERY_PATTERN.match(message)
        if query_match:
            result['message_type'] = 'query'
            result['query_type'] = query_match.group(1)
            result['domain'] = query_match.group(2)
            result['client_ip'] = query_match.group(3)
            return result

        # Reply: reply example.com is 192.168.1.1
        reply_match = self.REPLY_PATTERN.match(message)
        if reply_match:
            result['message_type'] = 'reply'
            result['domain'] = reply_match.group(1)
            result['answer'] = reply_match.group(2)

            # Определяет тип ответа
            if 'cached' in message.lower():
                result['message_type'] = 'reply_cached'

            return result

        # Cached: cached example.com is 192.168.1.1
        cached_match = self.CACHED_PATTERN.match(message)
        if cached_match:
            result['message_type'] = 'cached'
            result['domain'] = cached_match.group(1)
            result['answer'] = cached_match.group(2)
            return result

        # Forwarded: forwarded example.com to 8.8.8.8
        forwarded_match = self.FORWARDED_PATTERN.match(message)
        if forwarded_match:
            result['message_type'] = 'forwarded'
            result['domain'] = forwarded_match.group(1)
            result['dns_server'] = forwarded_match.group(2)
            return result

        # Config: read /etc/hosts
        config_match = self.CONFIG_PATTERN.match(message)
        if config_match:
            result['message_type'] = 'config'
            result['config_info'] = config_match.group(1)
            return result

        # Server: using local addresses only
        server_match = self.SERVER_PATTERN.match(message)
        if server_match:
            result['message_type'] = 'server'
            result['server_info'] = server_match.group(1)
            return result

        if 'failed' in message.lower():
            result['message_type'] = 'error'
        elif 'warning' in message.lower():
            result['message_type'] = 'warning'
        elif 'started' in message.lower():
            result['message_type'] = 'startup'
        elif 'restart' in message.lower():
            result['message_type'] = 'restart'
        elif 'exiting' in message.lower():
            result['message_type'] = 'shutdown'
        else:
            # Неизвестный тип сообщения
            result['message_type'] = 'unknown'

        return result

    def _determine_response_status(self, message_type: str, answer: str = '') -> str:
        """Определяет статус ответа на основе типа сообщения и ответа"""

        if message_type == 'query':
            return 'FORWARDED'

        elif message_type in ['reply', 'reply_cached']:
            if not answer:
                return 'RESOLVED'
            answer_lower = answer.lower()

            # Обработка спец. ответов dnsmasq
            if answer_lower == 'nodata':
                return 'FAILED'
            elif answer_lower == 'nxdomain':
                return 'FAILED'
            elif answer_lower == 'servfail':
                return 'FAILED'
            elif '<' in answer:  # CNAME: <CNAME>
                return 'RESOLVED'
            else:
                return 'RESOLVED'

        elif message_type == 'cached':
            return 'CACHED'

        elif message_type == 'forwarded':
            return 'FORWARDED'

        elif message_type == 'error':
            return 'FAILED'

        else:
            return 'UNKNOWN'

    def extract_response_ips(self, data: Dict[str, Any]) -> List[str]:
        """Извлекает IP-адреса из ответа dnsmasq"""
        ips = []

        if 'metadata' in data:
            metadata = data['metadata']

            # Проверяет answer_raw
            if 'answer_raw' in metadata:
                answer = metadata['answer_raw']

                # Поиск IPv4
                ipv4_matches = self.IPV4_PATTERN.findall(answer)
                if ipv4_matches:
                    ips.extend(ipv4_matches)

                # Поиск IPv6
                if ':' in answer and ' ' not in answer:
                    parts = answer.split(':')
                    if len(parts) >= 2 and all(p == '' or p.isalnum() for p in parts):
                        ips.append(answer)

        if 'query_name' in data:
            ipv4_in_domain = self.IPV4_PATTERN.findall(data['query_name'])
            ips.extend(ipv4_in_domain)

        if 'metadata' in data and 'original' in data['metadata']:
            original = data['metadata']['original']
            for value in original.values():
                if isinstance(value, str):
                    found_ips = self.IPV4_PATTERN.findall(value)
                    ips.extend(found_ips)

        return list(set(ips))

    def get_info(self) -> Dict[str, Any]:
        """Информация о плагине"""
        return {
            "service": self.SERVICE_NAME,
            "description": f"Плагин обработки логов {self.SERVICE_NAME}",
            "supported_formats": ["syslog"]
        }


class DnsmasqPluginExtended(DnsmasqPlugin):
    """Расширенная версия плагина dnsmasq с дополнительной логикой"""

    def __init__(self):
        super().__init__()

        # Дополнительные паттерны для специфичных форматов dnsmasq
        self.DHCP_PATTERN = re.compile(
            r'^DHCP([A-Z]+)\s+(.+)$'
        )
        self.TFTP_PATTERN = re.compile(
            r'^TFTP\s+(.+)$'
        )

        logging.info(f"Инициализирован расширенный плагин {self.SERVICE_NAME}")

    def _parse_dnsmasq_message(self, message: str) -> Optional[Dict[str, Any]]:
        """Расширенный парсинг с поддержкой DHCP и TFTP"""

        result = super()._parse_dnsmasq_message(message)

        if result and result.get('message_type') not in ['unknown', 'warning', 'error']:
            return result

        dhcp_match = self.DHCP_PATTERN.match(message)
        if dhcp_match:
            result = {
                'message_type': 'dhcp',
                'dhcp_type': dhcp_match.group(1),
                'dhcp_info': dhcp_match.group(2),
                'raw_message': message
            }
            return result

        tftp_match = self.TFTP_PATTERN.match(message)
        if tftp_match:
            result = {
                'message_type': 'tftp',
                'tftp_info': tftp_match.group(1),
                'raw_message': message
            }
            return result

        return result

def create_dnsmasq_plugin(extended: bool = False) -> DnsmasqPlugin:
    """Создает экземпляр плагина dnsmasq"""
    if extended:
        return DnsmasqPluginExtended()
    return DnsmasqPlugin()

if __name__ == "__main__":
    # Тестирование плагина
    plugin = create_dnsmasq_plugin()

    test_lines = [
        # Стандартные запросы
        "Feb  5 16:59:48 dnsmasq[2762358]: query[A] subdomain.domain.ru from 127.0.0.1",
        "Feb  5 16:59:48 dnsmasq[2762358]: cached subdomain.domain.ru is 185.226.53.203",
        "Feb  5 16:59:48 dnsmasq[2762358]: reply test.ru is 1.1.1.1",
        "Feb  5 16:59:48 dnsmasq[2762358]: forwarded example.com to 8.8.8.8",

        # Специфичные случаи
        "Feb  5 16:59:48 dnsmasq[2762358]: reply example.com is NODATA",
        "Feb  5 16:59:48 dnsmasq[2762358]: reply example.com is NXDOMAIN",
        "Feb  5 16:59:48 dnsmasq[2762358]: read /etc/hosts",
        "Feb  5 16:59:48 dnsmasq[2762358]: using local addresses only",
    ]

    print(f"Тестирование плагина {plugin.SERVICE_NAME}\n")

    for i, line in enumerate(test_lines, 1):
        print(f"\n{'='*60}")
        print(f"Тест #{i}: {line}")

        result = plugin.parse_line(line)

        if result:
            print(f"\nРезультат:")

            # Вывод основных поля
            main_fields = ['timestamp', 'server', 'client_ip', 'query_name',
                          'query_type', 'response', 'cached']

            for field in main_fields:
                if field in result:
                    print(f"  {field}: {result[field]}")

            # Вывод response_ip (если имеются)
            if result.get('response_ip'):
                print(f"  response_ip: {result['response_ip']}")

            # Вывод метаданных (если имеются)
            if 'metadata' in result:
                print(f"  metadata: {result['metadata']}")
        else:
            print("Не удалось распарсить строку")
