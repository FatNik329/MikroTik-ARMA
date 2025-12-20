#Скрипт-клиент для запуска фильтрации-обогащения IP адресов (работает через core/additional/ip_analyst_core.py)
import sys
import os
import logging
from pathlib import Path

project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

# Модули core/
## Логирование
from core.maintenance.logs_modules import setup_logging
## Основной функционал - ip_analyst_core.py
from core.additional.ip_analyst_core import IpAnalystCore
## Определение конфигурации и параметров
from core.maintenance.config_manager import get_ip_analyst_config

# Настройки скрипта по умолчанию (менее приоритетные, чем configs/config.yaml)
DEFAULT_CONFIG = {
    # Пути к файлам
    'ip_list_dir': ['raw-data/ExampleList/TXT'],  # Директория с исходными IP-адресами (TXT, JSON, YAML).  # Может быть строкой или списком ['путь1', 'путь2']
    'dns_file_filter': 'none', # Файл с DNS записями (исключает совпадения). Опциональный параметр, для отключения 'none'. Для включения указать путь до файла results-dns.yaml '/path/to/results-dns.yaml'
    'asn_db_file': 'path/to/ip-to-asn.mmdb',
    'output_dir': 'output-data/ExampleList/Custom',    # Кастомная директория для сохранения .rsc файла

    # Имя выходного файла
    'output_filename': 'My-ExampleList',  # Определяет и имя файла, и имя листа в RSC. 'none' - используется комбинированное имя всех исходных файлов

    # Дополнительные параметры и фильтры
    'prefix_threshold': 5,  # Минимальное количество IP в префиксе для его добавления
    'asn_filter': 'none',  # Пример: определённые ASN ['AS8075', 'AS15169', 'AS32934']. Без фильтрации: one
    'country_filter': 'none', # Пример: фильтрация на основе кода страны ['US', 'FR', 'RU', ...]. Без фильтраации: none
    'remove_last_seen': 55,  # Исключать IP, которые не появлялись более N дней (поддерживает ТОЛЬКО целые числа - дни). Без фильтрации: None
    'report_generation': 'true', # true/false - генерировать подробный отчёт об обработанных данных
}

def main():
    # Инициализация логирования
    # Логгер автоматически создаст нужную директорию и файл
    logger = setup_logging(__file__, level=logging.INFO) # <- Установить нужный уровень логирования при вызове

    script_name = Path(__file__).stem

    # Загрузка и объединение конфигурации
    final_config = get_ip_analyst_config(
        default_config=DEFAULT_CONFIG,
        script_name=script_name
    )

    # Запуск через ядро
    core = IpAnalystCore(final_config, script_name)
    success = core.run()

if __name__ == "__main__":
    main()
