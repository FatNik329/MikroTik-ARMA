#Скрипт-клиент для запуска обработки и фильтрации DNS-данных из YAML-файлов (работает через core/additional/filter_results_dns_core.py)
import sys
import os
import logging
from pathlib import Path

project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

# Модули core/
## Логирование
from core.maintenance.logs_modules import setup_logging
## Основной функционал - filter_results_dns_core.py
from core.additional.filter_results_dns_core import FilterResultsDnsCore
## Определение конфигурации и параметров
from core.maintenance.config_manager import get_filter_results_dns_config

# Настройки скрипта по умолчанию
DEFAULT_CONFIG = {
    'input_file': 'raw-data/ExampleList/DNS/results-dns.yaml', # Входной файл results-dns.yaml
    'output_file': 'raw-data/ExampleList/Filter/filter-results-dns.yaml', # Выходной обработанный results-dns.yaml
    'domains_catsort': True # Дополнительный файл с сортировкой доменов 2-го уровня
}

def main():
    # Инициализация логирования
    # Логгер автоматически создаст нужную директорию и файл
    logger = setup_logging(__file__, level=logging.INFO) # <- Установить нужный уровень логирования при вызове

    script_name = Path(__file__).stem

    # Загрузка и объединение конфигурации
    final_config = get_filter_results_dns_config(
        default_config=DEFAULT_CONFIG,
        script_name=script_name
    )

    # Запуск через ядро
    core = FilterResultsDnsCore(final_config, script_name, logger)
    success = core.run()

if __name__ == "__main__":
    main()
