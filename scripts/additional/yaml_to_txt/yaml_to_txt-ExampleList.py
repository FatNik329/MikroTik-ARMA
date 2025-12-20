#Скрипт-клиент для запуска обработки YAML файлов 'results-dns.yaml' (работает через core/additional/yaml_to_txt_core.py)
import sys
import os
import logging
from pathlib import Path

project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

# Модули core/
## Логирование
from core.maintenance.logs_modules import setup_logging
## Основной функционал - yaml_to_txt_core.py
from core.additional.yaml_to_txt_core import YAMLToTXTConverter
## Определение конфигурации и параметров
from core.maintenance.config_manager import get_yaml_to_txt_config

# Настройки скрипта по умолчанию
DEFAULT_CONFIG = {
    # Пути до YAML файлов
    'yaml_paths': [
        Path("raw-data/ExampleList/DNS/results-dns.yaml"),
    ],
    # Директория для выходных TXT файлов (простой список)
    'output_dir': Path("raw-data/ExampleList/TXT"),
    # Рекурсивный поиск в поддиректориях
    'recursive_search': False,
    'encoding': 'utf-8',
}

def main():
    # Инициализация логирования
    # Логгер автоматически создаст нужную директорию и файл
    logger = setup_logging(__file__, level=logging.INFO) # <- Установить нужный уровень логирования при вызове

    script_name = Path(__file__).stem

    # Загрузка и объединение конфигурации
    final_config = get_yaml_to_txt_config(
        default_config=DEFAULT_CONFIG,
        script_name=script_name
    )

    # Запуск через ядро
    core = YAMLToTXTConverter(final_config, script_name, logger)
    success = core.run()

if __name__ == "__main__":
    main()
