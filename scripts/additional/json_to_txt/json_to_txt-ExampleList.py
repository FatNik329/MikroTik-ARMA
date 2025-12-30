import sys
import os
import logging
from pathlib import Path

project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

# Модули core/
## Логирование
from core.maintenance.logs_modules import setup_logging
## Основной функционал - json_to_txt_core.py
from core.additional.json_to_txt_core import JSONToTXTConverter
## Определение конфигурации и параметров
from core.maintenance.config_manager import get_json_to_txt_config

# Настройки скрипта по умолчанию
DEFAULT_CONFIG = {
    # Пути до JSON файлов (директория или файл)
    'json_paths': [
        Path("raw-data/ExampleList/report/ExampleList-report.json"),
    ],
    # Директория для выходных TXT файлов
    'output_dir': Path("raw-data/ExampleList/TXT"),
    # Рекурсивный поиск в поддиректориях
    'recursive_search': False,
    'type_generation': 'additive', # = recreation/additive'
}

def main():
    # Инициализация логирования
    logger = setup_logging(__file__, level=logging.INFO)

    script_name = Path(__file__).stem

    # Загрузка и объединение конфигурации
    final_config = get_json_to_txt_config(
        default_config=DEFAULT_CONFIG,
        script_name=script_name,
        config_path="configs/config.yaml"
    )

    # Запуск через ядро
    core = JSONToTXTConverter(final_config, script_name, logger)
    success = core.run()

    return success

if __name__ == "__main__":
    main()
