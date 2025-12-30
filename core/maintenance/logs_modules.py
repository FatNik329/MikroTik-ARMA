# core/logs_modules.py
"""
Универсальный модуль логирования для скриптов системы MikroTik-ARMA.
"""
import logging
import sys
from pathlib import Path
from typing import Optional, Dict


class LoggerManager:
    """Менеджер логирования проекта"""

    _loggers: Dict[str, logging.Logger] = {}

    # Формат вывода логов
    _formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        '%Y-%m-%d %H:%M:%S'
    )

    # Пути хранения категорий скриптов - при добавлении нового модуля указать путь
    _category_paths = {
        'ip_analyst': 'logs/additional/ip_analyst',
        'filter_results_dns': 'logs/additional/filter_results_dns',
        'get_IP_Connections': 'logs/additional/get_IP_Connections',
        'yaml_to_txt': 'logs/additional/yaml_to_txt',
    }

    @classmethod
    def setup_global_logging(cls, level: int = logging.INFO):
        """Настраивает глобальное логирование для всех модулей"""
        # Очищаем корневой логгер
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.setLevel(level)

        # Консольный обработчик
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(cls._formatter)
        root_logger.addHandler(console_handler)

    @classmethod
    def get_logger(cls, script_path: str) -> logging.Logger:
        """Получает логгер с файловым обработчиком для скрипта"""
        script_name = Path(script_path).stem

        if script_name in cls._loggers:
            return cls._loggers[script_name]

        # Получает логгер (использует корневые настройки)
        logger = logging.getLogger(script_name)
        logger.propagate = True

        category = cls._detect_category(script_name)
        base_path = cls._category_paths.get(category, f'logs/{category}')
        log_path = Path(base_path) / f"{script_name}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setFormatter(cls._formatter)
        logger.addHandler(file_handler)

        cls._loggers[script_name] = logger
        return logger

    @classmethod
    def _detect_category(cls, script_name: str) -> str:
        """Определяет категорию скрипта по его имени"""
        for category in cls._category_paths:
            if script_name.startswith(category):
                return category

        if '-' in script_name:
            return script_name.split('-')[0]

        return 'general'

    @classmethod
    def add_category(cls, category_name: str, log_path: str) -> None:
        """Добавление новой категории"""
        cls._category_paths[category_name] = log_path

    @classmethod
    def set_default_level(cls, level: int) -> None:
        """Изменение уровня логирования по умолчанию"""
        logging.getLogger().setLevel(level)
        for logger in cls._loggers.values():
            logger.setLevel(level)


def setup_logging(script_file: str,
                  level: int = logging.INFO) -> logging.Logger:
    """
    Главная функция для настройки логирования

    Args:
        script_file: __file__ из вызывающего скрипта
        level: Уровень логирования

    Returns:
        Настроенный логгер
    """
    # 1. Настраивает глобальное логирование (консоль для всех)
    LoggerManager.setup_global_logging(level)

    # 2. Получаем логгер для скрипта (с файловым обработчиком)
    logger = LoggerManager.get_logger(script_file)

    return logger
