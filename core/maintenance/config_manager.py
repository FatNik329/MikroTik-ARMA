"""
Универсальный менеджер конфигураций для модулей системы MikroTik-ARMA.
Поддерживает приоритет: YAML конфиг > DEFAULT_CONFIG скрипта
"""
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path


def get_script_key(script_name: str, module_prefix: str = None) -> str:
    """
    Извлекает ключ скрипта из имени файла.

    Args:
        script_name: Имя скрипта (например, 'ip_analyst-ExampleScript1')
        module_prefix: Префикс модуля (например, 'ip_analyst-')

    Returns:
        Ключ для поиска в конфиге (например, 'ExampleScript1')
    """
    # Если передан префикс модуля, использует его для извлечения
    if module_prefix and script_name.startswith(module_prefix):
        return script_name[len(module_prefix):]

    # Ищет любой префикс с дефисом
    if '-' in script_name:
        return script_name.split('-', 1)[1]

    return script_name


def load_module_config_from_yaml(
    module_name: str,
    script_key: str,
    config_path: str = 'configs/config.yaml'
) -> Dict[str, Any]:
    """
    Загружает конфигурацию для конкретного скрипта из YAML файла.

    Args:
        module_name: Имя модуля (например, 'ip_analyst')
        script_key: Ключ скрипта (например, 'ExampleScript1')
        config_path: Путь к YAML файлу конфигурации

    Returns:
        Словарь с конфигурацией скрипта или пустой словарь
    """
    config_file = Path(config_path)
    if not config_file.exists():
        logging.debug(f"Файл конфигурации не найден: {config_file}")
        return {}

    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)

        if not isinstance(config_data, dict):
            logging.debug("YAML конфиг не является словарем")
            return {}

        # Получаем конфигурацию модуля
        module_config = config_data.get(module_name, {})
        if not isinstance(module_config, dict):
            logging.debug(f"Раздел {module_name} не найден или неверного формата")
            return {}

        # Получаем конфигурацию скрипта
        script_config = module_config.get(script_key, {})

        if script_config:
            logging.info(f"Загружена YAML конфигурация для {module_name}/{script_key}")

        return dict(script_config)

    except Exception as e:
        logging.warning(f"Ошибка загрузки YAML конфигурации: {e}")
        return {}


def merge_configs(
    default_config: Dict[str, Any],
    yaml_config: Dict[str, Any],
    module_name: str = None,
    script_key: str = None
) -> Dict[str, Any]:
    """
    Объединяет конфигурации с приоритетом YAML.

    Args:
        default_config: Конфигурация по умолчанию из скрипта
        yaml_config: Конфигурация из YAML файла
        module_name: Имя модуля (для логирования)
        script_key: Ключ скрипта (для логирования)

    Returns:
        Объединенная конфигурация
    """
    final_config = default_config.copy()

    for key, value in yaml_config.items():
        if key in final_config:
            final_config[key] = value
        else:
            log_context = f"{module_name}/{script_key}" if module_name and script_key else ""
            logging.warning(f"Неизвестный параметр в YAML конфиге {log_context}: {key}")

    return final_config


def get_ip_analyst_config(
    default_config: Dict[str, Any],
    script_name: str,
    config_path: str = 'configs/config.yaml'
) -> Dict[str, Any]:
    """
    Специализированная функция для модуля ip_analyst.

    Args:
        default_config: Конфигурация по умолчанию из скрипта
        script_name: Полное имя скрипта (например, 'ip_analyst-ExampleScript1')
        config_path: Путь к YAML файлу конфигурации

    Returns:
        Объединенная конфигурация для скрипта ip_analyst
    """
    module_name = 'ip_analyst'
    script_key = get_script_key(script_name, module_prefix='ip_analyst-')

    yaml_config = load_module_config_from_yaml(
        module_name=module_name,
        script_key=script_key,
        config_path=config_path
    )

    return merge_configs(default_config, yaml_config, module_name, script_key)


def get_filter_results_dns_config(
    default_config: Dict[str, Any],
    script_name: str,
    config_path: str = 'configs/config.yaml'
) -> Dict[str, Any]:
    """
    Специализированная функция для модуля filter_results_dns.
    """
    module_name = 'filter_results_dns'
    script_key = get_script_key(script_name, module_prefix='filter_results_dns-')

    yaml_config = load_module_config_from_yaml(
        module_name=module_name,
        script_key=script_key,
        config_path=config_path
    )

    return merge_configs(default_config, yaml_config, module_name, script_key)


def get_yaml_to_txt_config(
    default_config: Dict[str, Any],
    script_name: str,
    config_path: str = 'configs/config.yaml'
) -> Dict[str, Any]:
    """
    Специализированная функция для модуля yaml_to_txt.
    """
    module_name = 'yaml_to_txt'
    script_key = get_script_key(script_name, module_prefix='yaml_to_txt-')

    yaml_config = load_module_config_from_yaml(
        module_name=module_name,
        script_key=script_key,
        config_path=config_path
    )

    return merge_configs(default_config, yaml_config, module_name, script_key)


def get_generic_config(
    default_config: Dict[str, Any],
    script_name: str,
    module_name: str,
    module_prefix: Optional[str] = None,
    config_path: str = 'configs/config.yaml'
) -> Dict[str, Any]:
    """
    Args:
        default_config: Конфигурация по умолчанию из скрипта
        script_name: Полное имя скрипта
        module_name: Имя модуля в YAML конфиге
        module_prefix: Префикс модуля для извлечения script_key (опционально)
        config_path: Путь к YAML файлу конфигурации

    Returns:
        Объединенная конфигурация
    """
    script_key = get_script_key(script_name, module_prefix)

    yaml_config = load_module_config_from_yaml(
        module_name=module_name,
        script_key=script_key,
        config_path=config_path
    )

    return merge_configs(default_config, yaml_config, module_name, script_key)
  
