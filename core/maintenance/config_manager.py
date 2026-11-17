"""
Менеджер конфигураций для модулей системы ARMA.

Источники конфигурации (по возрастанию приоритета):
    1. configs/config.yaml                — глобальный конфиг (низший приоритет)
    2. configs/modules/<module_name>.yaml — конфиг конкретного модуля (высший приоритет)

Оба файла читаются всегда, результат мержится: модульный поверх глобального.
Имя модуля и ключ скрипта выводятся из script_name формата '<module>-<Script>'.
"""

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import yaml


DEFAULT_CONFIG_PATH = 'configs/config.yaml'
DEFAULT_MODULES_DIR = 'configs/modules'


def _split_script_name(script_name: str) -> Tuple[Optional[str], str]:
    """
    Разбирает имя скрипта на имя модуля и ключ скрипта.

    'ip_analyst-ExampleScript1' -> ('ip_analyst', 'ExampleScript1')
    'ExampleScript1'            -> (None, 'ExampleScript1')

    Args:
        script_name: Полное имя скрипта (обычно __name__).

    Returns:
        Кортеж (module_name | None, script_key).
    """
    if '-' in script_name:
        module_name, script_key = script_name.split('-', 1)
        return module_name, script_key
    return None, script_name


def _load_yaml(path: Path) -> Dict[str, Any]:
    """
    Читает YAML-файл и возвращает словарь. При любой проблеме — пустой dict.

    Args:
        path: Путь к YAML-файлу.

    Returns:
        Содержимое файла как dict или {} при ошибке/отсутствии.
    """
    if not path.exists():
        logging.debug(f"Файл конфигурации не найден: {path}")
        return {}

    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logging.warning(f"Ошибка чтения YAML {path}: {e}")
        return {}

    if not isinstance(data, dict):
        logging.warning(f"YAML {path} не является словарём — игнорируется")
        return {}

    return data


def _extract_script_config(
    data: Dict[str, Any],
    module_name: Optional[str],
    script_key: str,
    nested: bool,
    source: Path,
) -> Dict[str, Any]:
    """
    Вырезает конфигурацию скрипта из уже прочитанного YAML-словаря.

    Args:
        data: Содержимое YAML-файла.
        module_name: Имя модуля (для вложенной структуры).
        script_key: Ключ скрипта.
        nested: True — структура {module: {script: {...}}} (config.yaml),
                False — плоская {script: {...}} (модульный файл).
        source: Путь к файлу (для логирования).

    Returns:
        Словарь параметров скрипта (может быть пустым).
    """
    if nested:
        if module_name is None:
            return {}
        module_section = data.get(module_name)
        if not isinstance(module_section, dict):
            return {}
        script_section = module_section.get(script_key)
    else:
        script_section = data.get(script_key)

    if not isinstance(script_section, dict):
        return {}

    return dict(script_section)


def get_config(
    script_name: str,
    config_path: str = DEFAULT_CONFIG_PATH,
    modules_dir: str = DEFAULT_MODULES_DIR,
) -> Dict[str, Any]:
    """
    Возвращает итоговую конфигурацию для скрипта.

    Приоритет: configs/modules/<module>.yaml > configs/config.yaml.

    Args:
        script_name: Полное имя скрипта (обычно __name__), формат '<module>-<Script>'.
        config_path: Путь к глобальному YAML-конфигу.
        modules_dir: Директория с модульными YAML-конфигами.

    Returns:
        Объединённый словарь параметров. Пустой, если конфигурация не найдена.
    """
    module_name, script_key = _split_script_name(script_name)

    if module_name is None:
        logging.warning(
            f"Не удалось выделить имя модуля из '{script_name}' "
            f"(ожидается формат '<module>-<Script>'); "
            f"модульный конфиг не будет прочитан"
        )

    # --- Глобальный конфиг (низший приоритет) ---
    global_data = _load_yaml(Path(config_path))
    global_config = _extract_script_config(
        data=global_data,
        module_name=module_name,
        script_key=script_key,
        nested=True,
        source=Path(config_path),
    )

    # --- Модульный конфиг (высший приоритет) ---
    module_config: Dict[str, Any] = {}
    module_file: Optional[Path] = None
    if module_name is not None:
        module_file = Path(modules_dir) / f"{module_name}.yaml"
        module_data = _load_yaml(module_file)
        module_config = _extract_script_config(
            data=module_data,
            module_name=module_name,
            script_key=script_key,
            nested=False,
            source=module_file,
        )

    # --- Merge: модульный поверх глобального ---
    final_config = dict(global_config)
    overridden = []
    for key, value in module_config.items():
        if key in final_config and final_config[key] != value:
            overridden.append(key)
        final_config[key] = value

    # --- Логирование источников ---
    sources = []
    if global_config:
        sources.append(f"{config_path}")
    if module_config:
        sources.append(str(module_file))

    context = f"{module_name}/{script_key}" if module_name else script_key
    if not sources:
        logging.warning(
            f"Конфигурация для {context} не найдена "
            f"ни в {config_path}, ни в {modules_dir}"
        )
    else:
        logging.info(f"Конфигурация {context}: источники — {', '.join(sources)}")
        if overridden:
            logging.warning(
                f"Конфигурация {context}: параметры переопределены модульным файлом: "
                f"{', '.join(sorted(overridden))}"
            )

    return final_config
