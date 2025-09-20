"""
Скрипт для управления Address Lists в проекте ARMA.
Поддерживает создание и удаление списков со структурой директорий.
"""

import argparse
import shutil
import sys
from pathlib import Path
from typing import List, Tuple
import json
import json5
import yaml

# Базовые пути проекта
BASE_DIR = Path(__file__).parent.parent.parent
CONFIGS_DIR = BASE_DIR / "configs"
RAW_DATA_DIR = BASE_DIR / "raw-data"
OUTPUT_DATA_DIR = BASE_DIR / "output-data"
CACHE_DIR = BASE_DIR / "cache"


def validate_list_name(list_name: str) -> bool:
    """Проверяет валидность имени списка"""
    if not list_name.replace("-", "").isalnum():
        print(f"🚫 Ошибка: '{list_name}' — недопустимое имя. Используйте буквы, цифры и дефисы.")
        return False
    return True


def get_list_paths(list_name: str) -> List[Tuple[Path, str]]:
    """Возвращает список всех путей, связанных с указанным списком"""
    return [
        (CONFIGS_DIR / "AddressLists" / list_name, "Конфигурация AddressList"),
        (RAW_DATA_DIR / list_name / "DNS", "Директория необработанных данных DNS"),
        (RAW_DATA_DIR / list_name / "AS", "Директория необработанных данных AS"),
        (OUTPUT_DATA_DIR / list_name / "DNS", "Директория обработанных данных DNS"),
        (OUTPUT_DATA_DIR / list_name / "AS", "Директория обработанных данных AS"),
        (OUTPUT_DATA_DIR / list_name / "Custom", "Директория для кастомных данных"),
    ]


def create_list(list_name: str) -> bool:
    """Создаёт полную структуру директорий для нового списка"""
    try:
        if not validate_list_name(list_name):
            return False

        paths = get_list_paths(list_name)
        created_paths = []

        # Создание директорий
        for path, desc in paths:
            if path.suffix: # Файл
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            else:  # Директория
                path.mkdir(parents=True, exist_ok=True)
            created_paths.append((path, desc))

        # Шаблонные файлы конфигурации
        config_dir = CONFIGS_DIR / "AddressLists" / list_name
        dns_config = config_dir / "DNS" / f"{list_name}.yaml"
        as_config = config_dir / "AS" / "as_list.json5"

        dns_config.parent.mkdir(parents=True, exist_ok=True)
        as_config.parent.mkdir(parents=True, exist_ok=True)

        if not dns_config.exists():
            with open(dns_config, "w") as f:
                yaml.dump({"target_domains": ["example.com", "example2.com"]}, f)
            created_paths.append((dns_config, "DNS конфигурация"))

        if not as_config.exists():
            as_numbers = ["AS12345", "AS67890"]
            with open(as_config, "w") as f:
                json.dump(as_numbers, f, indent=2)
            created_paths.append((as_config, "AS конфигурация"))

        # Добавление списка в address_lists.yaml
        address_lists_file = CONFIGS_DIR / "address_lists.yaml"
        address_lists_file.touch(exist_ok=True)

        with open(address_lists_file, "r") as f:
            lists_data = yaml.safe_load(f) or {}

        # Инициализация структуры, если файл пустой или невалидный
        if not isinstance(lists_data, dict):
            lists_data = {}
        if "addressList" not in lists_data:
            lists_data["addressList"] = []

        # Добавление списка, если отсутствует
        if list_name not in lists_data["addressList"]:
            lists_data["addressList"].append(list_name)
            with open(address_lists_file, "w") as f:
                yaml.dump(lists_data, f, sort_keys=False)
            created_paths.append((address_lists_file, "Добавление в address_lists.yaml"))
        else:
            print(f"ℹ️ Список '{list_name}' уже присутствует в address_lists.yaml")

        # Итоговый отчёт о создании листа
        print("\n✅ Успешно созданы следующие элементы:")
        for path, desc in created_paths:
            print(f"  - {desc}: {path.relative_to(BASE_DIR)}")

        # Инструкция по дальнейшим действиям
        print("\n📌 Дальнейшие действия:")
        print(f"1. Добавьте домены (если требуется) в {dns_config.relative_to(BASE_DIR)}. Если использование не планируется - удалите шаблонный файл.")
        print(f"2. Добавьте AS номера (если требуется) в {as_config.relative_to(BASE_DIR)}. Если использование не планируется - удалите шаблонный файл.")
        print("3. Запустите проект через run.sh или проверьте вручную, запустив каждый скрипт по отдельности из корневой директории проекта: python scripts/<functional-level>/<name_scripts>.py")

        return True

    except Exception as e:
        print(f"🚫 Критическая ошибка при создании списка: {e}")
        return False

def remove_list(list_name: str) -> bool:
    """Удаляет все данные и директории, связанные с указанным списком"""
    try:
        if not validate_list_name(list_name):
            return False

        paths = get_list_paths(list_name)
        removed_paths = []
        errors = []

        def force_remove(path):
            """Рекурсивное удаление"""
            if not path.exists():
                return False

            try:
                if path.is_file() or path.is_symlink():
                    path.unlink()
                else:
                    shutil.rmtree(path, ignore_errors=False)

                if path.exists():
                    raise RuntimeError(f"Путь {path} всё ещё существует после удаления")
                return True
            except Exception as e:
                errors.append(f"{path.relative_to(BASE_DIR)}: {str(e)}")
                return False

        # Удаляет все связанные пути
        for path, desc in paths:
            if force_remove(path):
                removed_paths.append((path, desc))
                print(f"✅ Удалено: {path.relative_to(BASE_DIR)}")
            elif path.exists():
                print(f"⚠️ Не удалось удалить: {path.relative_to(BASE_DIR)}")

        # Проверяет и обновляет address_lists.yaml
        address_lists_file = CONFIGS_DIR / "address_lists.yaml"
        if address_lists_file.exists():
            try:
                with open(address_lists_file, "r") as f:
                    lists_data = yaml.safe_load(f) or {}

                if "addressList" in lists_data and list_name in lists_data["addressList"]:
                    lists_data["addressList"].remove(list_name)
                    with open(address_lists_file, "w") as f:
                        yaml.dump(lists_data, f, sort_keys=False)
                    removed_paths.append((address_lists_file, "Обработка из address_lists.yaml"))
                    print(f"✅ Удалён список '{list_name}' из address_lists.yaml")
                else:
                    print(f"ℹ️ Список '{list_name}' не найден в address_lists.yaml")
            except Exception as e:
                errors.append(f"Ошибка при работе с address_lists.yaml: {e}")
                print(f"⚠️ Ошибка при обновлении address_lists.yaml: {e}")

        for parent_dir in [
            RAW_DATA_DIR / list_name,
            OUTPUT_DATA_DIR / list_name,
            CONFIGS_DIR / "AddressLists" / list_name
        ]:
            try:
                if parent_dir.exists() and not any(parent_dir.iterdir()):
                    parent_dir.rmdir()
                    print(f"🔹 Удалена пустая родительская директория: {parent_dir.relative_to(BASE_DIR)}")
            except Exception as e:
                errors.append(f"Ошибка при удалении {parent_dir}: {e}")

        # Итоговый отчёт об удалении листа
        print("\n📊 Итоговый отчёт:")
        if removed_paths:
            print("\n✅ Успешно удалено:")
            for path, desc in removed_paths:
                print(f"  - {desc}: {path.relative_to(BASE_DIR)}")

        if errors:
            print("\n🚫 Ошибки при удалении:")
            for error in errors:
                print(f"  - {error}")

        return len(errors) == 0

    except Exception as e:
        print(f"🚫 Критическая ошибка при удалении списка: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Управление Address Lists в проекте ARMA",
        epilog="Примеры использования:\n"
               "  python init_newList.py --create-list YouTube\n"
               "  python init_newList.py --remove-list OldList",
        formatter_class=argparse.RawTextHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--create-list",
        metavar="NAME",
        help="Создать новый Address List с указанным именем"
    )
    group.add_argument(
        "--remove-list",
        metavar="NAME",
        help="Удалить Address List и все связанные данные"
    )

    args = parser.parse_args()

    if args.create_list:
        if not create_list(args.create_list):
            sys.exit(1)
    elif args.remove_list:
        if not remove_list(args.remove_list):
            sys.exit(1)


if __name__ == "__main__":
    main()
