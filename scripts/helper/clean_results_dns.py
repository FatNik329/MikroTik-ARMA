#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Скрипт для удаления категорий и доменов из файлов results-dns.yaml
Запускается вручную, параметры настраиваются внутри скрипта
"""

import os
import sys
from pathlib import Path
from datetime import datetime
import yaml
from typing import List, Optional, Set


# ========== НАСТРОЙКА ПАРАМЕТРОВ ==========
# Категории для удаления (если не требуется - оставить пустым списком)
DEL_CATEGORY: List[str] = [
    "Google",
    "ru",
]

# Домены для удаления (если не требуется - оставить пустым списком)
DEL_DOMAIN: List[str] = [
     "google.com",
]

# Пути к директориям с файлами results-dns.yaml (можно указать несколько)
PATHS_TO_REMOVE_DATA: List[str] = [
    "/path/to/raw-data/Example-List1/DNS",  # Заменить на реальный путь
    "/path/to/raw-data/Example-List2/DNS",
]

# ==========================================


class DNSDataRemover:
    """Класс для удаления данных из YAML-файлов"""

    def __init__(self, del_categories: List[str], del_domains: List[str], paths: List[str]):
        self.del_categories = set(del_categories)
        self.del_domains = set(del_domains)
        self.paths = paths
        self.processed_files = 0
        self.modified_files = 0
        self.total_categories_removed = 0
        self.total_domains_removed = 0

    def log(self, message: str, level: str = "INFO"):
        """Вывод лога в терминал с временной меткой"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def find_yaml_files(self, base_path: Path) -> List[Path]:
        """Поиск файлов results-dns.yaml в указанной директории"""
        if not base_path.exists():
            self.log(f"Директория не существует: {base_path}", "ERROR")
            return []

        if not base_path.is_dir():
            self.log(f"Указанный путь не является директорией: {base_path}", "ERROR")
            return []

        # Поиск файлов с именем results-dns.yaml
        yaml_files = list(base_path.glob("**/results-dns.yaml"))
        root_file = base_path / "results-dns.yaml"
        if root_file.exists() and root_file not in yaml_files:
            yaml_files.append(root_file)

        if yaml_files:
            self.log(f"Найдено {len(yaml_files)} файлов в {base_path}")
            for f in yaml_files:
                self.log(f"  - {f.relative_to(base_path)}", "DEBUG")
        else:
            self.log(f"Файлы results-dns.yaml не найдены в {base_path}", "WARNING")

        return yaml_files

    def remove_domains_from_category(self, category_data: dict, category_name: str) -> tuple:
        """
        Удаление указанных доменов из категории
        Возвращает (удалено_доменов, изменена_категория)
        """
        removed_count = 0
        category_modified = False

        # Определение доменов для удаления к конкретной категории
        domains_to_remove = set()
        for domain in self.del_domains:
            if domain in category_data:
                domains_to_remove.add(domain)

        if not domains_to_remove:
            return 0, False

        # Удаляет найденные домены
        for domain in domains_to_remove:
            del category_data[domain]
            removed_count += 1
            category_modified = True
            self.log(f"  Удалён домен '{domain}' из категории '{category_name}'", "INFO")

        return removed_count, category_modified

    def process_yaml_file(self, file_path: Path) -> bool:
        """
        Обработка одного YAML-файла
        Возвращает True если файл был изменён
        """
        self.log(f"Обработка файла: {file_path}", "INFO")
        file_modified = False

        try:
            # Чтение YAML-файла
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    data = yaml.safe_load(f)
                except yaml.YAMLError as e:
                    self.log(f"Ошибка парсинга YAML: {e}", "ERROR")
                    return False

            if not data:
                self.log("Файл пуст или не содержит данных", "WARNING")
                return False

            # Проверка наличия секции categories
            if 'categories' not in data:
                self.log("В файле нет секции 'categories'", "WARNING")
                return False

            categories = data['categories']

            # ===== ШАГ 1: Удаление доменов =====
            if self.del_domains:
                self.log(f"Поиск доменов для удаления: {', '.join(self.del_domains)}", "INFO")
                domains_removed_global = 0

                # Проход по всем категориям
                for category_name, category_data in list(categories.items()):
                    if isinstance(category_data, dict):
                        removed, modified = self.remove_domains_from_category(category_data, category_name)
                        if modified:
                            domains_removed_global += removed
                            file_modified = True
                            # Если категория пустая, удалить
                            if not category_data:
                                del categories[category_name]
                                self.log(f"  Категория '{category_name}' стала пустой и была удалена", "INFO")

                if domains_removed_global > 0:
                    self.log(f"Всего удалено доменов: {domains_removed_global}", "INFO")
                    self.total_domains_removed += domains_removed_global
                else:
                    self.log("Указанные домены не найдены ни в одной категории", "INFO")

            # ===== ШАГ 2: Удаление категорий =====
            if self.del_categories:
                self.log(f"Поиск категорий для удаления: {', '.join(self.del_categories)}", "INFO")
                categories_removed = 0

                for category in self.del_categories:
                    if category in categories:
                        del categories[category]
                        categories_removed += 1
                        file_modified = True
                        self.log(f"  Удалена категория '{category}'", "INFO")

                if categories_removed > 0:
                    self.log(f"Всего удалено категорий: {categories_removed}", "INFO")
                    self.total_categories_removed += categories_removed
                else:
                    self.log("Указанные категории не найдены", "INFO")

            if file_modified:
                self.log(f"Сохранение изменений в {file_path}", "INFO")
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        yaml.dump(data, f, allow_unicode=True, default_flow_style=False,
                                 sort_keys=False, indent=2)
                    self.log(f"Файл успешно сохранён", "INFO")
                    self.modified_files += 1
                except Exception as e:
                    self.log(f"Ошибка сохранения файла: {e}", "ERROR")
                    return False
            else:
                self.log(f"Файл не требует изменений", "INFO")

            return file_modified

        except Exception as e:
            self.log(f"Критическая ошибка при обработке файла {file_path}: {e}", "ERROR")
            return False

    def run(self):
        """Запуск процесса удаления"""
        self.log("=" * 70)
        self.log("ЗАПУСК ПРОЦЕССА УДАЛЕНИЯ ДАННЫХ ИЗ ФАЙЛОВ results-dns.yaml")
        self.log("=" * 70)

        # Информация о параметрах
        if self.del_categories:
            self.log(f"Категории для удаления: {', '.join(self.del_categories)}", "INFO")
        else:
            self.log("Категории для удаления не указаны", "INFO")

        if self.del_domains:
            self.log(f"Домены для удаления: {', '.join(self.del_domains)}", "INFO")
        else:
            self.log("Домены для удаления не указаны", "INFO")

        if not self.del_categories and not self.del_domains:
            self.log("ВНИМАНИЕ: Не указаны ни категории, ни домены для удаления!", "WARNING")
            self.log("Никакие изменения не будут произведены", "WARNING")
            return

        self.log(f"Пути для обработки: {len(self.paths)}")
        for idx, path in enumerate(self.paths, 1):
            self.log(f"  {idx}. {path}", "DEBUG")

        # Обработка каждого пути
        for path_str in self.paths:
            self.log(f"\n--- Обработка пути: {path_str} ---", "INFO")
            base_path = Path(path_str)

            if not base_path.exists():
                self.log(f"Путь не существует: {path_str}", "ERROR")
                continue

            yaml_files = self.find_yaml_files(base_path)

            if not yaml_files:
                self.log(f"В {path_str} не найдено файлов results-dns.yaml", "WARNING")
                continue

            for yaml_file in yaml_files:
                self.processed_files += 1
                self.process_yaml_file(yaml_file)

        # Итоговая статистика
        self.log("\n" + "=" * 70)
        self.log("СТАТИСТИКА:")
        self.log("=" * 70)
        self.log(f"Обработано файлов: {self.processed_files}")
        self.log(f"Файлов изменено: {self.modified_files}")
        self.log(f"Всего удалено категорий: {self.total_categories_removed}")
        self.log(f"Всего удалено доменов: {self.total_domains_removed}")
        self.log("=" * 70)


def main():
    """Главная функция"""
    # Проверка параметров
    if not PATHS_TO_REMOVE_DATA:
        print("[ERROR] Не указаны пути для обработки (PATHS_TO_REMOVE_DATA)")
        print("Заполните список PATHS_TO_REMOVE_DATA в настройках скрипта")
        sys.exit(1)

    valid_paths = [p for p in PATHS_TO_REMOVE_DATA if p and p.strip()]

    if not valid_paths:
        print("[ERROR] Все пути пустые или содержат только пробелы")
        sys.exit(1)

    remover = DNSDataRemover(
        del_categories=DEL_CATEGORY,
        del_domains=DEL_DOMAIN,
        paths=valid_paths
    )

    remover.run()


if __name__ == "__main__":
    main()
