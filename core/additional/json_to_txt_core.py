"""
Ядро функционала для скриптов json_to_txt-*
Содержит логику для конвертации JSON файлов с IP адресами (IPv4) в текстовые файлы (TXT)
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Set, Optional, Union
import time
import logging

class JSONToTXTConverter:
    """Конвертер JSON файлов в TXT формат с IP-адресами и префиксами."""

    def __init__(self, config: Dict, script_name: str, logger: logging.Logger):
        """
        Инициализация конвертера.

        Args:
            config: Конфигурация скрипта (уже объединенная с YAML)
            script_name: Имя скрипта-клиента
            logger: Логгер для записи событий
        """
        self.config = config
        self.script_name = script_name
        self.logger = logger

        self._normalize_paths()

        # Статистика обработки
        self.stats = {
            'processed_paths': 0,
            'processed_files': 0,
            'total_ips': 0,
            'created_files': 0,
            'errors': 0
        }

        self.start_time = time.time()

    def _normalize_paths(self) -> None:
        """Нормализация путей в конфигурации."""
        # Преобразование json_paths
        if 'json_paths' in self.config:
            normalized_paths = []
            for path in self.config['json_paths']:
                if isinstance(path, str):
                    normalized_paths.append(Path(path))
                elif isinstance(path, Path):
                    normalized_paths.append(path)
            self.config['json_paths'] = normalized_paths

        # Преобразование output_dir
        if 'output_dir' in self.config:
            output_dir = self.config['output_dir']
            if isinstance(output_dir, str):
                self.config['output_dir'] = Path(output_dir)
            elif isinstance(output_dir, Path):
                pass
            else:
                self.config['output_dir'] = Path('.')

    def run(self) -> bool:
        """Основной метод запуска конвертера."""

        self.logger.info(f"\n=== Запуск {self.script_name} - конвертер JSON в RSC ===")

        try:
            self._log_startup_info()
            self._process_json_paths()
            self._log_statistics()
            return True
        except Exception as e:
            self.logger.error(f"Критическая ошибка при выполнении: {str(e)}", exc_info=True)
            return False

    def _log_startup_info(self) -> None:
        """Логирование информации о настройках скрипта."""
        self.logger.info(f"Загружена JSON конфигурация для {self.script_name}")
        self.logger.info("=" * 60)
        self.logger.info("НАСТРОЙКИ СКРИПТА:")
        self.logger.info(f"Имя скрипта: {self.script_name}")

        # Информация о режиме генерации
        generation_type = self.config.get('type_generation', 'additive')
        self.logger.info(f"Режим генерации: {generation_type} ({'дозапись' if generation_type == 'additive' else 'пересоздание'})")

        json_paths = self.config.get('json_paths', [])
        self.logger.info(f"Количество путей JSON: {len(json_paths)}")

        for i, path in enumerate(json_paths, 1):
            path_str = str(path) if isinstance(path, Path) else str(path)
            self.logger.info(f"  {i}. {path_str}")

        output_dir = self.config.get('output_dir', 'Не указана')
        output_dir_str = str(output_dir) if isinstance(output_dir, Path) else output_dir
        self.logger.info(f"Выходная директория: {output_dir_str}")
        self.logger.info(f"Рекурсивный поиск: {'Да' if self.config.get('recursive_search', False) else 'Нет'}")
        self.logger.info("=" * 60)

    def _process_json_paths(self) -> None:
        """Обработка всех указанных JSON путей."""
        output_dir = self.config.get('output_dir', Path('.'))
        if isinstance(output_dir, str):
            output_dir = Path(output_dir)

        # Создание директории при отсутстви
        output_dir.mkdir(parents=True, exist_ok=True)

        # Удаление старых TXT файлов (режим recreation)
        generation_type = self.config.get('type_generation', 'additive')
        if generation_type == 'recreation':
            self.logger.info(f"Режим '{generation_type}': очистка выходной директории {output_dir}")
            deleted_count = 0
            for txt_file in output_dir.glob("*.txt"):
                try:
                    txt_file.unlink()
                    self.logger.debug(f"Удалён TXT-файл: {txt_file}")
                    deleted_count += 1
                except Exception as e:
                    self.logger.warning(f"Не удалось удалить файл {txt_file}: {e}")
            if deleted_count > 0:
                self.logger.info(f"Удалено {deleted_count} старых TXT-файлов")
        else:
            self.logger.info(f"Режим '{generation_type}': сохранение существующих TXT-файлов")

        json_paths = self.config.get('json_paths', [])

        for i, json_path in enumerate(json_paths, 1):
            path_str = str(json_path) if isinstance(json_path, Path) else json_path
            self.logger.info(f"Обработка пути {path_str} ({i}/{len(json_paths)})")

            try:
                if isinstance(json_path, str):
                    path = Path(json_path)
                else:
                    path = json_path

                if not path.exists():
                    self.logger.warning(f"Путь не найден: {path}. Пропускаем...")
                    self.stats['errors'] += 1
                    continue

                if path.is_file():
                    self._process_single_file(path)
                elif path.is_dir():
                    self._process_directory(path)

                self.stats['processed_paths'] += 1
            except Exception as e:
                path_str = str(json_path) if isinstance(json_path, Path) else json_path
                self.logger.error(f"Ошибка при обработке пути {path_str}: {str(e)}", exc_info=True)
                self.stats['errors'] += 1

    def _process_directory(self, directory: Path) -> None:
        """Обработка директории с JSON файлами."""
        recursive = self.config.get('recursive_search', False)

        if recursive:
            json_files = list(directory.rglob("*.json"))
        else:
            json_files = list(directory.glob("*.json"))

        self.logger.info(f"Найдено {len(json_files)} JSON файлов в {directory}")

        for json_file in json_files:
            self._process_single_file(json_file)

    def _process_single_file(self, json_file: Path) -> None:
        """Обработка одного JSON файла."""
        try:
            self.logger.info(f"Обработка файла: {json_file}")

            # Загрузка JSON данных
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Определение формата JSON (results-as.json & *-report.json и извлечение данных)
            if 'as_data' in data:
                self.logger.debug(f"Обнаружен формат (as_data) в файле {json_file}")
                asn_data = self._extract_asn_data_from_as_data(data['as_data'])
            elif 'asn_hierarchy' in data:
                self.logger.debug(f"Обнаружен формат (asn_hierarchy) в файле {json_file}")
                asn_data = self._extract_asn_data(data['asn_hierarchy'])
            else:
                self.logger.warning(f"Файл {json_file} не содержит ни 'as_data', ни 'asn_hierarchy'. Пропускаем.")
                return

            # Сохранение данных в TXT файлы
            self._save_asn_data(asn_data)

            self.stats['processed_files'] += 1

        except json.JSONDecodeError as e:
            self.logger.error(f"Ошибка парсинга JSON в файле {json_file}: {str(e)}")
            self.stats['errors'] += 1
        except Exception as e:
            self.logger.error(f"Ошибка при обработке файла {json_file}: {str(e)}", exc_info=True)
            self.stats['errors'] += 1

    def _extract_asn_data(self, asn_hierarchy: List[Dict]) -> Dict[str, Dict[str, Set[str]]]:
        """
        Извлечение данных по ASN из иерархии. ip_analyst-*.py -> *-report.json
        """
        asn_data = {}

        for asn_item in asn_hierarchy:
            asn = asn_item.get('asn', 'UNKNOWN')
            org = asn_item.get('org', 'UNKNOWN')

            # Создание ключа для группировки
            asn_org_key = f"{asn}-{org}"

            if asn_org_key not in asn_data:
                asn_data[asn_org_key] = {
                    'asn': asn,
                    'org': org,
                    'data': set()
                }

            # Обработка префиксов
            for prefix in asn_item.get('prefixes', []):
                if prefix.get('aggregated', False):
                    # Отбор префикса
                    network = prefix.get('network', '')
                    if network:
                        asn_data[asn_org_key]['data'].add(network)
                else:
                    # Отбор отдельных IP
                    ips = prefix.get('ips', [])
                    for ip in ips:
                        if ip:
                            asn_data[asn_org_key]['data'].add(ip)

        return asn_data

    def _extract_asn_data_from_as_data(self, as_data: Dict[str, Dict]) -> Dict[str, Dict[str, Set[str]]]:
        """
        Извлечение IPv4-префиксов из формата 'as_data' # fetch_as_prefixes.py -> results-as.json
        """
        asn_data = {}
        for asn_key, content in as_data.items():
            if not asn_key.startswith("AS"):
                self.logger.debug(f"Пропускаем некорректный ключ ASN: {asn_key}")
                continue

            try:
                asn_number = asn_key[2:]
                if not asn_number.isdigit():
                    self.logger.warning(f"Некорректный номер ASN в ключе: {asn_key}")
                    continue
            except Exception:
                self.logger.warning(f"Не удалось распознать ASN из ключа: {asn_key}")
                continue

            org = asn_key
            prefixes_v4 = content.get('prefixes_v4', [])
            if not isinstance(prefixes_v4, list):
                self.logger.warning(f"prefixes_v4 не является списком для {asn_key}")
                continue

            valid_prefixes = {p.strip() for p in prefixes_v4 if isinstance(p, str) and p.strip()}
            if not valid_prefixes:
                continue

            asn_org_key = f"{asn_number}-{org}"
            asn_data[asn_org_key] = {
                'asn': asn_number,
                'org': org,
                'data': valid_prefixes
            }

        return asn_data

    def _save_asn_data(self, asn_data: Dict[str, Dict[str, Set[str]]]) -> None:
        """Сохранение данных по ASN в отдельные TXT файлы."""
        output_dir = self.config.get('output_dir', Path('.'))

        if isinstance(output_dir, str):
            output_dir = Path(output_dir)

        output_dir.mkdir(parents=True, exist_ok=True)

        generation_type = self.config.get('type_generation', 'additive')
        self.logger.info(f"Сохранение результатов в директорию: {output_dir} (режим: {generation_type})")

        for asn_org_key, data in asn_data.items():
            if not data['data']:
                continue

            # Формирование имени файла
            filename = self._generate_filename(data['asn'], data['org'])
            filepath = output_dir / filename

            # Получаем существующие данные только в режиме additive
            existing_data = set()
            if generation_type == 'additive' and filepath.exists():
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        existing_data = set(line.strip() for line in f if line.strip())
                    self.logger.debug(f"Загружено {len(existing_data)} существующих записей из {filename}")
                except Exception as e:
                    self.logger.warning(f"Не удалось прочитать существующий файл {filepath}: {str(e)}")

            all_data = existing_data.union(data['data'])

            # Сохранение данных
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    for item in sorted(all_data):
                        f.write(f"{item}\n")

                # Логирование статистики
                new_items = len(data['data'])
                total_items = len(all_data)

                if existing_data and generation_type == 'additive':
                    self.logger.info(f"Файл обновлен: новых {new_items} из {len(existing_data)} существующих IP/префиксов ({total_items} всего) в файле: {filepath}")
                elif filepath.exists() and generation_type == 'recreation':
                    self.logger.info(f"Файл пересоздан: {total_items} IP/префиксов в файле: {filepath}")
                else:
                    self.logger.info(f"Создан файл с {total_items} IP/префиксами: {filepath}")

                if not filepath.exists() or generation_type == 'recreation':
                    self.stats['created_files'] += 1

                self.stats['total_ips'] += new_items

            except Exception as e:
                self.logger.error(f"Ошибка при сохранении файла {filepath}: {str(e)}")
                self.stats['errors'] += 1

    def _generate_filename(self, asn: str, org: str) -> str:
        """
        Генерация имени файла по шаблону: asn-org.txt

        Args:
            asn: Номер ASN
            org: Название организации

        Returns:
            Имя файла в формате TXT
        """
        # Очистка ASN от недопустимых символов
        asn_clean = re.sub(r'[<>:"/\\|?*]', '', asn)

        # Очистка и обрезка названия организации
        org_clean = re.sub(r'[<>:"/\\|?*]', '', org)
        org_clean = org_clean.replace(' ', '_')

        # Обрезка слишком длинных названий
        max_org_length = 50
        if len(org_clean) > max_org_length:
            org_clean = org_clean[:max_org_length]

        return f"{asn_clean}-{org_clean}.txt"

    def _log_statistics(self) -> None:
        """Логирование статистики выполнения."""
        execution_time = time.time() - self.start_time

        self.logger.info("=" * 60)
        self.logger.info("СТАТИСТИКА ОБРАБОТКИ:")
        self.logger.info(f"Обработано путей (исходных данных): {self.stats['processed_paths']}")
        self.logger.info(f"Обработано исходных файлов: {self.stats['processed_files']}")
        self.logger.info(f"Извлечено IP/префиксов: {self.stats['total_ips']}")
        self.logger.info(f"Создано/обновлено TXT файлов: {self.stats['created_files']}")
        self.logger.info(f"Ошибок: {self.stats['errors']}")
        self.logger.info(f"Время выполнения: {execution_time:.2f} секунд")
        self.logger.info("=" * 60)

        if self.stats['errors'] == 0 and self.stats['processed_files'] > 0:
            self.logger.info("Обработка завершена успешно!")
        elif self.stats['processed_files'] == 0:
            self.logger.warning("Не найдено JSON файлов для обработки.")
        else:
            self.logger.warning("Обработка завершена с ошибками.")
