"""
Скрипт для автоматической генерации TXT-файлов с доменными именами и
DNS-серверами в формате, совместимом с сервисом dnscrypt-proxy.
"""
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
import sys

# ========== НАСТРОЙКА КОНФИГУРАЦИИ ==========
DEFAULT_CONFIG = {
    # Путь к JSON отчету (автоматически на основе output_file)
    "json_report": True,  # Включить генерацию JSON отчета

    # Общие DNS серверы по умолчанию (будут использоваться если не указаны другие в "dns_overrides")
    "default_dns_servers": ["77.88.8.8","9.9.9.9"],

    # Переопределение DNS серверов для категорий/доменов
    # Ключ: категория или домен (например: "ru", "cc", "example.com")
    # Значение: список DNS серверов
    "dns_overrides": {
        # Примеры:
        # "ru": ["192.168.0.1", "192.168.0.100"],
        # "example.com": ["192.168.0.50"],
    },

    # Основная категория для фильтрации (например: "ru", "cc", "org")
    # Если None или пустая строка - обрабатываются все категории
    "specific_category": [
                      "ru", "xn--p1ai",             # TLD RUS
                      "Github", "Yandex", "Amazon",  # ExampleService
                     ], # None - все категории из YAML

    # Дополнительный домен для фильтрации (например: "example.com")
    "specific_domain": ["example.com", "microsoft.com"], # None - все домены

    # Пути к входным YAML файлам (filter-results-dns-catsort) (абсолютные или относительные)
    "input_files": [
        "raw-data/TLD-List/DNS/filter-results-dns-catsort.yaml",              # TLD список
        "raw-data/Service-List/DNS/filter-results-dns-catsort.yaml",          # Service список
    ],

    # Путь к выходному TXT файлу Forwarding
    "output_file": "/path/to/dnscrypt-proxy/forwarding-rules.txt",

    # Режим записи в выходной файл
    # "w" - перезаписать файл
    # "a" - добавить в конец файла
    "output_mode": "a",
}

# ========== НАСТРОЙКА ЛОГИРОВАНИЯ ==========
script_name = Path(__file__).stem
log_filename = f"{script_name}.log"

# Создание директории в logs (автоматическое имя из названия скрипта)
log_path = Path(f'logs/additional/gen_filter_forwarding/{log_filename}')
log_path.parent.mkdir(parents=True, exist_ok=True)

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class DomainProcessor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.domains_data: Dict[str, str] = {}
        self.domains_report: List[Dict[str, Any]] = []
        self.processed_files = 0
        self.total_domains = 0
        self._setup_category_filter()
        self._setup_domain_filter()
        self.existing_domains: Set[str] = set()

        if config["output_mode"] == "a":
            self._load_existing_domains()

    def _setup_category_filter(self):
        """Настройка фильтра категорий"""
        specific_category = self.config["specific_category"]

        if specific_category is None:
            self.category_filter = None
        elif isinstance(specific_category, str):
            if specific_category.strip() == "":
                self.category_filter = None
            else:
                self.category_filter = [specific_category]
        elif isinstance(specific_category, list):
            # Фильтрует пустые значения и строки
            valid_categories = [cat for cat in specific_category if cat and isinstance(cat, str)]
            self.category_filter = valid_categories if valid_categories else None
        else:
            logger.warning(f"Неверный формат specific_category: {type(specific_category)}. Использую None.")
            self.category_filter = None

        if self.category_filter:
            logger.debug(f"Установлен фильтр категорий: {self.category_filter}")

    def _setup_domain_filter(self):
        """Настройка фильтра доменов"""
        specific_domain = self.config["specific_domain"]

        if specific_domain is None:
            self.domain_filter = None
        elif isinstance(specific_domain, str):
            if specific_domain.strip() == "":
                self.domain_filter = None
            else:
                self.domain_filter = {specific_domain.lower()}
        elif isinstance(specific_domain, list):
            # Фильтрует пустые значения и строки, приводим к нижнему регистру
            valid_domains = {str(dom).lower().strip()
                           for dom in specific_domain
                           if dom and isinstance(dom, str) and str(dom).strip()}
            self.domain_filter = valid_domains if valid_domains else None
        else:
            logger.warning(f"Неверный формат specific_domain: {type(specific_domain)}. Использую None.")
            self.domain_filter = None

        if self.domain_filter:
            logger.info(f"Установлен фильтр доменов: {list(self.domain_filter)}")

    def _get_dns_servers_for_domain(self, category: str, domain: str) -> List[str]:
        """Получение DNS серверов для домена с учетом dns_overrides."""
        # Проверяет переопределение для конкретного домена
        if domain in self.config["dns_overrides"]:
            servers = self.config["dns_overrides"][domain]
            logger.debug(f"Используются переопределенные DNS для домена {domain}: {servers}")
            return servers

        # Проверяет переопределение для категории
        if category in self.config["dns_overrides"]:
            servers = self.config["dns_overrides"][category]
            logger.debug(f"Используются переопределенные DNS для категории {category}: {servers}")
            return servers

        # Использует DNS серверы по умолчанию
        return self.config["default_dns_servers"]

    def _should_process_category(self, category: str) -> bool:
        """Определяет необходимость обработки категории."""
        if self.category_filter is None:  # Если категория не указана, обрабатывает все
            return True

        return category in self.category_filter

    def _should_process_domain(self, domain: str, category: str) -> bool:
        """Определяет необходимость обработки домена."""
        # Если домен в specific_domain - всегда обрабатываем
        if self.domain_filter and domain.lower() in self.domain_filter:
            logger.debug(f"Домен '{domain}' включен через specific_domain (категория: '{category}')")
            return True

        if self.category_filter is not None:
            return category in self.category_filter

        return True

    def _should_process_domain(self, domain: str, category: str) -> bool:
        """Определяет необходимость обработки домена."""
        if self.domain_filter and domain.lower() in self.domain_filter:
            logger.debug(f"Домен '{domain}' включен через specific_domain (категория: '{category}')")
            return True

        if self.category_filter is not None:
            return category in self.category_filter

        return True

    def process_yaml_file(self, filepath: Path) -> Dict[str, Any]:
        """Обработка YAML файла."""
        try:
            if not filepath.exists():
                logger.error(f"Файл не найден: {filepath}")
                return {"success": False}

            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data or 'categories' not in data:
                logger.warning(f"Файл {filepath} не содержит секции categories")
                return {"success": False}

            categories = data.get('categories', {})

            categories_processed = 0
            domains_in_file = 0
            domains_matched_specific = 0

            for category, category_data in categories.items():
                domains = category_data.get('domains', {})
                if not domains:
                    logger.debug(f"Категория '{category}' не содержит domains")
                    continue

                logger.debug(f"Проверка категории: '{category}', доменов: {len(domains)}")

                for second_level_domain, subdomains in domains.items():
                    if not self._should_process_domain(second_level_domain, category):
                        continue

                    categories_processed += 1
                    domains_in_file += 1

                    if self.domain_filter and second_level_domain.lower() in self.domain_filter:
                        domains_matched_specific += 1

                    # Получает DNS серверы для домена
                    dns_servers = self._get_dns_servers_for_domain(category, second_level_domain)

                    if self.domain_filter and second_level_domain.lower() in self.domain_filter:
                        matched_by = "specific_domain"
                        matched_value = second_level_domain
                    elif self.category_filter and category in self.category_filter:
                        matched_by = "category"
                        matched_value = category
                    else:
                        matched_by = "all"
                        matched_value = "all"

                    # Создаем строку DNS серверов
                    dns_str = ",".join(sorted(dns_servers))

                    self.domains_data[second_level_domain] = dns_str

                    # Сбор информации для отчета (report.json)
                    domain_info = {
                        "domain": second_level_domain,
                        "category": category,
                        "source_file": str(filepath),
                        "dns_servers": dns_servers,
                        "matched_by": matched_by,
                        "matched_value": matched_value
                    }
                    self.domains_report.append(domain_info)

                    logger.debug(f"Добавлен домен: {second_level_domain} -> {dns_str}")
                    self.total_domains += 1

            self.total_domains = len(self.domains_data)

            return {
                "success": True,
                "categories_processed": categories_processed,
                "domains_in_file": domains_in_file,
                "domains_matched_specific": domains_matched_specific
            }

        except yaml.YAMLError as e:
            logger.error(f"Ошибка парсинга YAML файла {filepath}: {e}")
            return {"success": False}
        except Exception as e:
            logger.error(f"Ошибка обработки файла {filepath}: {e}")
            return {"success": False}

    def generate_json_report(self) -> bool:
        """Генерация JSON отчета."""
        if not self.config.get("json_report", True):
            logger.info("Генерация JSON отчета отключена в конфигурации")
            return True

        try:
            import json
            from datetime import datetime

            output_path = Path(self.config["output_file"])
            if not output_path.is_absolute():
                output_path = Path.cwd() / output_path

            report_path = output_path.with_name(output_path.name + ".report.json")

            # Подготавливает данные для отчета
            report_data = {
                "report": {
                    "meta": {
                        "generated_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "output_file": str(output_path),
                        "output_mode": self.config["output_mode"]
                    },
                    "filters": {
                        "specific_category": self.config["specific_category"],
                        "specific_domain": self.config["specific_domain"],
                        "default_dns_servers": self.config["default_dns_servers"]
                    },
                    "sources": {
                        "input_files": self.config["input_files"],
                        "processed_successfully": self.processed_files_list,
                        "failed_to_process": self.failed_files_list
                    },
                    "domains": self.domains_report
                }
            }

            # Добавляет информацию о переопределениях DNS
            used_overrides = []
            for domain_info in self.domains_report:
                category = domain_info["category"]
                domain = domain_info["domain"]

                if domain in self.config.get("dns_overrides", {}):
                    used_overrides.append(domain)
                elif category in self.config.get("dns_overrides", {}):
                    used_overrides.append(category)

            report_data["report"]["filters"]["dns_overrides_used"] = list(set(used_overrides))

            # Сохраняет JSON отчет
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2)

            logger.info(f"JSON отчет сохранен: {report_path}")
            logger.info(f"В отчете {len(self.domains_report)} доменов")
            return True

        except Exception as e:
            logger.error(f"Ошибка генерации JSON отчета: {e}")
            return False

    def process_all_files(self) -> bool:
        """Обработать все указанные YAML файлы."""
        self.processed_files_list = []
        self.failed_files_list = []

        logger.info("=" * 50)
        logger.info("Начало обработки YAML файлов")
        logger.info(f"Основная категория: {self.config['specific_category']}")
        logger.info(f"Конкретный домен: {self.config['specific_domain']}")
        logger.info(f"Количество файлов для обработки: {len(self.config['input_files'])}")
        logger.info("=" * 50)

        success_count = 0
        processed_files_info = []

        for file_path_str in self.config["input_files"]:
            filepath = Path(file_path_str)

            # Преобразование относительного пути в абсолютный
            if not filepath.is_absolute():
                filepath = Path.cwd() / filepath

            result = self.process_yaml_file(filepath)

            if result["success"]:
                success_count += 1

                self.processed_files += 1
                self.processed_files_list.append(file_path_str)

                logger.info(f"Файл {filepath} успешно обработан. "
                           f"Категорий: {result['categories_processed']}, "
                           f"доменов: {result['domains_in_file']}")

                processed_files_info.append({
                    "file": file_path_str,
                    "categories": result["categories_processed"],
                    "domains": result["domains_in_file"]
                })

                if self.domain_filter and result.get("domains_matched_specific", 0) > 0:
                    logger.info(f"Найдено совпадений с specific_domain: {result['domains_matched_specific']}")

            else:
                self.failed_files_list.append(file_path_str)

        logger.info("=" * 50)
        logger.info(f"Обработка завершена. Успешно обработано файлов: {success_count}/{len(self.config['input_files'])}")
        logger.info(f"Найдено уникальных доменов 2-го уровня: {len(self.domains_data)}")
        logger.info("=" * 50)

        return success_count > 0

    def _load_existing_domains(self):
        """Загрузить существующие домены из выходного файла (если существует)."""
        output_path = Path(self.config["output_file"])

        # Преобразование относительного пути в абсолютный
        if not output_path.is_absolute():
            output_path = Path.cwd() / output_path

        if not output_path.exists():
            logger.info(f"Выходной файл не существует: {output_path}. Будет создан новый.")
            return

        try:
            logger.info(f"Чтение существующих доменов из файла: {output_path}")
            with open(output_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        # Извлекает домен
                        parts = line.split(' ', 1)
                        if parts:
                            domain = parts[0]
                            self.existing_domains.add(domain)

            logger.info(f"Загружено {len(self.existing_domains)} существующих доменов из файла")

        except Exception as e:
            logger.error(f"Ошибка чтения существующего файла: {e}")

    def save_to_txt(self) -> bool:
        """Сохранение результатов в TXT файл."""
        try:
            output_path = Path(self.config["output_file"])

            # Преобразование относительного пути в абсолютный
            if not output_path.is_absolute():
                output_path = Path.cwd() / output_path

            # Создает директорию
            output_path.parent.mkdir(parents=True, exist_ok=True)

            mode = self.config["output_mode"]

            logger.info(f"Сохранение результатов в файл: {output_path}")
            logger.info(f"Режим записи: {'добавление' if mode == 'a' else 'перезапись'}")

            # Фильтрует домены для добавления
            domains_to_save = self.domains_data.copy()

            if mode == "a" and self.existing_domains:
                # Удаляет существующие домены
                existing_count = len(domains_to_save)
                for domain in list(domains_to_save.keys()):
                    if domain in self.existing_domains:
                        del domains_to_save[domain]

                new_domains_count = len(domains_to_save)
                skipped_count = existing_count - new_domains_count
                logger.info(f"Пропущено {skipped_count} уже существующих доменов")

            if not domains_to_save:
                logger.warning("Нет новых доменов для добавления")
                return True

            with open(output_path, mode, encoding='utf-8') as f:
                # Сортирует домены для удобства чтения
                for domain in sorted(domains_to_save.keys()):
                    dns_str = domains_to_save[domain]
                    line = f"{domain} {dns_str}\n"
                    f.write(line)

            logger.info(f"Добавлено {len(domains_to_save)} новых доменов в файл: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Ошибка сохранения в файл: {e}")
            return False

    def print_statistics(self):
        """Вывести статистику обработки."""
        logger.info("=" * 50)
        logger.info("СТАТИСТИКА ОБРАБОТКИ")
        logger.info(f"Обработано файлов: {self.processed_files}")
        logger.info(f"Найдено доменов 2-го уровня: {self.total_domains}")
        logger.info(f"Уникальных доменов: {len(self.domains_data)}")

        if self.config["output_mode"] == "a":
            logger.info(f"Уже существовало доменов в файле: {len(self.existing_domains)}")

        if self.domains_data:
            logger.debug("Первые 10 доменов:")
            for i, domain in enumerate(sorted(self.domains_data.keys())[:10]):
                logger.debug(f"  {i+1}. {domain} -> {self.domains_data[domain]}")
        logger.info("=" * 50)

def main():
    """Основная функция."""
    logger.info("\n")
    logger.info("=" * 57)
    logging.info("Запуск %s - генератор Forwarding файла", script_name)
    logger.info("=" * 57)

    try:
        processor = DomainProcessor(DEFAULT_CONFIG)

        # Обработка файлов
        if not processor.process_all_files():
            logger.error("Не удалось обработать ни одного файла")
            return 1

        # Сохранение результатов TXT
        if not processor.save_to_txt():
            logger.error("Не удалось сохранить результаты")
            return 1

        # Генерация JSON
        if not processor.generate_json_report():
            logger.warning("Не удалось сгенерировать JSON отчет")

        # Вывод статистики
        processor.print_statistics()

        logger.info("Скрипт успешно завершен!")
        return 0

    except KeyboardInterrupt:
        logger.info("Скрипт прерван пользователем.")
        return 130
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
