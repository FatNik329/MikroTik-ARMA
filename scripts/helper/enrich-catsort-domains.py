#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт фильтрации и гео насыщения YAML-файлов с доменами Catsort (filter-results-dns-catsort.yaml).
Параметры задаются в блоке CONFIG.
"""

import sys
import logging
from datetime import datetime, timedelta, date
from pathlib import Path
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

import yaml
import json
import maxminddb
import dns.resolver
import dns.exception


# =============================================================================
# CONFIG — параметры скрипта
# =============================================================================

# Начальная дата отбора (включительно). Формат: 'YYYY-MM-DD' или 'none'.
start_date: str = 'none'

# Конечная дата отбора (включительно). Формат: 'YYYY-MM-DD' или 'none'.
end_date: str = 'none'

# Интервальная дата: отобрать записи за последние N дней от текущей даты.
# Число (1, 2, 10, ...) или 'none'. Приоритетнее start_date/end_date.
interval_date: Any = 1

# Категории для включения. Список строк или 'none'.
category_inclusion: Any = 'none'

# Категории для исключения. Список строк или 'none'.
category_exclusion: Any = 'none'

# Домены для включения в результат (даже если категория исключена в category_exclusion).
# Список строк или 'none'.
domain_inclusion: Any = 'none'

# Домены для исключения из результата (даже если категория включена в category_inclusion).
# Список строк или 'none'.
domain_exclusion: Any = 'none'

# Страны (country_code) для включения в результат. Список строк или 'none'.
# Применяется ПОСЛЕ GEO-обогащения (требует geo_checking=True).
country_inclusion: Any = 'none'

# Страны (country_code) для исключения из результата. Список строк или 'none'.
# Применяется ПОСЛЕ GEO-обогащения (требует geo_checking=True).
country_exclusion: Any = 'none'

# Путь(и) до YAML-файлов с доменами. Список строк (или одна строка).
path_to_yaml_catsort_domains: Any = [
    # '/path/to/domains1/filter-results-dns-catsort.yaml',
    # '/path/to/domains2/filter-results-dns-catsort.yaml',
]

# Сохранять ли результат в файл (True/False).
save_to_file: bool = False

# --- GEO-проверка ---
geo_checking: bool = False                                           #Включить/отключить геонасыщение доменов (True/False). Необходимо указать путь (path_to_mmdb) до MMDB файла (скачивается скриптом get_asn_mmdb.py)
path_to_mmdb: Any = '/path/to/mmmdb/ip-to-asn.mmdb'                 # обязателен при geo_checking=True
path_to_schema_mmdb: Any = '/path/to/mmmdb/ip-to-asn.schema.json'   # опционален (генерируется скриптом get_asn_mmdb.py)

# Порог "шумности" домена: если количество субдоменов у домена
# БОЛЬШЕ указанного значения — домен и все его субдомены
# удаляются из конечного результата.
# 0 — фильтрация отключена (по умолчанию).
# Применяется ПОСЛЕ GEO-обогащения и фильтрации по стране.
domain_noise_threshold: int = 0

# DNS-сервер для резолва A-записей. Формат: 'IP' или 'IP:port'.
# Примеры: '127.0.0.1', '127.0.0.1:7373', '1.1.1.1:53'.
dns_server: str = '127.0.0.1'

# =============================================================================
# Константы
# =============================================================================
# Кол-во потоков для параллельного DNS-резолва.
# По умолчанию: 16–64
GEO_MAX_WORKERS = 32

# Дефолтное соответствие standard_name -> source_field, если схема не задана.
DEFAULT_FIELD_MAPPING: dict[str, str | list[str]] = {
    'country_code':   'country_code',
    'country':        'country',
    'continent':      'continent',
    'continent_code': 'continent_code',
    'org':            'as_name',
    'asn':            'asn',
    'as_domain':      'as_domain',
}

# =============================================================================
# Логирование
# =============================================================================

LOG_FORMAT = '%(asctime)s | %(levelname)-7s | %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

logger = logging.getLogger('filter_domains')


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


# =============================================================================
# Парсинг и валидация базовых параметров
# =============================================================================

def _parse_date(value: str, param_name: str) -> date | None:
    if value == 'none':
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        logger.error(f"Параметр '{param_name}': неверный формат даты '{value}'. "
                     f"Ожидается 'YYYY-MM-DD' или 'none'.")
        sys.exit(1)


def _normalize_list(value: Any, param_name: str) -> list[str] | None:
    if value == 'none':
        return None
    if isinstance(value, str):
        logger.warning(f"Параметр '{param_name}': передана строка вместо списка. "
                       f"Оборачиваю в список: [{value!r}].")
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    logger.error(f"Параметр '{param_name}': ожидается список строк или 'none', "
                 f"получено {type(value).__name__}.")
    sys.exit(1)

def _resolve_inc_exc(
    inc_raw: Any,
    exc_raw: Any,
    name_inc: str,
    name_exc: str,
    label: str,
    normalize: Any = None,
) -> tuple[set[str] | None, set[str] | None]:
    """
    Общая логика resolution inclusion/exclusion:
    нормализация, warning при пересечении, приоритет exclusion.

    normalize — опциональная функция приведения элемента (например, str.upper).
    """
    inc = _normalize_list(inc_raw, name_inc)
    exc = _normalize_list(exc_raw, name_exc)

    if normalize is not None:
        inc = [normalize(x) for x in inc] if inc else None
        exc = [normalize(x) for x in exc] if exc else None

    if inc and exc:
        overlap = set(inc) & set(exc)
        if overlap:
            logger.warning(f"{label} одновременно в {name_inc} и {name_exc}: "
                           f"{sorted(overlap)}. Приоритет у exclusion — они будут исключены.")
            inc = [x for x in inc if x not in overlap]

    return (set(inc) if inc else None), (set(exc) if exc else None)

def resolve_date_range() -> tuple[date | None, date | None]:
    today = datetime.now().date()

    if interval_date != 'none':
        if not isinstance(interval_date, int) or interval_date <= 0:
            logger.error(f"Параметр 'interval_date': ожидается положительное целое, "
                         f"получено {interval_date!r}.")
            sys.exit(1)
        if start_date != 'none' or end_date != 'none':
            logger.warning("Параметр 'interval_date' переопределяет "
                           "'start_date' и 'end_date'.")
        from_date = today - timedelta(days=interval_date)
        return from_date, today

    from_date = _parse_date(start_date, 'start_date')
    to_date = _parse_date(end_date, 'end_date')

    if from_date and to_date and from_date > to_date:
        logger.error(f"'start_date' ({from_date}) больше 'end_date' ({to_date}).")
        sys.exit(1)

    return from_date, to_date

def resolve_categories() -> tuple[set[str] | None, set[str] | None]:
    return _resolve_inc_exc(
        category_inclusion, category_exclusion,
        'category_inclusion', 'category_exclusion',
        label='Категории',
    )


def resolve_domains() -> tuple[set[str] | None, set[str] | None]:
    return _resolve_inc_exc(
        domain_inclusion, domain_exclusion,
        'domain_inclusion', 'domain_exclusion',
        label='Домены',
    )


def resolve_countries() -> tuple[set[str] | None, set[str] | None]:
    return _resolve_inc_exc(
        country_inclusion, country_exclusion,
        'country_inclusion', 'country_exclusion',
        label='Страны',
        normalize=str.upper,
    )

def resolve_paths() -> list[Path]:
    raw = path_to_yaml_catsort_domains
    if isinstance(raw, str):
        raw = [raw]
    if not raw:
        logger.error("Параметр 'path_to_yaml_catsort_domains' пуст. Укажите хотя бы один путь.")
        sys.exit(1)
    paths = [Path(p).expanduser().resolve() for p in raw]
    for p in paths:
        if not p.is_file():
            logger.error(f"Файл не найден: {p}")
            sys.exit(1)
    return paths


# =============================================================================
# GEO — валидация и загрузка
# =============================================================================

def resolve_geo_config() -> tuple[Path | None, dict[str, str | list[str]] | None]:
    """
    Возвращает (mmdb_path, field_mapping) при geo_checking=True,
    иначе (None, None).

    field_mapping: standard_name -> source_field (str или list[str]).
    """
    if not geo_checking:
        return None, None

    # --- MMDB ---
    if path_to_mmdb == 'none':
        logger.error("Параметр 'path_to_mmdb' обязателен при geo_checking=True.")
        sys.exit(1)
    mmdb_path = Path(str(path_to_mmdb)).expanduser().resolve()
    if not mmdb_path.is_file():
        logger.error(f"Файл MMDB не найден: {mmdb_path}")
        sys.exit(1)

    # --- Схема (опционально) ---
    if path_to_schema_mmdb == 'none':
        logger.info("Схема MMDB не задана — используем дефолтное соответствие полей.")
        field_mapping = dict(DEFAULT_FIELD_MAPPING)
    else:
        schema_path = Path(str(path_to_schema_mmdb)).expanduser().resolve()
        if not schema_path.is_file():
            logger.error(f"Файл схемы MMDB не найден: {schema_path}")
            sys.exit(1)
        try:
            with schema_path.open('r', encoding='utf-8') as f:
                schema = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Ошибка чтения схемы MMDB {schema_path}: {e}")
            sys.exit(1)

        fm_raw = schema.get('field_mapping')
        if not isinstance(fm_raw, dict):
            logger.error(f"Схема MMDB {schema_path}: отсутствует или невалиден блок 'field_mapping'.")
            sys.exit(1)

        field_mapping = {}
        for std_name, spec in fm_raw.items():
            if not isinstance(spec, dict):
                logger.warning(f"Схема MMDB: поле '{std_name}' имеет невалидный spec — пропущено.")
                continue
            src = spec.get('source_field')
            if not isinstance(src, (str, list)):
                logger.warning(f"Схема MMDB: поле '{std_name}' без валидного 'source_field' — пропущено.")
                continue
            field_mapping[std_name] = src

        if not field_mapping:
            logger.error("Схема MMDB: после валидации field_mapping пуст.")
            sys.exit(1)

    logger.info(f"GEO: MMDB = {mmdb_path}")
    logger.info(f"GEO: поля для извлечения: {sorted(field_mapping.keys())}")
    return mmdb_path, field_mapping


# =============================================================================
# GEO — резолв и lookup
# =============================================================================
def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_server]
    return resolver

def _parse_dns_server(value: str) -> tuple[str, int | None]:
    """
    Парсит 'IP' или 'IP:port'. Возвращает (host, port|None).
    port=None означает «порт по умолчанию» (53).
    """
    value = str(value).strip()
    if not value:
        logger.error("dns_server: пустое значение.")
        sys.exit(1)

    if ':' in value:
        host, _, port_s = value.rpartition(':')
        host = host.strip()
        try:
            port = int(port_s)
        except ValueError:
            logger.error(f"dns_server: неверный порт в '{value}'.")
            sys.exit(1)
        if not (0 < port < 65536):
            logger.error(f"dns_server: порт вне диапазона 0..65535: {port}.")
            sys.exit(1)
        if not host:
            logger.error(f"dns_server: пустой host в '{value}'.")
            sys.exit(1)
        return host, port

    return value, None

def resolve_ipv4(domain: str, resolver: dns.resolver.Resolver) -> str | None:
    """Возвращает первый IPv4-адрес домена или None."""
    try:
        answers = resolver.resolve(domain, 'A')
        ips = sorted(str(rdata) for rdata in answers)
        return ips[0] if ips else None
    except (dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
            dns.exception.DNSException,
            OSError) as e:
        logger.debug(f"DNS: {domain} не отрезолвлен ({type(e).__name__}: {e})")
    return None

def _extract_field(record: dict, path: str | list[str]) -> Any:
    """Извлекает значение по пути (строка или список ключей)."""
    keys = [path] if isinstance(path, str) else path
    cur: Any = record
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def geo_lookup(
    ip: str,
    reader: maxminddb.Reader,
    field_mapping: dict[str, str | list[str]],
) -> dict[str, Any]:
    """Возвращает dict standard_name -> value. Отсутствующие поля не включаются."""
    try:
        record = reader.get(ip)
    except Exception as e:
        logger.warning(f"MMDB: ошибка lookup для {ip}: {e}")
        return {}

    if not record:
        return {}

    result: dict[str, Any] = {}
    for std_name, src in field_mapping.items():
        value = _extract_field(record, src)
        if value is not None:
            result[std_name] = value
        else:
            logger.debug(f"MMDB: поле '{std_name}' (source={src!r}) отсутствует для {ip}.")
    return result


def enrich_with_geo(
    filtered_data: dict,
    mmdb_path: Path,
    field_mapping: dict[str, str | list[str]],
) -> dict:
    """
    Обходит filtered_data, для каждого домена/субдомена делает резолв + lookup
    и добавляет _other_info.
    Формат субдомена меняется на словарь {_date_added, _other_info}.

    Резолв уникальных host'ов выполняется параллельно (ThreadPoolExecutor),
    результат раскладывается обратно в структуру.
    """
    stats = {
        'geo_domains_checked': 0,   # всего записей (домены + субдомены)
        'geo_resolved': 0,
        'geo_unresolved': 0,
        'geo_ip_not_found': 0,
        'geo_unique_hosts': 0,      # количество уникальных host'ов резолва
    }

    categories = filtered_data.get('categories') or {}

    # --- Проход 1: собрать уникальные host'ы ---
    unique_hosts: set[str] = set()
    for cat_data in categories.values():
        domains = (cat_data or {}).get('domains') or {}
        for dom_name, dom_value in domains.items():
            if not isinstance(dom_value, dict):
                continue
            unique_hosts.add(dom_name)
            for key in dom_value.keys():
                if key in ('_date_added', '_other_info'):
                    continue
                unique_hosts.add(key)

    stats['geo_unique_hosts'] = len(unique_hosts)
    logger.info(f"GEO: уникальных host'ов для резолва: {len(unique_hosts)}")

    # --- Проход 2: параллельный резолв уникальных host'ов ---
    geo_cache: dict[str, dict[str, Any] | None] = {}
    resolver_local = threading.local()

    def _get_resolver() -> dns.resolver.Resolver:
        r = getattr(resolver_local, 'resolver', None)
        if r is None:
            r = _make_resolver()
            resolver_local.resolver = r
        return r

    def _worker(host: str) -> tuple[str, dict[str, Any] | None]:
        return host, _resolve_and_lookup(
            host, _get_resolver(), reader, field_mapping, stats,
        )

    reader = maxminddb.open_database(str(mmdb_path))
    try:
        if unique_hosts:
            with ThreadPoolExecutor(max_workers=GEO_MAX_WORKERS) as pool:
                futures = [pool.submit(_worker, h) for h in unique_hosts]
                for fut in as_completed(futures):
                    host, info = fut.result()
                    geo_cache[host] = info
    finally:
        reader.close()

    # --- Проход 3: раскладка результатов по структуре (без I/O) ---
    for cat_data in categories.values():
        domains = (cat_data or {}).get('domains') or {}
        for dom_name, dom_value in domains.items():
            if not isinstance(dom_value, dict):
                continue

            new_dom: dict[str, Any] = {}

            # 1. _date_added (если был)
            if '_date_added' in dom_value:
                new_dom['_date_added'] = dom_value['_date_added']

            # 2. _other_info для самого домена
            stats['geo_domains_checked'] += 1
            dom_geo = geo_cache.get(dom_name)
            if dom_geo is not None:
                new_dom['_other_info'] = dom_geo

            # 3. субдомены
            for key, sub_date in dom_value.items():
                if key in ('_date_added', '_other_info'):
                    continue
                stats['geo_domains_checked'] += 1
                sub_geo = geo_cache.get(key)
                new_sub: dict[str, Any] = {'_date_added': sub_date}
                if sub_geo is not None:
                    new_sub['_other_info'] = sub_geo
                new_dom[key] = new_sub

            domains[dom_name] = new_dom

    return stats

def _resolve_and_lookup(
    host: str,
    resolver: dns.resolver.Resolver,
    reader: maxminddb.Reader,
    field_mapping: dict[str, str | list[str]],
    stats: dict,
) -> dict[str, Any] | None:
    """Резолвит host, делает lookup. Возвращает dict или None (не резолвится / нет в MMDB)."""
    ip = resolve_ipv4(host, resolver)
    if ip is None:
        stats['geo_unresolved'] += 1
        return None
    stats['geo_resolved'] += 1

    info = geo_lookup(ip, reader, field_mapping)
    if not info:
        stats['geo_ip_not_found'] += 1
        return None

    # IP, по которому выполнено GEO-определение.
    return {'resolv_ip': ip, **info}

# =============================================================================
# Фильтрация по стране (пост-фильтр, после GEO)
# =============================================================================

def _country_passes(
    country_code: Any,
    inc_countries: set[str] | None,
    exc_countries: set[str] | None,
) -> bool:
    """
    Проверяет, проходит ли запись фильтр по стране.

    - Нет country_code (None/пусто):
        * при inc_countries задан — НЕ проходит (нет подтверждения нужной страны);
        * при exc_countries задан — проходит (нечего исключать);
        * если оба None — проходит.
    - Есть country_code:
        * при inc_countries задан и кода нет в нём — НЕ проходит;
        * при exc_countries задан и код в нём — НЕ проходит;
        * иначе проходит.
    """
    if inc_countries is None and exc_countries is None:
        return True

    if country_code is None or str(country_code).strip() == '':
        # Нет данных о стране
        return inc_countries is None

    code = str(country_code).upper()

    if inc_countries is not None and code not in inc_countries:
        return False
    if exc_countries is not None and code in exc_countries:
        return False
    return True


def filter_by_country(
    filtered_data: dict,
    inc_countries: set[str] | None,
    exc_countries: set[str] | None,
) -> tuple[dict, dict]:
    """
    Пост-фильтрация уже GEO-обогащённых данных по country_code.
    Применяется ПОСЛЕ enrich_with_geo.

    Удаляет домены/субдомены, не прошедшие фильтр по стране.
    Опустевшие домены и категории удаляются.
    Обновляет meta.statistics.
    """
    stats = {
        'country_domains_checked': 0,
        'country_domains_skipped': 0,
        'country_subdomains_checked': 0,
        'country_subdomains_skipped': 0,
        'country_domains_dropped_empty': 0,
        'country_categories_dropped_empty': 0,
    }

    categories = filtered_data.get('categories') or {}
    kept_categories: dict[str, dict] = {}

    for cat_name, cat_data in categories.items():
        domains = (cat_data or {}).get('domains') or {}
        kept_domains: dict[str, Any] = {}

        for dom_name, dom_value in domains.items():
            if not isinstance(dom_value, dict):
                kept_domains[dom_name] = dom_value
                continue

            new_dom: dict[str, Any] = {}

            new_dom: dict[str, Any] = {}

            # 1. Проверка домена по _other_info.country_code
            dom_geo = dom_value.get('_other_info')
            dom_country = dom_geo.get('country_code') if isinstance(dom_geo, dict) else None
            stats['country_domains_checked'] += 1
            dom_passes = _country_passes(dom_country, inc_countries, exc_countries)

            if dom_passes:
                # Домен прошёл — сохраняет его _date_added и _other_info
                if '_date_added' in dom_value:
                    new_dom['_date_added'] = dom_value['_date_added']
                if dom_geo is not None:
                    new_dom['_other_info'] = dom_geo
            else:
                # Домен не прошёл — его _date_added/_other_info НЕ сохраняются
                stats['country_domains_skipped'] += 1

            # 2. Субдомены
            for key, sub_value in dom_value.items():
                if key in ('_date_added', '_other_info'):
                    continue

                stats['country_subdomains_checked'] += 1

                if not isinstance(sub_value, dict):
                    stats['country_subdomains_skipped'] += 1
                    continue

                sub_geo = sub_value.get('_other_info')
                sub_country = sub_geo.get('country_code') if isinstance(sub_geo, dict) else None

                if _country_passes(sub_country, inc_countries, exc_countries):
                    new_dom[key] = sub_value
                else:
                    stats['country_subdomains_skipped'] += 1

            # 3. Оставить домен, только если прошёл по country_code
            has_subdomains = any(k not in ('_date_added', '_other_info') for k in new_dom)

            if dom_passes or has_subdomains:
                kept_domains[dom_name] = new_dom
            else:
                stats['country_domains_dropped_empty'] += 1

        if kept_domains:
            kept_categories[cat_name] = {'domains': kept_domains}
        else:
            stats['country_categories_dropped_empty'] += 1

    filtered_data['categories'] = kept_categories

    # Статистика в meta
    filtered_data.setdefault('meta', {}).setdefault('statistics', {})
    filtered_data['meta']['statistics']['country'] = {
        'domains_checked': stats['country_domains_checked'],
        'domains_skipped': stats['country_domains_skipped'],
        'subdomains_checked': stats['country_subdomains_checked'],
        'subdomains_skipped': stats['country_subdomains_skipped'],
        'domains_dropped_empty': stats['country_domains_dropped_empty'],
        'categories_dropped_empty': stats['country_categories_dropped_empty'],
    }

    return filtered_data, stats


def filter_by_domain_noise(
    filtered_data: dict,
    threshold: int,
) -> tuple[dict, dict]:
    """
    Удаляет домены (вместе со всеми субдоменами), у которых количество
    субдоменов СТРОГО больше threshold.

    threshold == 0 — фильтрация отключена (функция ничего не делает).

    Субдоменами считаются все ключи домена, кроме служебных
    ('_date_added', '_other_info').
    """
    stats = {
        'noise_threshold': threshold,
        'noise_domains_checked': 0,
        'noise_domains_dropped': 0,
        'noise_subdomains_dropped': 0,
        'noise_categories_dropped_empty': 0,
    }

    if threshold == 0:
        logger.info("domain_noise_threshold=0 — фильтрация по шумности отключена.")
        return filtered_data, stats

    categories = filtered_data.get('categories') or {}
    kept_categories: dict[str, dict] = {}

    for cat_name, cat_data in categories.items():
        domains = (cat_data or {}).get('domains') or {}
        kept_domains: dict[str, Any] = {}

        for dom_name, dom_value in domains.items():
            if not isinstance(dom_value, dict):
                kept_domains[dom_name] = dom_value
                continue

            stats['noise_domains_checked'] += 1

            sub_count = sum(
                1 for k in dom_value
                if k not in ('_date_added', '_other_info')
            )

            if sub_count > threshold:
                stats['noise_domains_dropped'] += 1
                stats['noise_subdomains_dropped'] += sub_count
                logger.debug(
                    f"Шумность: удалён '{cat_name}/{dom_name}' "
                    f"(субдоменов={sub_count} > {threshold})."
                )
                continue

            kept_domains[dom_name] = dom_value

        if kept_domains:
            kept_categories[cat_name] = {'domains': kept_domains}
        else:
            stats['noise_categories_dropped_empty'] += 1

    filtered_data['categories'] = kept_categories

    filtered_data.setdefault('meta', {}).setdefault('statistics', {})
    filtered_data['meta']['statistics']['domain_noise'] = {
        'threshold': stats['noise_threshold'],
        'domains_checked': stats['noise_domains_checked'],
        'domains_dropped': stats['noise_domains_dropped'],
        'subdomains_dropped': stats['noise_subdomains_dropped'],
        'categories_dropped_empty': stats['noise_categories_dropped_empty'],
    }

    return filtered_data, stats

# =============================================================================
# Загрузка и фильтрация YAML
# =============================================================================

def _parse_record_date(value: Any) -> date | None:
    """
    Парсит дату записи.
    """
    if value is None:
        return None
    try:
        return datetime.strptime(str(value), '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return None

def _in_range(d: date, from_date: date | None, to_date: date | None) -> bool:
    if from_date and d < from_date:
        return False
    if to_date and d > to_date:
        return False
    return True


def _category_passes(
    cat_name: str,
    inc_cats: set[str] | None,
    exc_cats: set[str] | None,
) -> bool:
    if inc_cats is not None and cat_name not in inc_cats:
        return False
    if exc_cats is not None and cat_name in exc_cats:
        return False
    return True


def filter_domains(
    data: dict,
    from_date: date | None,
    to_date: date | None,
    inc_cats: set[str] | None,
    exc_cats: set[str] | None,
    inc_doms: set[str] | None,
    exc_doms: set[str] | None,
) -> tuple[dict, dict]:

    stats = {
        'categories_total': 0,
        'categories_selected': 0,
        'domains_total': 0,
        'domains_selected': 0,
        'subdomains_total': 0,
        'subdomains_selected': 0,
        'skipped_by_date': 0,
        'skipped_by_category': 0,
        'skipped_by_domain': 0,
        'forced_by_domain_inclusion': 0,
        'skipped_by_date_missing': 0,
        'skipped_by_date_bad': 0,
        'bad_date_examples': [],   # до 5 примеров 'cat/dom[/sub]=value'
    }

    categories = data.get('categories') or {}
    filtered_categories: dict[str, dict] = {}

    for cat_name in categories.keys():
        stats['categories_total'] += 1

        cat_passes = _category_passes(cat_name, inc_cats, exc_cats)
        if not cat_passes:
            stats['skipped_by_category'] += 1

        cat_data = categories[cat_name] or {}
        domains = cat_data.get('domains') or {}
        filtered_domains: dict[str, Any] = {}

        for dom_name in domains.keys():
            dom_value = domains[dom_name]
            if not isinstance(dom_value, dict):
                logger.warning(f"Категория '{cat_name}', домен '{dom_name}': "
                               f"ожидался словарь, получено {type(dom_value).__name__} — пропущено.")
                continue

            stats['domains_total'] += 1

            forced_in = False
            if exc_doms is not None and dom_name in exc_doms:
                stats['skipped_by_domain'] += 1
                continue
            if inc_doms is not None and dom_name in inc_doms:
                forced_in = True
                stats['forced_by_domain_inclusion'] += 1

            if not forced_in and not cat_passes:
                stats['skipped_by_domain'] += 1
                continue

            new_dom_entry: dict[str, Any] = {}

            dom_date_raw = dom_value.get('_date_added')
            if dom_date_raw is not None:
                d = _parse_record_date(dom_date_raw)
                if d is None:
                    stats['skipped_by_date'] += 1
                    stats['skipped_by_date_bad'] += 1
                    if len(stats['bad_date_examples']) < 5:
                        stats['bad_date_examples'].append(
                            f"{cat_name}/{dom_name}={dom_date_raw!r}"
                        )
                elif _in_range(d, from_date, to_date):
                    new_dom_entry['_date_added'] = str(dom_date_raw)
                    stats['domains_selected'] += 1
                else:
                    stats['skipped_by_date'] += 1

            for key, sub_value in dom_value.items():
                if key == '_date_added':
                    continue
                stats['subdomains_total'] += 1
                d = _parse_record_date(sub_value)
                if d is None:
                    stats['skipped_by_date'] += 1
                    if sub_value is None:
                        stats['skipped_by_date_missing'] += 1
                    else:
                        stats['skipped_by_date_bad'] += 1
                        if len(stats['bad_date_examples']) < 5:
                            stats['bad_date_examples'].append(
                                f"{cat_name}/{dom_name}/{key}={sub_value!r}"
                            )
                    continue
                if _in_range(d, from_date, to_date):
                    new_dom_entry[key] = str(sub_value)
                    stats['subdomains_selected'] += 1
                else:
                    stats['skipped_by_date'] += 1

            if new_dom_entry:
                filtered_domains[dom_name] = new_dom_entry

        if filtered_domains:
            filtered_categories[cat_name] = {'domains': filtered_domains}
            stats['categories_selected'] += 1

    # Сортировка в алфавитном порядке в выводе
    sorted_categories = {
        cat_name: {
            'domains': {
                dom_name: filtered_categories[cat_name]['domains'][dom_name]
                for dom_name in sorted(filtered_categories[cat_name]['domains'])
            }
        }
        for cat_name in sorted(filtered_categories)
    }

    filtered_data = {
        'meta': {
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source_meta_generated_at': (data.get('meta') or {}).get('generated_at'),
            'filter': {
                'start_date': str(from_date) if from_date else 'none',
                'end_date': str(to_date) if to_date else 'none',
                'interval_date': interval_date,
                'category_inclusion': sorted(inc_cats) if inc_cats else 'none',
                'category_exclusion': sorted(exc_cats) if exc_cats else 'none',
                'domain_inclusion': sorted(inc_doms) if inc_doms else 'none',
                'domain_exclusion': sorted(exc_doms) if exc_doms else 'none',
            },
            'statistics': {
                'categories_selected': stats['categories_selected'],
                'domains_selected': stats['domains_selected'],
                'subdomains_selected': stats['subdomains_selected'],
            },
        },
        'categories': sorted_categories,
    }

    return filtered_data, stats


# =============================================================================
# Вывод
# =============================================================================

def render_result(filtered_data: dict) -> str:
    """Сериализует результат в YAML-строку"""
    if not filtered_data.get('categories'):
        return ''
    return yaml.safe_dump(
        filtered_data, allow_unicode=True, sort_keys=False,
        default_flow_style=False,
    )


def save_result(yaml_text: str) -> Path:
    """Сохраняет сериализованный YAML в файл"""
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_path = Path(__file__).resolve().parent / f"enriched_{ts}.yaml"
    with out_path.open('w', encoding='utf-8') as f:
        f.write(yaml_text)
    return out_path

def resolve_domain_noise_threshold() -> int:
    v = domain_noise_threshold
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        logger.error(
            f"Параметр 'domain_noise_threshold': ожидается целое >= 0, "
            f"получено {v!r}."
        )
        sys.exit(1)
    return v

# =============================================================================
# main
# =============================================================================

def main() -> None:
    setup_logging()
    _parse_dns_server(dns_server)

    script_name = Path(__file__).name
    logger.info("=" * 70)
    logger.info(f"Скрипт: {script_name}")
    logger.info(f"dns_server            = {dns_server!r}")
    logger.info(f"start_date            = {start_date!r}")
    logger.info(f"end_date              = {end_date!r}")
    logger.info(f"interval_date         = {interval_date!r}")
    logger.info(f"category_inclusion    = {category_inclusion!r}")
    logger.info(f"category_exclusion    = {category_exclusion!r}")
    logger.info(f"domain_inclusion      = {domain_inclusion!r}")
    logger.info(f"domain_exclusion      = {domain_exclusion!r}")
    logger.info(f"country_inclusion     = {country_inclusion!r}")
    logger.info(f"country_exclusion     = {country_exclusion!r}")
    logger.info(f"domain_noise_threshold = {domain_noise_threshold!r}")
    logger.info(f"path_to_yaml...       = {path_to_yaml_catsort_domains!r}")
    logger.info(f"save_to_file          = {save_to_file!r}")
    logger.info(f"geo_checking          = {geo_checking!r}")
    logger.info(f"path_to_mmdb          = {path_to_mmdb!r}")
    logger.info(f"path_to_schema_mmdb   = {path_to_schema_mmdb!r}")
    logger.info("=" * 70)

    # Валидация базовых параметров
    from_date, to_date = resolve_date_range()
    inc_cats, exc_cats = resolve_categories()
    inc_doms, exc_doms = resolve_domains()
    inc_countries, exc_countries = resolve_countries()
    paths = resolve_paths()
    mmdb_path, field_mapping = resolve_geo_config()
    noise_threshold = resolve_domain_noise_threshold()

    if from_date or to_date:
        logger.info(f"Диапазон дат: {from_date or '...'} .. {to_date or '...'} (включительно)")
    else:
        logger.info("Диапазон дат не задан — берём все записи.")

    # Загрузка + merge
    merged_categories: dict[str, dict] = {}
    total_files = len(paths)
    for i, path in enumerate(paths, 1):
        logger.info(f"[{i}/{total_files}] Загрузка: {path}")
        try:
            with path.open('r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            logger.error(f"Ошибка парсинга YAML в {path}: {e}")
            sys.exit(1)
        except OSError as e:
            logger.error(f"Ошибка чтения {path}: {e}")
            sys.exit(1)

        cats = data.get('categories') or {}
        if not isinstance(cats, dict):
            logger.warning(f"{path}: 'categories' не словарь — пропущено.")
            continue

        for cat_name, cat_value in cats.items():
            if not isinstance(cat_value, dict):
                logger.warning(f"{path}: категория '{cat_name}' не словарь — пропущено.")
                continue
            domains = cat_value.get('domains') or {}
            if not isinstance(domains, dict):
                logger.warning(f"{path}: категория '{cat_name}'.domains не словарь — пропущено.")
                continue

            target = merged_categories.setdefault(cat_name, {'domains': {}})
            for dom_name, dom_value in domains.items():
                if dom_name in target['domains']:
                    existing = target['domains'][dom_name]
                    if not isinstance(existing, dict) or not isinstance(dom_value, dict):
                        target['domains'][dom_name] = dom_value
                        continue
                    merged_entry = existing
                    for k, v in dom_value.items():
                        if k not in merged_entry:
                            merged_entry[k] = v
                        elif k == '_date_added':
                            try:
                                a = datetime.strptime(str(merged_entry[k]), '%Y-%m-%d').date()
                                b = datetime.strptime(str(v), '%Y-%m-%d').date()
                                merged_entry[k] = str(min(a, b))
                            except (ValueError, TypeError):
                                pass
                    target['domains'][dom_name] = merged_entry
                else:
                    target['domains'][dom_name] = dom_value

    merged_data = {'categories': merged_categories}

    # Фильтрация
    logger.info("Фильтрация...")
    filtered_data, stats = filter_domains(
        merged_data, from_date, to_date,
        inc_cats, exc_cats, inc_doms, exc_doms,
    )

    # Фильтрация по шумности домена (в самом конце, после GEO и стран)
    if noise_threshold > 0:
        logger.info(f"Фильтрация по шумности (порог > {noise_threshold} субдоменов)...")
        filtered_data, noise_stats = filter_by_domain_noise(
            filtered_data, noise_threshold,
        )

    logger.info("-" * 70)
    logger.info("СТАТИСТИКА ФИЛЬТРАЦИИ")
    logger.info(f"  Категорий всего:              {stats['categories_total']}")
    logger.info(f"  Категорий отобрано:           {stats['categories_selected']}")
    logger.info(f"  Доменов всего:                {stats['domains_total']}")
    logger.info(f"  Доменов отобрано:             {stats['domains_selected']}")
    logger.info(f"  Субдоменов всего:             {stats['subdomains_total']}")
    logger.info(f"  Субдоменов отобрано:          {stats['subdomains_selected']}")
    logger.info(f"  Форсировано domain_inclusion: {stats['forced_by_domain_inclusion']}")
    logger.info(f"  Пропущено по дате:            {stats['skipped_by_date']}")
    if stats['skipped_by_date_bad'] or stats['skipped_by_date_missing']:
        logger.warning(
            f"  Даты: битых={stats['skipped_by_date_bad']}, "
            f"отсутствующих(субдомены)={stats['skipped_by_date_missing']}."
        )
        for ex in stats['bad_date_examples']:
            logger.warning(f"    пример битой даты: {ex}")

    logger.info(f"  Пропущено по категории:       {stats['skipped_by_category']}")
    logger.info(f"  Пропущено по домену:          {stats['skipped_by_domain']}")
    logger.info("-" * 70)

    # GEO
    if geo_checking and mmdb_path and field_mapping:
        logger.info("GEO-проверка...")
        geo_stats = enrich_with_geo(filtered_data, mmdb_path, field_mapping)
        logger.info("-" * 70)
        logger.info("СТАТИСТИКА GEO")
        logger.info(f"  Проверено записей:            {geo_stats['geo_domains_checked']}")
        logger.info(f"  Успешно отрезолвлено:         {geo_stats['geo_resolved']}")
        logger.info(f"  Не отрезолвлено:              {geo_stats['geo_unresolved']}")
        logger.info(f"  IP не найден в MMDB:          {geo_stats['geo_ip_not_found']}")
        logger.info("-" * 70)

        # Статистика meta
        filtered_data['meta']['statistics']['geo'] = {
            'checked': geo_stats['geo_domains_checked'],
            'resolved': geo_stats['geo_resolved'],
            'unresolved': geo_stats['geo_unresolved'],
            'ip_not_found': geo_stats['geo_ip_not_found'],
        }

    # Фильтрация по стране (после GEO)
    if inc_countries is not None or exc_countries is not None:
        if not (geo_checking and mmdb_path and field_mapping):
            logger.warning(
                "country_inclusion/country_exclusion заданы, но geo_checking=False — "
                "country_code отсутствует. При country_inclusion все записи без "
                "_other_info будут исключены (нет подтверждения страны)."
            )
        logger.info("Фильтрация по стране (country_code)...")
        filtered_data, country_stats = filter_by_country(
            filtered_data, inc_countries, exc_countries,
        )
        logger.info("-" * 70)
        logger.info("СТАТИСТИКА ФИЛЬТРАЦИИ ПО СТРАНЕ")
        logger.info(f"  Доменов проверено:            {country_stats['country_domains_checked']}")
        logger.info(f"  Доменов пропущено:            {country_stats['country_domains_skipped']}")
        logger.info(f"  Субдоменов проверено:         {country_stats['country_subdomains_checked']}")
        logger.info(f"  Субдоменов пропущено:         {country_stats['country_subdomains_skipped']}")
        logger.info(f"  Доменов удалено (пустые):     {country_stats['country_domains_dropped_empty']}")
        logger.info(f"  Категорий удалено (пустые):   {country_stats['country_categories_dropped_empty']}")
        logger.info("-" * 70)

    # Отражение параметров фильтра по стране в meta.filter
    filtered_data['meta'].setdefault('filter', {})
    filtered_data['meta']['filter']['domain_noise_threshold'] = noise_threshold
    filtered_data['meta']['filter']['country_inclusion'] = (
        sorted(inc_countries) if inc_countries else 'none'
    )
    filtered_data['meta']['filter']['country_exclusion'] = (
        sorted(exc_countries) if exc_countries else 'none'
    )

    logger.info("=" * 70)
    logger.info("РЕЗУЛЬТАТ ФИЛЬТРАЦИИ")
    logger.info("=" * 70)

    yaml_text = render_result(filtered_data)
    if not yaml_text:
        logger.info("(пусто — ни одна запись не прошла фильтр)")
    else:
        print(yaml_text, end='')
        logger.info("=" * 70)

    if save_to_file:
        if not yaml_text:
            yaml_text = yaml.safe_dump(
                filtered_data, allow_unicode=True, sort_keys=False,
                default_flow_style=False,
            )
        out_path = save_result(yaml_text)
        logger.info(f"Результат сохранён: {out_path}")
    else:
        logger.info("save_to_file=False — файл не сохранён.")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Прервано пользователем.")
        sys.exit(130)
  
