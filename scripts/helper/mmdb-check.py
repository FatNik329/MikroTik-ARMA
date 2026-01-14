"""
Скрипт для анализа структуры MMDB файлов
Использование: python3 check-mmdb.py /путь/к/файлу.mmdb
"""

import sys
import json
from datetime import datetime
from pathlib import Path
import maxminddb

def analyze_mmdb(filename: str) -> dict:
    """Анализ MMDB файла"""
    result = {
        'filename': str(Path(filename).resolve()),
        'analysis_date': datetime.now().isoformat(),
        'file_size': Path(filename).stat().st_size if Path(filename).exists() else 0
    }

    try:
        with maxminddb.open_database(filename) as db:
            # Metadata
            meta = db.metadata()
            result['metadata'] = {
                'database_type': meta.database_type,
                'description': meta.description,
                'binary_format_version': f'{meta.binary_format_major_version}.{meta.binary_format_minor_version}',
                'build_epoch': meta.build_epoch,
                'build_date': datetime.fromtimestamp(meta.build_epoch).isoformat(),
                'node_count': meta.node_count,
                'record_size': meta.record_size,
                'ip_version': meta.ip_version
            }

            # Тестируемые IP
            test_ips = ['8.8.8.8', '1.1.1.1', '77.88.8.8', '208.67.222.222']
            result['test_samples'] = {}

            for ip in test_ips:
                data = db.get(ip)
                if data:
                    result['test_samples'][ip] = {
                        'fields': list(data.keys()),
                        'data': {k: str(v) if not isinstance(v, (dict, list)) else v for k, v in data.items()}
                    }

            # Поля статистики
            all_fields = set()
            for ip_data in result['test_samples'].values():
                all_fields.update(ip_data['fields'])

            result['field_analysis'] = {
                'total_unique_fields': len(all_fields),
                'fields_list': sorted(list(all_fields))
            }

        result['status'] = 'success'
        result['error'] = None

    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)

    return result

def print_readable(analysis: dict):
    """Вывод в читаемом виде"""
    print('=' * 60)
    print('Анализ MMDB файла')
    print('=' * 60)

    if analysis['status'] == 'error':
        print(f'\n Error: {analysis["error"]}')
        return

    meta = analysis['metadata']

    print(f'\n Файл: {analysis["filename"]}')
    print(f' Размер: {analysis["file_size"]:,} байт')

    print('\n Мета информация:')
    print(f'  Тип базы:          {meta["database_type"]}')
    print(f'  Описание:          {meta["description"].get("en", "N/A")}')
    print(f'  Версия формата:    {meta["binary_format_version"]}')
    print(f'  Дата сборки:       {datetime.fromtimestamp(meta["build_epoch"]).strftime("%Y-%m-%d %H:%M:%S")}')
    print(f'  Нода записи:       {meta["node_count"]:,}')
    print(f'  IP версия:         IPv{meta["ip_version"]}')

    print('\n Тестовые данные:')
    for ip, data in analysis['test_samples'].items():
        print(f'\n  IP: {ip}')
        print(f'     Поля ({len(data["fields"])}): {data["fields"]}')
        for field_name, field_value in data['data'].items():
            if isinstance(field_value, (list, dict)):
                value_str = json.dumps(field_value, ensure_ascii=False)[:50]
                if len(value_str) == 50:
                    value_str += '...'
                print(f'     {field_name}: {type(field_value).__name__} = {value_str}')
            else:
                print(f'     {field_name}: str = "{field_value}"')

    print('\n Статистика полей:')
    fields = analysis['field_analysis']['fields_list']
    print(f'  Уникальных полей:  {len(fields)}')
    print(f'  Список полей:      {fields}')

    print('\n' + '=' * 60)

def main():
    """Основная функция"""
    if len(sys.argv) != 2:
        print(f'Использование: {sys.argv[0]} /путь/к/файлу.mmdb')
        print(f'Пример: {sys.argv[0]} raw-data/ASN-db/ip-to-asn.mmdb')
        sys.exit(1)

    filename = sys.argv[1]

    if not Path(filename).exists():
        print(f' Файл не найден: {filename}')
        sys.exit(1)


    analysis = analyze_mmdb(filename)


    print_readable(analysis)


    output_file = Path(filename).with_suffix('.analysis.json')
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False, default=str)
        print(f' Полный анализ сохранён в: {output_file}')
    except Exception as e:
        print(f' Не удалось сохранить JSON: {e}')

if __name__ == '__main__':
    main()
  
