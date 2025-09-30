# Скрипт необходимо запускать из корневой директории проекта
import os
import glob
import gzip
import yaml
from datetime import datetime

# Загрузка конфигурации из файла
def load_config():
    try:
        with open('configs/config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config.get('logs_rotate', {})
    except FileNotFoundError:
        print("⚠️ Файл конфигурации configs/config.yaml не найден, используются значения по умолчанию")
        return {}
    except Exception as e:
        print(f"⚠️ Ошибка загрузки конфигурации: {e}, используются значения по умолчанию")
        return {}

# Загрузка настроек из конфига
config = load_config()
MAX_DIR_SIZE_MB = config.get('max_dir_size', 5)
MAX_LOG_VERSIONS = config.get('count_arch_logs', 3)


# Конфигурация
LOG_DIRS = [      # Список директорий с логами
    "logs"
]

def get_dir_size(path):
    """Возвращает размер директории в мегабайтах (рекурсивно)"""
    total = 0
    for entry in os.scandir(path):
        if entry.is_file():
            total += entry.stat().st_size
        elif entry.is_dir():
            total += get_dir_size(entry.path)  # Рекурсивный вызов
    return total / (1024 * 1024)  # Конвертация в МБ

def find_all_log_dirs(base_dirs):
    """Рекурсивно находит все поддиректории, содержащие .log файлы"""
    log_dirs = set()

    for base_dir in base_dirs:
        if not os.path.exists(base_dir):
            print(f"❌ Директория не найдена: {base_dir}")
            continue

        # Рекурсивный поиск всех директорий с .log файлами
        for root, dirs, files in os.walk(base_dir):
            # Проверяет, есть ли в текущей директории .log файлы
            log_files = [f for f in files if f.endswith('.log') and not f.endswith('.gz')]
            if log_files:
                log_dirs.add(root)

    return sorted(log_dirs)

def rotate_logs_in_dir(log_dir):
    """Ротация логов в одной директории"""
    print(f"\n📂 Обрабатывается директория: {log_dir}")

    # 1. Удалять старые архивы сверх лимита
    all_archives = sorted(
        glob.glob(os.path.join(log_dir, "*.log.*.gz")),
        key=os.path.getmtime  # Сначала старые
    )

    # Удалять лишние архивы
    for old_archive in all_archives[:-MAX_LOG_VERSIONS] if MAX_LOG_VERSIONS > 0 else all_archives:
        try:
            os.remove(old_archive)
            print(f"🧹 Удалён архив: {os.path.basename(old_archive)}")
        except Exception as e:
            print(f"⚠️ Ошибка удаления {os.path.basename(old_archive)}: {str(e)}")

    # 2. Проверить размер и архивировать если нужно
    current_size = get_dir_size(log_dir)
    print(f"📊 Текущий размер: {current_size:.2f} MB")

    if current_size < MAX_DIR_SIZE_MB:
        print("✅ Размер в норме, архивация не требуется")
        return

    current_logs = sorted(
        [f for f in glob.glob(os.path.join(log_dir, "*.log")) if not f.endswith('.gz')],
        key=os.path.getmtime
    )

    for log_file in current_logs:
        if get_dir_size(log_dir) < MAX_DIR_SIZE_MB * 0.9:
            break

        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            archive_name = f"{log_file}.{timestamp}.gz"

            with open(log_file, 'rb') as f_in:
                with gzip.open(archive_name, 'wb') as f_out:
                    f_out.writelines(f_in)

            os.remove(log_file)
            print(f"📦 Заархивирован: {os.path.basename(log_file)} -> {os.path.basename(archive_name)}")
        except Exception as e:
            print(f"⚠️ Ошибка архивации {os.path.basename(log_file)}: {str(e)}")

    print(f"📊 Новый размер: {get_dir_size(log_dir):.2f} MB")

def main():
    print("===== Запуск logs_rotate.py - ротация логов =====")
    print(f"🔄 Ротация логов (макс. {MAX_DIR_SIZE_MB} MB на директорию, {MAX_LOG_VERSIONS} архивов)")

    # Находит все директории с логами рекурсивно
    all_log_dirs = find_all_log_dirs(LOG_DIRS)

    if not all_log_dirs:
        print("❌ Не найдено директорий с .log файлами")
        return

    print(f"📁 Найдено директорий с логами: {len(all_log_dirs)}")

    for log_dir in all_log_dirs:
        rotate_logs_in_dir(log_dir)

    print("\n✅ Логи успешно обработаны")

if __name__ == "__main__":
    main()
