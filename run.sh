#!/bin/bash
# Пример скрипта для запуска оркестратора проекта MikroTik-ARMA
# Пример команды запуска скрипта run.sh через Cron по расписанию каждые 5 минут:
# */5 * * * * flock -n /path/to/MikroTik-ARMA/cache/main_start/cron.lock bash /path/to/MikroTik-ARMA/run.sh

# Перемещение в директорию проекта
real=$(realpath "$(dirname "$0")")
cd $real

# Проверка актуальности зависимостей
"env/bin/pip" install -q -r requirements.txt

# Запуск оркестратора ARMA
"env/bin/python" scripts/main_start.py
