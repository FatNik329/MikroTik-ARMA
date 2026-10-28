#!/bin/bash
# === Скрипт установки для MikroTik-ARMA ===

set -e

# PART1 - установка виртуального окружения (Python)

venv_name="env"

# Проверяет, существует ли виртуальное окружение в директории
if [ -d "$venv_name" ]; then
    echo "⚠️ Виртуальное окружение '$venv_name' уже существует."
    read -p "Пересоздать? (y/N) " rebuild
    if [[ "$rebuild" =~ ^[Yy]$ ]]; then
        rm -rf "$venv_name"
    else
        echo "Обновляем зависимости в существующем окружении..."
        "$venv_name/bin/pip" install -U -r requirements.txt
    fi
fi

# Создаёт виртуальное окружение (если отсутствует)
if [ ! -d "$venv_name" ]; then
    echo "🛠 Создаётся виртуальное окружение '$venv_name'..."
    python3 -m venv "$venv_name"

    # Устанавливаем зависимости
    echo "📦 Установка зависимостей из requirements.txt..."
    "$venv_name/bin/pip" install -U pip setuptools wheel  # Обновляет базовые инструменты
    "$venv_name/bin/pip" install -r requirements.txt
fi


# PART2 - создание основных директории проекта
echo "📁 Создание структуры директорий проекта"
mkdir -p security cache cache/bgp_announce_routes cache/filter_results_dns raw-data output-data configs/AddressLists logs/base logs/additional logs/helper
echo "✅ Директории созданы"

# и файлов c чувствительными данными (mikrotik.yaml, notify.yaml)
## Создание security/mikrotik.yaml
echo "⚙️ Создание security/mikrotik.yaml - с шаблонным заполнением"
cat > security/mikrotik.yaml <<EOF
# Данное заполнение является примером рабочей конфигурации
devices:
  master1: # Раздел настроек для Master устройств. 1-й master
    name: "DescriptionMaster1"     # Удобочитаемое имя - описание
    host: 192.168.0.1              # IP адрес подключения
    username: "<Your_username_Master1>"               # Имя пользователя для подключения
    password: "<Password_username_Master1>"    # Пароль пользователя
    type_auth:            # Раздел настроек авторизации. Опциональный, более приоритетный, чем configs/config.yaml
      use_ssl: true       # Использовать SSL для подключения к конкретному устройству
    type_mode: "ips-asn"  # Режим синхронизации устройства. Опциональный, но более приоритетный, чем configs/config.yaml
    settings:             # Раздел индивидуальных доп. настроек для Master устройства. Опциональные.
      batch_size: 1500    # Переопределение общего batch_size (скорость добавления адресов)
      update_delay: 0.1   # Задержка между добавляемыми адресами
      list_name: ["ExampleList", "BlockingService"] # Параметр определения AddressList для синхронизации. Опциональный, более приоритетный, чем configs/address_lists.yaml
    slaves:                             # Раздел настроек Slave устройств
      - name: "DescriptionSlave1"       # Удобочитаемое имя - описание. 1-й slave
        host: 192.168.1.1               # IP адрес подключения
        username: "<Your_username_Slave1>"          # Имя пользователя для подключения
        password: "<Password_username_Slave1>"     # Пароль пользователя
        type_auth:            # Раздел настроек авторизации. Опциональный, более приоритетный, чем configs/config.yaml
          use_ssl: true       # Использовать SSL для подключения к конкретному устройству.
        settings:             # Раздел доп. настроек для Slave устройства
          batch_size: 1500    # Переопределение общего batch_size (скорость добавления адресов)
          update_delay: 0.1   # Задержка между добавляемыми адресами
        list_sync: ["TestLists", "ExampleList"]      # Список Address Lists для синxронизации с Master устройством
      - name: "DescriptionSlave2"      # 2-й slave
        host: 10.10.10.100
        username: "<Your_username_Slave2>"
        password: "<Password_username_Slave2>"
        settings:
          batch_size: 1500
          update_delay: 0.1
        list_sync: ["TestLists"]
EOF

## Создание security/notify.yaml
echo "⚙️ Создание security/notify.yaml - с шаблонным заполнением"
cat > security/notify.yaml <<EOF
# ==========================
# Параметры Telegram и Email
# ==========================

# Заменить на свои параметры
telegram:   # раздел настроек Telegram
  bot_token: "API:token"
  chat_id: "<chat_id>"
email:      # раздел настроек Email
  smtp_server: "smtp.yandex.ru"
  smtp_port: 465
  login: "example@yandex.ru"
  password: "exampleAPP-PASS"  # Рекомендуется использовать пароль приложений
  from_addr: "example@yandex.ru"
  to_addr: "example@yandex.ru"

EOF

# PART3 - генерирует run.sh - для общего запуска системы
echo "⚙️ Создание run.sh"
cat > run.sh <<EOF
#!/bin/bash

# Перемещение в директорию проекта
real=\$(realpath "\$(dirname "\$0")")
cd \$real

# Проверка актуальности зависимостей
"$venv_name/bin/pip" install -q -r requirements.txt

# Запуск оркестратора ARMA
"$venv_name/bin/python" scripts/main_start.py
EOF

chmod +x run.sh  # Назначает права исполнения скрипту

echo "✅ Всё готово"

echo "Для активации виртуального окружения ввести команду из директории проекта: source $venv_name/bin/activate"
