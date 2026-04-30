#!/bin/bash
# Bug Bounty Security Agent — деплой на Ubuntu VPS
# Использование: curl -sSL <url>/deploy.sh | bash
# Или: chmod +x deploy.sh && ./deploy.sh

set -e

echo "=== Bug Bounty Security Agent — Установка ==="

# 1. Docker (если нет)
if ! command -v docker &> /dev/null; then
    echo "→ Устанавливаю Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    echo "  Docker установлен. Перелогинься (exit + ssh) если docker compose не работает."
fi

# 2. Docker Compose plugin (если нет)
if ! docker compose version &> /dev/null; then
    echo "→ Устанавливаю Docker Compose plugin..."
    sudo apt-get update && sudo apt-get install -y docker-compose-plugin
fi

# 3. Генерируем секрет для JWT
if [ ! -f .env ]; then
    echo "→ Генерирую JWT секрет..."
    echo "JWT_SECRET_KEY=$(openssl rand -hex 32)" > .env
    echo "  Секрет сохранён в .env"
fi

# 4. Собираем и запускаем
echo "→ Собираю контейнеры (это займёт 3-5 минут)..."
docker compose up -d --build

echo ""
echo "=== Готово! ==="
echo ""
echo "  Веб-интерфейс:  http://$(curl -s ifconfig.me)"
echo "  API:             http://$(curl -s ifconfig.me):8000/docs"
echo ""
echo "  Логин:  admin"
echo "  Пароль: admin  ← СМЕНИ СРАЗУ!"
echo ""
echo "  Логи:    docker compose logs -f"
echo "  Стоп:    docker compose down"
echo "  Рестарт: docker compose restart"
echo ""
