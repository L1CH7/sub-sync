#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Проверяем наличие uv
if ! command -v uv &> /dev/null && [ ! -f "$HOME/.local/bin/uv" ]; then
    echo "=================================================="
    echo "⚡ VPN Spoof - Первичная настройка"
    echo "=================================================="
    echo "[!] Для работы требуется быстрый менеджер Python (uv)."
    read -p "Скачать и настроить uv автоматически? [Y/n]: " choice
    choice=${choice:-Y}
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        echo "[*] Установка Astral uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.local/bin:$PATH"
    else
        echo "[-] Отменено пользователем. Установите uv вручную: https://astral.sh/uv"
        exit 1
    fi
else
    export PATH="$HOME/.local/bin:$PATH"
fi

# 2. Первичная настройка окружения при необходимости
if [ ! -d ".venv" ]; then
    echo "[*] Настройка окружения зависимостей..."
    uv sync
fi

# 3. Запуск стандартного меню
exec uv run main.py
