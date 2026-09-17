#!/usr/bin/env bash
SERVICE_NAME="vpn-spoof.service"
DESKTOP_NAME="vpn-spoof.desktop"

echo "[*] Остановка и удаление автозапуска $SERVICE_NAME..."

# 1. Остановка и удаление systemd --user
systemctl --user stop "$SERVICE_NAME" 2>/dev/null || true
systemctl --user disable "$SERVICE_NAME" 2>/dev/null || true
rm -f "$HOME/.config/systemd/user/$SERVICE_NAME"
systemctl --user daemon-reload 2>/dev/null || true

# 2. Удаление XDG Autostart
rm -f "$HOME/.config/autostart/$DESKTOP_NAME"

# 3. Удаление legacy системной службы, если была создана с sudo
if [ -f "/etc/systemd/system/$SERVICE_NAME" ]; then
    if command -v sudo >/dev/null 2>&1; then
        sudo systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        sudo systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        sudo rm -f "/etc/systemd/system/$SERVICE_NAME"
        sudo systemctl daemon-reload 2>/dev/null || true
    fi
fi

# 4. Завершение работающих процессов прокси
pkill -f "main.py proxy" 2>/dev/null || true

echo "[+] Автозапуск успешно отключен и все следы службы удалены."
