#!/usr/bin/env bash
set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SERVICE_NAME="vpn-spoof.service"
DESKTOP_NAME="vpn-spoof.desktop"
UV_PATH="$(which uv || echo "$HOME/.local/bin/uv")"

echo "[*] Настройка автозапуска VPN Spoof Proxy (пользовательский режим без root)..."

# 1. Настройка через systemd --user (работает на Debian, Astra Linux, Ubuntu без sudo)
USER_SYSTEMD_DIR="$HOME/.config/systemd/user"
mkdir -p "$USER_SYSTEMD_DIR"

cat << EOF > "$USER_SYSTEMD_DIR/$SERVICE_NAME"
[Unit]
Description=VPN Spoof Proxy Daemon
After=default.target

[Service]
Type=simple
WorkingDirectory=$REPO_DIR
ExecStart=$UV_PATH run main.py proxy
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF

SYSTEMD_USER_OK=false
if systemctl --user daemon-reload 2>/dev/null && systemctl --user enable --now "$SERVICE_NAME" 2>/dev/null; then
    SYSTEMD_USER_OK=true
    echo "[+] Служба systemd --user успешно настроена и запущена!"
fi

# 2. Настройка через XDG Autostart (для графических оболочек Fly, GNOME, XFCE, KDE)
AUTOSTART_DIR="$HOME/.config/autostart"
mkdir -p "$AUTOSTART_DIR"

cat << EOF > "$AUTOSTART_DIR/$DESKTOP_NAME"
[Desktop Entry]
Type=Application
Name=VPN Spoof Proxy
Comment=VPN Spoof Proxy Background Daemon
Exec=bash -c "cd '$REPO_DIR' && '$UV_PATH' run main.py proxy"
Terminal=false
Hidden=false
X-GNOME-Autostart-enabled=true
EOF

echo "[+] Ярлык автозапуска создан в: $AUTOSTART_DIR/$DESKTOP_NAME"

# 3. Если systemd --user недоступен в текущей сессии, запускаем процесс в фоне прямо сейчас
if [ "$SYSTEMD_USER_OK" = false ]; then
    if ! pgrep -f "main.py proxy" > /dev/null 2>&1; then
        echo "[*] Запуск фонового процесса прокси..."
        nohup "$UV_PATH" run --directory "$REPO_DIR" main.py proxy > /dev/null 2>&1 &
    fi
fi

echo "[+] Автозапуск успешно настроен (без прав root)!"
echo "[*] Локальный эндпоинт прокси: http://127.0.0.1:54321/sub"
