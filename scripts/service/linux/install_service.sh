#!/usr/bin/env bash
set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SERVICE_NAME="${SUBSYNC_SERVICE_NAME:-vpn-spoof.service}"
PORT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)
            REPO_DIR="$(cd "$2" && pwd)"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --service-name)
            SERVICE_NAME="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

[[ "$SERVICE_NAME" == *.service ]] || SERVICE_NAME="${SERVICE_NAME}.service"
DESKTOP_NAME="${SERVICE_NAME%.service}.desktop"
CFG_FILE="$REPO_DIR/data/config.json"

if [ -z "$PORT" ] && [ -f "$CFG_FILE" ]; then
    PORT="$(grep -o '"listen_port": *[0-9]*' "$CFG_FILE" 2>/dev/null | head -n1 | grep -o '[0-9]*' || true)"
fi
PORT="${PORT:-54321}"

UV_PATH="$(command -v uv || true)"
if [ -z "$UV_PATH" ] && [ -x "$HOME/.local/bin/uv" ]; then
    UV_PATH="$HOME/.local/bin/uv"
fi
[ -n "$UV_PATH" ] || { echo "[-] Не найден uv в PATH или ~/.local/bin/uv"; exit 1; }

PROXY_ARGS="main.py proxy --config $CFG_FILE --port $PORT"

echo "[*] Настройка автозапуска $SERVICE_NAME (каталог: $REPO_DIR, порт: $PORT)..."

# 1. Настройка через systemd --user (без root)
USER_SYSTEMD_DIR="$HOME/.config/systemd/user"
mkdir -p "$USER_SYSTEMD_DIR"

cat << EOF > "$USER_SYSTEMD_DIR/$SERVICE_NAME"
[Unit]
Description=SubSync Proxy Daemon ($SERVICE_NAME)
After=default.target

[Service]
Type=simple
WorkingDirectory=$REPO_DIR
ExecStart=$UV_PATH run $PROXY_ARGS
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF

# Останавливаем прежний фоновый процесс именно этого каталога (если был запущен без systemd)
pkill -f "--config $CFG_FILE" 2>/dev/null || true

SYSTEMD_USER_OK=false
if systemctl --user daemon-reload 2>/dev/null && systemctl --user enable "$SERVICE_NAME" 2>/dev/null && systemctl --user restart "$SERVICE_NAME" 2>/dev/null; then
    SYSTEMD_USER_OK=true
    echo "[+] Служба systemd --user ($SERVICE_NAME) успешно настроена и запущена!"
fi

# 2. Настройка через XDG Autostart
AUTOSTART_DIR="$HOME/.config/autostart"
mkdir -p "$AUTOSTART_DIR"

cat << EOF > "$AUTOSTART_DIR/$DESKTOP_NAME"
[Desktop Entry]
Type=Application
Name=SubSync Proxy ($SERVICE_NAME)
Comment=SubSync Local Subscription & Cascade Proxy
Exec=bash -c "cd '$REPO_DIR' && '$UV_PATH' run $PROXY_ARGS"
Terminal=false
Hidden=false
X-GNOME-Autostart-enabled=true
EOF

echo "[+] Ярлык автозапуска создан в: $AUTOSTART_DIR/$DESKTOP_NAME"

# 3. Если systemd --user недоступен, запускаем процесс в фоне
if [ "$SYSTEMD_USER_OK" = false ]; then
    echo "[*] Запуск фонового процесса прокси без systemd..."
    nohup "$UV_PATH" run --directory "$REPO_DIR" $PROXY_ARGS > /dev/null 2>&1 &
fi

echo "[+] Автозапуск успешно настроен (без прав root)!"
echo "[*] Локальный эндпоинт прокси: http://127.0.0.1:$PORT/sub"
