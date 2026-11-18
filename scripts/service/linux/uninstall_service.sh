#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
SERVICE_NAME="${SUBSYNC_SERVICE_NAME:-vpn-spoof.service}"
EXPLICIT_DIR=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)
            REPO_DIR="$(cd "$2" && pwd)"
            EXPLICIT_DIR=true
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

echo "[*] Остановка и удаление автозапуска $SERVICE_NAME..."

# 1. Остановка и удаление systemd --user
systemctl --user stop "$SERVICE_NAME" 2>/dev/null || true
systemctl --user disable "$SERVICE_NAME" 2>/dev/null || true
rm -f "$HOME/.config/systemd/user/$SERVICE_NAME"
systemctl --user daemon-reload 2>/dev/null || true

# 2. Удаление XDG Autostart
rm -f "$HOME/.config/autostart/$DESKTOP_NAME"

# 3. Завершение фоновых процессов прокси (при --dir — только целевого экземпляра)
if [ "$EXPLICIT_DIR" = true ] || [ "$SERVICE_NAME" != "vpn-spoof.service" ]; then
    pkill -f "--config $CFG_FILE" 2>/dev/null || true
else
    pkill -f "--config $CFG_FILE" 2>/dev/null || true
    pkill -f "main.py proxy" 2>/dev/null || true
fi

echo "[+] Автозапуск $SERVICE_NAME отключен и следы службы удалены."
