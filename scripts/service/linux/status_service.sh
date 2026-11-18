#!/usr/bin/env bash
SERVICE_NAME="${SUBSYNC_SERVICE_NAME:-vpn-spoof.service}"
PORT=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

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

echo "=========================================="
echo "      СТАТУС СЛУЖБЫ SUBSYNC ($SERVICE_NAME)"
echo "=========================================="

HAS_AUTOSTART=false
if systemctl --user is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo -e "\033[32m[+] Автозапуск: УСТАНОВЛЕН (systemd --user)\033[0m"
    HAS_AUTOSTART=true
elif [ -f "$HOME/.config/autostart/$DESKTOP_NAME" ]; then
    echo -e "\033[32m[+] Автозапуск: УСТАНОВЛЕН (XDG Autostart ~/.config/autostart)\033[0m"
    HAS_AUTOSTART=true
elif systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo -e "\033[32m[+] Автозапуск: УСТАНОВЛЕН (системный systemd)\033[0m"
    HAS_AUTOSTART=true
fi

if [ "$HAS_AUTOSTART" = false ]; then
    echo -e "\033[33m[-] Автозапуск: НЕ УСТАНОВЛЕН\033[0m"
fi

if systemctl --user is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo -e "\033[32m[+] Служба systemd --user: АКТИВНА (running)\033[0m"
fi

PIDS=$(pgrep -f -- "--config $CFG_FILE" 2>/dev/null || true)
if [ -z "$PIDS" ] && [ "$SERVICE_NAME" = "vpn-spoof.service" ]; then
    PIDS=$(pgrep -f "[m]ain.py proxy" 2>/dev/null || true)
fi
if [ -n "$PIDS" ]; then
    echo -e "\033[32m[+] Процесс main.py proxy: РАБОТАЕТ (PID: $PIDS)\033[0m"
else
    echo -e "\033[33m[-] Процесс main.py proxy: ОСТАНОВЛЕН\033[0m"
fi

PORT_INFO=$(ss -tlpn "sport = :$PORT" 2>/dev/null | grep ":$PORT" | head -n1)
if [ -n "$PORT_INFO" ]; then
    PORT_OWNER_PID=$(echo "$PORT_INFO" | grep -o 'pid=[0-9]*' | head -n1 | cut -d= -f2)
    PROC_NAME=$(echo "$PORT_INFO" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')

    IS_OUR_PROXY=false
    if [ -n "$PIDS" ] && [ -n "$PORT_OWNER_PID" ]; then
        for p in $PIDS; do
            if [ "$p" = "$PORT_OWNER_PID" ]; then
                IS_OUR_PROXY=true
                break
            fi
        done
    elif [ -n "$PIDS" ]; then
        IS_OUR_PROXY=true
    fi

    if [ "$IS_OUR_PROXY" = true ]; then
        echo -e "\033[32m[+] Порт $PORT: АКТИВЕН (Служба proxy принимает подключения)\033[0m"
        echo -e "[*] Эндпоинт подписки: http://127.0.0.1:$PORT/sub"
    else
        echo -e "\033[31m[!] Порт $PORT: ЗАНЯТ сторонним процессом (${PROC_NAME:-неизвестно}, PID: ${PORT_OWNER_PID:-?})\033[0m"
    fi
else
    if [ -n "$PIDS" ]; then
        echo -e "\033[31m[!] Порт $PORT: НЕ ОТКРЫТ (хотя процесс запущен - возможен сбой при старте)\033[0m"
    else
        echo -e "\033[37m[i] Порт $PORT: СВОБОДЕН (служба выключена)\033[0m"
    fi
fi
echo "=========================================="
