#!/usr/bin/env bash
SERVICE_NAME="vpn-spoof.service"
DESKTOP_NAME="vpn-spoof.desktop"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CFG_FILE="$REPO_DIR/data/config.json"
PORT=54321
if [ -f "$CFG_FILE" ]; then
    CFG_PORT=$(grep -o '"listen_port": *[0-9]*' "$CFG_FILE" 2>/dev/null | grep -o '[0-9]*')
    if [ -n "$CFG_PORT" ]; then
        PORT="$CFG_PORT"
    fi
fi

echo "=========================================="
echo "      СТАТУС СЛУЖБЫ VPN SPOOF PROXY      "
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

PIDS=$(pgrep -f "[m]ain.py proxy" 2>/dev/null || true)
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
