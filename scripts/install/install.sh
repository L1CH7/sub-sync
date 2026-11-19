#!/usr/bin/env bash
set -euo pipefail

DEFAULT_REPO_URL="${SUBSYNC_REPO_URL:-https://github.com/L1CH7/sub-sync.git}"
REPO_URL="$DEFAULT_REPO_URL"
BRANCH="${SUBSYNC_BRANCH:-master}"
TARGET_DIR=""
PORT=""
SERVICE_NAME="${SUBSYNC_SERVICE_NAME:-vpn-spoof.service}"
TUI_MODE="ask"

print_help() {
    cat << 'EOF'
Установщик и авто-обновитель SubSync

Использование:
  curl -fsSL https://raw.githubusercontent.com/L1CH7/sub-sync/master/scripts/install/install.sh | bash
  curl -fsSL ... | bash -s -- [ПАРАМЕТРЫ]

Параметры:
  --dir <путь>            Каталог установки (по умолчанию определяется по прошлой установке или ~/.local/share/sub-sync)
  --port <порт>           Переопределить listen_port (например, 54322 для изолированного теста)
  --service-name <имя>    Имя systemd-службы (по умолчанию vpn-spoof.service)
  --branch <ветка>        Ветка или тег Git (по умолчанию master)
  --repo-url <url>        URL или локальный путь Git-репозитория
  --no-tui                Не спрашивать о запуске TUI после установки
  --tui                   Принудительно запустить TUI после установки
  -h, --help              Показать эту справку
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)
            TARGET_DIR="$2"
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
        --branch)
            BRANCH="$2"
            shift 2
            ;;
        --repo-url)
            REPO_URL="$2"
            shift 2
            ;;
        --no-tui)
            TUI_MODE="no"
            shift
            ;;
        --tui)
            TUI_MODE="yes"
            shift
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            echo "[-] Неизвестный параметр: $1"
            print_help
            exit 1
            ;;
    esac
done

[[ "$SERVICE_NAME" == *.service ]] || SERVICE_NAME="${SERVICE_NAME}.service"
STATE_HOME="${XDG_CONFIG_HOME:-$HOME/.config}/subsync"
POINTER_FILE="$STATE_HOME/${SERVICE_NAME}.path"

detect_existing_dir() {
    if [ -f "$POINTER_FILE" ]; then
        local saved
        saved="$(tr -d '\r\n' < "$POINTER_FILE" || true)"
        if [ -n "$saved" ] && [ -f "$saved/main.py" ]; then
            echo "$saved"
            return 0
        fi
    fi

    local unit_file="$HOME/.config/systemd/user/$SERVICE_NAME"
    if [ -f "$unit_file" ]; then
        local wd
        wd="$(grep -E '^WorkingDirectory=' "$unit_file" 2>/dev/null | head -n1 | cut -d= -f2- || true)"
        if [ -n "$wd" ] && [ -f "$wd/main.py" ]; then
            echo "$wd"
            return 0
        fi
    fi

    local desktop_file="$HOME/.config/autostart/${SERVICE_NAME%.service}.desktop"
    if [ -f "$desktop_file" ]; then
        local cd_path
        cd_path="$(sed -n "s/.*cd '\([^']*\)'.*/\1/p" "$desktop_file" 2>/dev/null | head -n1 || true)"
        if [ -n "$cd_path" ] && [ -f "$cd_path/main.py" ]; then
            echo "$cd_path"
            return 0
        fi
    fi

    if [ -f "$PWD/main.py" ] && [ -f "$PWD/pyproject.toml" ]; then
        echo "$PWD"
        return 0
    fi
    return 1
}

nearest_existing_ancestor() {
    local p="$1"
    while [ ! -e "$p" ]; do
        local parent
        parent="$(dirname "$p")"
        [ "$parent" = "$p" ] && break
        p="$parent"
    done
    echo "$p"
}

run_priv() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
        return
    fi
    if ! command -v sudo >/dev/null 2>&1; then
        echo "[-] Недостаточно прав для $TARGET_DIR, а утилита sudo не найдена."
        exit 1
    fi
    sudo "$@"
}

ensure_writable_target_dir() {
    local target="$1"
    if [ ! -d "$target" ]; then
        local ancestor
        ancestor="$(nearest_existing_ancestor "$target")"
        if [ -w "$ancestor" ]; then
            mkdir -p "$target"
        else
            echo "[*] Каталог $(dirname "$target") требует прав администратора — запрашиваю sudo..."
            run_priv mkdir -p "$target"
            run_priv chown -R "$(id -un):$(id -gn)" "$target"
        fi
    elif [ ! -w "$target" ]; then
        echo "[*] Каталог $target недоступен на запись — передаю права пользователю $(id -un) через sudo..."
        run_priv chown -R "$(id -un):$(id -gn)" "$target"
    fi
}

if [ -z "$TARGET_DIR" ]; then
    if EXISTING_DIR="$(detect_existing_dir)"; then
        TARGET_DIR="$EXISTING_DIR"
    else
        TARGET_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/sub-sync"
    fi
fi

[[ "$TARGET_DIR" == /* ]] || TARGET_DIR="$PWD/$TARGET_DIR"
while [ "$TARGET_DIR" != "/" ] && [[ "$TARGET_DIR" == */ ]]; do
    TARGET_DIR="${TARGET_DIR%/}"
done

echo "=================================================="
echo "  SubSync — установка и обновление"
echo "=================================================="
echo "[*] Целевой каталог : $TARGET_DIR"
echo "[*] Служба          : $SERVICE_NAME"
echo "[*] Источник        : $REPO_URL ($BRANCH)"

# 1. Проверка / установка uv
export PATH="$HOME/.local/bin:$PATH"
if ! command -v uv >/dev/null 2>&1; then
    echo "[*] Установка пакетного менеджера uv..."
    if command -v curl >/dev/null 2>&1; then
        curl -LsSf https://astral.sh/uv/install.sh | sh
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- https://astral.sh/uv/install.sh | sh
    else
        echo "[-] Требуется curl или wget для установки uv."
        exit 1
    fi
    export PATH="$HOME/.local/bin:$PATH"
fi
UV_PATH="$(command -v uv)"

# 2. Фиксация старой версии и резервное копирование data/
OLD_VERSION=""
TMP_ROOT="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

STAGING_DIR="$TMP_ROOT/repo"
DATA_BACKUP="$TMP_ROOT/data_backup"

if [ -d "$TARGET_DIR" ]; then
    if [ -f "$TARGET_DIR/VERSION" ]; then
        OLD_VERSION="$(tr -d ' \t\r\n' < "$TARGET_DIR/VERSION")"
    elif [ -f "$TARGET_DIR/main.py" ]; then
        OLD_VERSION="legacy"
    fi

    if [ -n "$OLD_VERSION" ]; then
        echo "[*] Найдена предыдущая версия: $OLD_VERSION — сохраняем данные и обновляем."
    fi

    if [ -d "$TARGET_DIR/data" ]; then
        mkdir -p "$DATA_BACKUP"
        cp -a "$TARGET_DIR/data/." "$DATA_BACKUP/"
    fi
fi

# 3. Загрузка свежей копии репозитория во временный каталог
if command -v git >/dev/null 2>&1; then
    echo "[*] Клонирование репозитория..."
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$STAGING_DIR"
else
    if [[ "$REPO_URL" =~ https://github.com/([^/]+/[^/.]+)(\.git)?$ ]]; then
        SLUG="${BASH_REMATCH[1]}"
        TAR_URL="https://github.com/$SLUG/archive/refs/heads/$BRANCH.tar.gz"
        echo "[*] git не найден, скачиваем архив $TAR_URL..."
        mkdir -p "$STAGING_DIR"
        curl -fsSL "$TAR_URL" | tar -xz -C "$STAGING_DIR" --strip-components=1
    else
        echo "[-] Для загрузки $REPO_URL требуется git."
        exit 1
    fi
fi

# 4. Восстановление пользовательской папки data/ (без перезаписи нового config.example.json)
mkdir -p "$STAGING_DIR/data"
if [ -d "$DATA_BACKUP" ]; then
    for item in "$DATA_BACKUP"/* "$DATA_BACKUP"/.[!.]*; do
        [ -e "$item" ] || continue
        base="$(basename "$item")"
        [ "$base" = "config.example.json" ] && continue
        [ "$base" = ".gitkeep" ] && continue
        cp -a "$item" "$STAGING_DIR/data/"
    done
fi

# 5. Применение --port к config.json при передаче флага
if [ -n "$PORT" ]; then
    "$UV_PATH" run --no-project python - "$STAGING_DIR/data/config.json" "$PORT" << 'PY'
import json, sys
from pathlib import Path

cfg_path = Path(sys.argv[1])
port = int(sys.argv[2])
data = {}
if cfg_path.exists():
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        data = {}
data["listen_port"] = port
cfg_path.parent.mkdir(parents=True, exist_ok=True)
cfg_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
PY
fi

# 6. Проверка прав, остановка старого экземпляра и замена каталога
ensure_writable_target_dir "$TARGET_DIR"

if [ -f "$TARGET_DIR/scripts/service/linux/uninstall_service.sh" ]; then
    systemctl --user stop "$SERVICE_NAME" 2>/dev/null || true
elif [ -f "$TARGET_DIR/src/scripts/linux/uninstall_service.sh" ]; then
    systemctl --user stop "$SERVICE_NAME" 2>/dev/null || true
fi
pkill -f "--config $TARGET_DIR/data/config.json" 2>/dev/null || true

if [ -w "$(dirname "$TARGET_DIR")" ]; then
    rm -rf "$TARGET_DIR"
    mv "$STAGING_DIR" "$TARGET_DIR"
else
    find "$TARGET_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    cp -a "$STAGING_DIR/." "$TARGET_DIR/"
fi

# 7. Установка зависимостей и запись версии/состояния
echo "[*] Синхронизация Python-окружения (uv sync)..."
(cd "$TARGET_DIR" && "$UV_PATH" sync --no-dev 2>/dev/null || "$UV_PATH" sync)

NEW_VERSION="0.0.0"
if [ -f "$TARGET_DIR/VERSION" ]; then
    NEW_VERSION="$(tr -d ' \t\r\n' < "$TARGET_DIR/VERSION")"
fi

EFFECTIVE_PORT="$PORT"
if [ -z "$EFFECTIVE_PORT" ] && [ -f "$TARGET_DIR/data/config.json" ]; then
    EFFECTIVE_PORT="$(grep -o '"listen_port": *[0-9]*' "$TARGET_DIR/data/config.json" 2>/dev/null | head -n1 | grep -o '[0-9]*' || true)"
fi
EFFECTIVE_PORT="${EFFECTIVE_PORT:-54321}"

"$UV_PATH" run --directory "$TARGET_DIR" python - "$TARGET_DIR/data/.install_state.json" "$NEW_VERSION" "$EFFECTIVE_PORT" "$SERVICE_NAME" "$BRANCH" << 'PY'
import json, sys, time
from pathlib import Path

out = Path(sys.argv[1])
state = {
    "version": sys.argv[2],
    "port": int(sys.argv[3]),
    "service_name": sys.argv[4],
    "branch": sys.argv[5],
    "installed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
}
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
PY

mkdir -p "$STATE_HOME"
printf '%s\n' "$TARGET_DIR" > "$POINTER_FILE"

# 8. Переадресация установки службы на локальный скрипт
SVC_SCRIPT="$TARGET_DIR/scripts/service/linux/install_service.sh"
chmod +x "$SVC_SCRIPT" "$TARGET_DIR/scripts/service/linux/status_service.sh" "$TARGET_DIR/scripts/service/linux/uninstall_service.sh" "$TARGET_DIR/scripts/install/install.sh" "$TARGET_DIR/setup.sh"
bash "$SVC_SCRIPT" --dir "$TARGET_DIR" --port "$EFFECTIVE_PORT" --service-name "$SERVICE_NAME"

echo "=================================================="
if [ -n "$OLD_VERSION" ]; then
    echo "[+] Обновление завершено: $OLD_VERSION -> $NEW_VERSION"
else
    echo "[+] Установка завершена: версия $NEW_VERSION"
fi
echo "[*] Каталог: $TARGET_DIR"
echo "[*] Адрес  : http://127.0.0.1:$EFFECTIVE_PORT/sub"
echo "=================================================="

# 9. Предложение открыть TUI
HAS_CONFIG=false
if [ -f "$TARGET_DIR/data/config.json" ] && grep -q '"target_url"' "$TARGET_DIR/data/config.json" 2>/dev/null; then
    HAS_CONFIG=true
fi

if [ "$TUI_MODE" = "yes" ]; then
    if [ -r /dev/tty ]; then
        exec "$UV_PATH" run --directory "$TARGET_DIR" main.py < /dev/tty
    else
        exec "$UV_PATH" run --directory "$TARGET_DIR" main.py
    fi
elif [ "$TUI_MODE" = "ask" ] && [ -r /dev/tty ] && [ -t 1 ]; then
    if [ "$HAS_CONFIG" = true ]; then
        printf "Открыть интерактивный TUI для настройки? [y/N]: " > /dev/tty
        read -r answer < /dev/tty || answer="n"
        answer="${answer:-N}"
    else
        printf "Конфигурация ещё не задана. Открыть TUI для настройки сейчас? [Y/n]: " > /dev/tty
        read -r answer < /dev/tty || answer="y"
        answer="${answer:-Y}"
    fi
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        exec "$UV_PATH" run --directory "$TARGET_DIR" main.py < /dev/tty
    fi
fi
