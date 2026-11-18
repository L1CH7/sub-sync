import json
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_CONFIG_PATH = Path(__file__).absolute().parent.parent.parent / "data" / "config.json"

DEFAULT_CACHE_SETTINGS: Dict[str, Any] = {
    "ttl_sec": 1800,
    "timeout_sec": 4.0,
    "retries": 3,
}


class ConfigStore:
    """Хранилище конфигурации с обратной совместимостью для TUI."""

    def __init__(self, config_path: Optional[Path] = None):
        self.path = config_path or DEFAULT_CONFIG_PATH

    def load(self) -> Dict[str, Any]:
        """Загружает JSON-конфигурацию или возвращает пустой словарь."""
        if not self.path.exists():
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def save(self, data: Dict[str, Any]):
        """Сохраняет конфигурацию на диск."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def update_target_url(self, target_url: str):
        """Обновляет URL основной подписки (TUI работает с ней)."""
        cfg = self.load()
        cfg["target_url"] = target_url
        if "listen_port" not in cfg:
            cfg["listen_port"] = 54321
        self.save(cfg)

    def update_headers(self, headers: Dict[str, str]):
        """Обновляет заголовки клиента для основной подписки."""
        cfg = self.load()
        cfg["headers"] = headers
        self.save(cfg)

    @staticmethod
    def get_subscriptions(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Возвращает нормализованный список всех настроенных подписок."""
        subs: List[Dict[str, Any]] = []
        primary_headers = cfg.get("headers", {})
        primary_url = cfg.get("target_url")
        if primary_url:
            subs.append({
                "id": "1",
                "label": str(cfg.get("label") or "1"),
                "target_url": primary_url,
                "headers": primary_headers,
            })

        for idx, extra in enumerate(cfg.get("extra_subscriptions", []), start=2):
            if not isinstance(extra, dict) or not extra.get("target_url"):
                continue
            sub_id = str(extra.get("id") or idx)
            subs.append({
                "id": sub_id,
                "label": str(extra.get("label") or sub_id),
                "target_url": extra["target_url"],
                "headers": extra.get("headers") or primary_headers,
            })
        return subs

    @staticmethod
    def get_cache_settings(cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Возвращает параметры кэширования и повторных попыток."""
        raw = cfg.get("cache", {}) if isinstance(cfg.get("cache"), dict) else {}
        return {
            "ttl_sec": int(raw.get("ttl_sec", DEFAULT_CACHE_SETTINGS["ttl_sec"])),
            "timeout_sec": float(raw.get("timeout_sec", DEFAULT_CACHE_SETTINGS["timeout_sec"])),
            "retries": max(1, int(raw.get("retries", DEFAULT_CACHE_SETTINGS["retries"]))),
        }
