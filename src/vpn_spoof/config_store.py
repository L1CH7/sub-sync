import json
from pathlib import Path
from typing import Dict, Any, Optional

DEFAULT_CONFIG_PATH = Path(__file__).absolute().parent.parent.parent / "data" / "config.json"

class ConfigStore:
    def __init__(self, config_path: Optional[Path] = None):
        self.path = config_path or DEFAULT_CONFIG_PATH

    def load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def save(self, data: Dict[str, Any]):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def update_target_url(self, target_url: str):
        cfg = self.load()
        cfg["target_url"] = target_url
        if "listen_port" not in cfg:
            cfg["listen_port"] = 54321
        self.save(cfg)

    def update_headers(self, headers: Dict[str, str]):
        cfg = self.load()
        cfg["headers"] = headers
        self.save(cfg)
