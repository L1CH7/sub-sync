import base64
import json
import zlib
from pathlib import Path
from typing import Optional
from .config_store import ConfigStore
from .qr_utils import print_qr_banner, render_solid_terminal_qr

class BundleTransfer:
    def __init__(self):
        self.config_store = ConfigStore()

    def export_bundle_string(self) -> str:
        cfg = self.config_store.load()
        if not cfg.get('target_url') or not cfg.get('headers'):
            raise ValueError('Configuration is incomplete. Please run capture first.')
        raw_json = json.dumps(cfg).encode('utf-8')
        compressed = zlib.compress(raw_json, level=9)
        b64 = base64.urlsafe_b64encode(compressed).decode('utf-8')
        return f"vpnbundle://{b64}"

    def import_bundle_string(self, bundle_str: str) -> dict:
        clean_str = bundle_str.strip()
        if clean_str.startswith('vpnbundle://'):
            clean_str = clean_str[len('vpnbundle://'):]
        
        try:
            compressed = base64.urlsafe_b64decode(clean_str.encode('utf-8'))
            raw_json = zlib.decompress(compressed).decode('utf-8')
            data = json.loads(raw_json)
        except Exception:
            data = json.loads(clean_str)

        if not isinstance(data, dict) or 'target_url' not in data:
            raise ValueError('Invalid bundle format.')

        self.config_store.save(data)
        return data

    def print_export_qr(self):
        bundle = self.export_bundle_string()
        print_qr_banner('📦 QR ДЛЯ ПЕРЕНОСА КОНФИГА НА ДРУГОЙ ПК', bundle)
        print('Или скопируйте строку бандла:')
        print(f'{bundle}\n')
