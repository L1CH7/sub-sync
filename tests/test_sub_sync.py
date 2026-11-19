import base64
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from vpn_spoof.config_store import ConfigStore
from vpn_spoof.proxy_service import SpoofProxyServer, SubscriptionCache
from vpn_spoof.sub_converter import (
    build_clash_yaml,
    build_raw_uris,
    build_xray_configs,
    decode_xray_payload,
    format_userinfo_summary,
    parse_userinfo,
)


SAMPLE_XRAY_JSON = [
    {
        "remarks": "🇺🇸 USA #1",
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "us1.example.com",
                            "port": 443,
                            "users": [{"id": "11111111-1111-1111-1111-111111111111", "flow": "xtls-rprx-vision"}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {"serverName": "us1.example.com", "publicKey": "pub1", "shortId": "aa", "fingerprint": "firefox"},
                    "finalmask": {"tcp": [{"type": "fragment"}]},
                },
            }
        ],
    },
    {
        "remarks": "🇷🇺 Moscow #1 🔀 GRPC",
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "ru1.example.com",
                            "port": 7443,
                            "users": [{"id": "11111111-1111-1111-1111-111111111111", "flow": ""}],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "grpc",
                    "grpcSettings": {"serviceName": ""},
                    "security": "reality",
                    "realitySettings": {"serverName": "ru1.example.com", "publicKey": "pub2", "shortId": "bb", "fingerprint": "firefox"},
                    "finalmask": {"tcp": [{"type": "fragment"}]},
                },
            }
        ],
    },
    {
        "remarks": "⌛️Дней осталось: 183",
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{"address": "sub1.example.com", "port": 10443, "users": [{"id": "111"}]}]},
                "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "info.example.com", "publicKey": "pub3", "shortId": "cc"}},
            }
        ],
    },
]


class TestSubSync(unittest.TestCase):
    def test_config_store_multi_subs(self):
        cfg = {
            "target_url": "https://a.test/sub1",
            "headers": {"User-Agent": "Happ/4.14.0"},
            "extra_subscriptions": [
                {"id": "2", "label": "WL", "target_url": "https://b.test/sub2"}
            ],
        }
        subs = ConfigStore.get_subscriptions(cfg)
        self.assertEqual(len(subs), 2)
        self.assertEqual(subs[0]["id"], "1")
        self.assertEqual(subs[1]["id"], "2")
        self.assertEqual(subs[1]["label"], "WL")
        self.assertEqual(subs[1]["headers"]["User-Agent"], "Happ/4.14.0")

    def test_userinfo_parsing_and_formatting(self):
        ui_unlim = parse_userinfo("upload=0; download=10737418240; total=0; expire=1810807820")
        txt_unlim = format_userinfo_summary("main", ui_unlim)
        self.assertIn("Безлимит", txt_unlim)
        self.assertIn("10.0 ГБ", txt_unlim)

        ui_lim = parse_userinfo("upload=0; download=10737418240; total=53687091200; expire=0")
        txt_lim = format_userinfo_summary("WL", ui_lim)
        self.assertIn("Ост. 40.0/50.0 ГБ", txt_lim)

    def test_decode_base64_uris(self):
        raw = "\n".join([
            "vless://22222222-2222-2222-2222-222222222222@wl1.example.ru:443?type=tcp&security=reality&pbk=pk&sid=12&sni=ya.ru&fp=firefox#WL%20Node",
            "hysteria2://secret@hy.example.com:443?sni=hy.example.com#HY%20Node",
        ])
        b64 = base64.b64encode(raw.encode("utf-8")).decode("ascii").encode("ascii")
        configs = decode_xray_payload(b64)
        self.assertEqual(len(configs), 2)
        self.assertEqual(configs[0]["remarks"], "WL Node")
        self.assertEqual(configs[1]["outbounds"][0]["protocol"], "hysteria")

    def test_build_clash_yaml_flat_layout_and_mlkem768(self):
        extra_multi = {
            "remarks": "🇩🇪 Germany Multi",
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "de1.example.com", "port": 443, "users": [{"id": "111"}]}]},
                    "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "de1.example.com", "publicKey": "p", "shortId": "aa"}},
                },
                {
                    "tag": "proxy-2",
                    "protocol": "vless",
                    "settings": {"vnext": [{"address": "de2.example.com", "port": 443, "users": [{"id": "111"}]}]},
                    "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "de2.example.com", "publicKey": "p2", "shortId": "bb"}},
                },
            ],
        }
        payloads = [
            {
                "id": "1",
                "label": "main",
                "configs": SAMPLE_XRAY_JSON + [extra_multi],
                "headers": {"Subscription-Userinfo": "upload=0; download=1073741824; total=0; expire=0"},
            },
            {
                "id": "2",
                "label": "WL",
                "configs": decode_xray_payload(
                    b"vless://22222222-2222-2222-2222-222222222222@wl1.example.ru:443?type=tcp&security=reality&pbk=pk&sid=12#RU-WL"
                ),
                "headers": {"Subscription-Userinfo": "upload=0; download=0; total=10737418240; expire=0"},
            },
        ]
        clash_cfg = {
            "entry_subscription_ids": ["2"],
            "entry_match": "Moscow",
            "exclude_nodes": "Germany Multi",
            "groups": [
                {"name": "🇺🇸 США", "match": "USA", "bridge": True},
                {"name": "🇷🇺 РФ", "match": "Moscow|\\[WL\\]", "bridge": False},
            ],
        }
        yaml_text = build_clash_yaml(payloads, clash_cfg)
        self.assertIn("⌛️Дней осталось: 183", yaml_text)
        self.assertIn("Безлимит", yaml_text)
        self.assertIn("Ост. 10.0/10.0 ГБ", yaml_text)
        self.assertIn('name: "🌍 2. Выход (Сервер)"', yaml_text)
        self.assertIn('name: "✈️ 1. Вход (Шаг 1)"', yaml_text)
        self.assertIn('name: "⚡ Авто · Вход"', yaml_text)
        self.assertIn("hidden: true", yaml_text)
        self.assertIn("support-x25519mlkem768: true", yaml_text)
        self.assertIn('client-fingerprint: "chrome"', yaml_text)
        self.assertIn('dialer-proxy: "✈️ 1. Вход (Шаг 1)"', yaml_text)
        self.assertIn("MATCH,🌍 2. Выход (Сервер)", yaml_text)
        self.assertNotIn("Germany Multi", yaml_text)
        self.assertNotIn("proxy-2", yaml_text)
        self.assertNotIn("[Мост] ", yaml_text)

        # Проверяем, что входные узлы (Moscow, WL) не дублируются в списке выхода
        exit_section = yaml_text.split('name: "🌍 2. Выход (Сервер)"')[1].split('name: "✈️ 1. Вход (Шаг 1)"')[0]
        self.assertIn("USA #1", exit_section)
        self.assertNotIn("Moscow #1", exit_section)
        self.assertNotIn("RU-WL", exit_section)

    def test_build_clash_yaml_grouped_layout_preserves_info_and_has_no_auto_exit(self):
        payloads = [
            {
                "id": "1",
                "label": "main",
                "configs": SAMPLE_XRAY_JSON,
                "headers": {"Subscription-Userinfo": "upload=0; download=1073741824; total=0; expire=0"},
            },
            {
                "id": "2",
                "label": "WL",
                "configs": decode_xray_payload(
                    b"vless://22222222-2222-2222-2222-222222222222@wl1.example.ru:443?type=tcp&security=reality&pbk=pk&sid=12#RU-WL"
                ),
                "headers": {"Subscription-Userinfo": "upload=0; download=0; total=10737418240; expire=0"},
            },
        ]
        clash_cfg = {
            "layout": "grouped",
            "entry_subscription_ids": ["2"],
            "entry_match": "Moscow",
            "groups": [
                {"name": "🇺🇸 США", "match": "USA", "bridge": True},
                {"name": "🇷🇺 РФ", "match": "Moscow|\\[WL\\]", "bridge": False},
            ],
        }
        yaml_text = build_clash_yaml(payloads, clash_cfg)
        self.assertIn("⌛️Дней осталось: 183", yaml_text)
        self.assertIn("Безлимит", yaml_text)
        self.assertIn("Ост. 10.0/10.0 ГБ", yaml_text)
        self.assertIn("⚡ Авто · Вход", yaml_text)
        self.assertIn("hidden: true", yaml_text)
        self.assertIn("🌉 🇺🇸 США", yaml_text)
        self.assertIn("🛡️ Режим", yaml_text)
        self.assertIn('dialer-proxy: "✈️ 1. Вход (Шаг 1)"', yaml_text)
        self.assertNotIn("Авто · США", yaml_text)
        self.assertNotIn("Авто · ВСЕ", yaml_text)

    def test_build_xray_inline_chains_strips_finalmask(self):
        payloads = [{"id": "1", "label": "main", "configs": SAMPLE_XRAY_JSON, "headers": {}}]
        chains = [{"name": "🌉 МСК ➔ США #1", "via": "Moscow #1.*GRPC", "to": "USA #1"}]
        out = build_xray_configs(payloads, chains)
        self.assertEqual(len(out), 4)
        chained = out[-1]
        self.assertEqual(chained["remarks"], "🌉 МСК ➔ США #1")
        self.assertEqual(chained["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"], "chain_entry")
        self.assertNotIn("finalmask", chained["outbounds"][0]["streamSettings"])
        self.assertNotIn("finalmask", chained["outbounds"][1]["streamSettings"])
        self.assertEqual(chained["outbounds"][1]["tag"], "chain_entry")

    def test_build_raw_uris(self):
        payloads = [{"id": "1", "label": "main", "configs": SAMPLE_XRAY_JSON, "headers": {}}]
        b64 = build_raw_uris(payloads)
        decoded = base64.b64decode(b64).decode("utf-8")
        self.assertIn("vless://", decoded)
        self.assertIn("us1.example.com:443", decoded)

    def test_cache_fresh_stale_and_retries(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = SubscriptionCache(Path(tmp))
            sub_cfg = {"id": "1", "target_url": "https://example.test/sub", "headers": {}}

            calls = {"n": 0}

            def flaky_fetch(url, headers, timeout_sec):
                calls["n"] += 1
                if calls["n"] < 3:
                    raise TimeoutError("simulated timeout")
                return b"[]", {"Subscription-Userinfo": "total=0"}

            with patch.object(SubscriptionCache, "_fetch_once", side_effect=flaky_fetch):
                body, _, status, _ = cache.get_payload(sub_cfg, {"ttl_sec": 60, "timeout_sec": 1.0, "retries": 3})
                self.assertEqual(body, b"[]")
                self.assertEqual(status, "fetched")
                self.assertEqual(calls["n"], 3)

                # Fresh hit does not call upstream
                _, _, status2, _ = cache.get_payload(sub_cfg, {"ttl_sec": 60, "timeout_sec": 1.0, "retries": 3})
                self.assertEqual(status2, "fresh")
                self.assertEqual(calls["n"], 3)

            # Stale cache falls back immediately when upstream times out
            with patch.object(SubscriptionCache, "_fetch_once", side_effect=TimeoutError("down")):
                body3, _, status3, _ = cache.get_payload(sub_cfg, {"ttl_sec": 0, "timeout_sec": 1.0, "retries": 2})
                self.assertEqual(body3, b"[]")
                self.assertEqual(status3, "stale-cache")
                time.sleep(0.2)

    def test_route_resolution(self):
        self.assertEqual(SpoofProxyServer._resolve_route("/sub", {}, "Happ/4.14.0", 2), ("sub", "1", "xray"))
        self.assertEqual(SpoofProxyServer._resolve_route("/sub", {}, "clash-verge/2.0", 2), ("sub", "merged", "clash"))
        self.assertEqual(SpoofProxyServer._resolve_route("/sub/1/clash", {}, "curl/8.0", 2), ("sub", "1", "clash"))
        self.assertEqual(SpoofProxyServer._resolve_route("/sub/2/xray", {}, "Happ/4.14", 2), ("sub", "2", "xray"))
        self.assertEqual(SpoofProxyServer._resolve_route("/sub/merged/raw", {}, "curl", 2), ("sub", "merged", "raw"))
        self.assertEqual(SpoofProxyServer._resolve_route("/api/status", {}, "curl", 2), ("status", "", ""))


if __name__ == "__main__":
    unittest.main()
