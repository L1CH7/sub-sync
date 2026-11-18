import http.server
import json
import signal
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config_store import ConfigStore
from .key_listener import wait_for_cancel
from .sub_converter import (
    build_clash_yaml,
    build_raw_uris,
    build_xray_configs,
    decode_xray_payload,
    format_userinfo_summary,
    parse_userinfo,
)

FORWARD_HEADERS = [
    "Content-Type",
    "subscription-userinfo",
    "Subscription-Userinfo",
    "Subscription-UserInfo",
    "profile-update-interval",
    "Profile-Update-Interval",
    "profile-title",
    "Profile-Title",
    "subscription-refill-date",
    "Subscription-Refill-Date",
]


class ReusableHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class SubscriptionCache:
    """Управляет локальным кэшем подписок с метками времени и повторными попытками."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.cache_dir = data_dir / "cache"
        self.legacy_dump = data_dir / "last_response.yaml"
        self._lock = threading.Lock()
        self._refreshing: set = set()

    def _paths(self, sub_id: str) -> Tuple[Path, Path]:
        safe_id = "".join(ch for ch in str(sub_id) if ch.isalnum() or ch in ("-", "_")) or "1"
        return self.cache_dir / f"sub_{safe_id}.bin", self.cache_dir / f"sub_{safe_id}.meta.json"

    def read_cache(self, sub_id: str) -> Tuple[Optional[bytes], Dict[str, Any]]:
        """Читает тело ответа и метаданные с диска."""
        bin_path, meta_path = self._paths(sub_id)
        if bin_path.exists() and bin_path.stat().st_size > 0:
            meta: Dict[str, Any] = {}
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                except Exception:
                    meta = {}
            return bin_path.read_bytes(), meta

        if str(sub_id) == "1" and self.legacy_dump.exists() and self.legacy_dump.stat().st_size > 0:
            mtime = self.legacy_dump.stat().st_mtime
            return self.legacy_dump.read_bytes(), {"fetched_at": mtime, "headers": {}}

        return None, {}

    def write_cache(self, sub_id: str, body: bytes, headers: Dict[str, str]) -> float:
        """Сохраняет ответ подписки и время получения на диск."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        bin_path, meta_path = self._paths(sub_id)
        now = time.time()
        meta = {"fetched_at": now, "headers": headers}
        bin_path.write_bytes(body)
        meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

        if str(sub_id) == "1":
            try:
                self.legacy_dump.parent.mkdir(parents=True, exist_ok=True)
                self.legacy_dump.write_bytes(body)
            except Exception:
                pass
        return now

    @staticmethod
    def _fetch_once(url: str, headers: Dict[str, str], timeout_sec: float) -> Tuple[bytes, Dict[str, str]]:
        req = urllib.request.Request(url, headers=headers)
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, context=ctx, timeout=timeout_sec) as resp:
            body = resp.read()
            resp_headers = {h: resp.headers.get(h) for h in FORWARD_HEADERS if resp.headers.get(h)}
            return body, resp_headers

    def _fetch_with_retries(
        self,
        sub_cfg: Dict[str, Any],
        timeout_sec: float,
        retries: int,
    ) -> Tuple[bytes, Dict[str, str], float]:
        last_err: Optional[Exception] = None
        for attempt in range(1, retries + 1):
            try:
                body, resp_headers = self._fetch_once(sub_cfg["target_url"], sub_cfg.get("headers", {}), timeout_sec)
                fetched_at = self.write_cache(sub_cfg["id"], body, resp_headers)
                return body, resp_headers, fetched_at
            except Exception as exc:
                last_err = exc
                if attempt < retries:
                    time.sleep(min(0.5 * attempt, 2.0))
        raise last_err or RuntimeError("Upstream fetch failed")

    def _schedule_background_refresh(self, sub_cfg: Dict[str, Any], timeout_sec: float, retries: int) -> None:
        sub_id = str(sub_cfg["id"])
        with self._lock:
            if sub_id in self._refreshing:
                return
            self._refreshing.add(sub_id)

        def _worker():
            try:
                self._fetch_with_retries(sub_cfg, max(timeout_sec, 6.0), retries)
                print(f"[+] Фоновое обновление подписки [{sub_id}] завершено успешно.")
            except Exception as exc:
                print(f"[-] Фоновое обновление подписки [{sub_id}] не удалось: {exc}")
            finally:
                with self._lock:
                    self._refreshing.discard(sub_id)

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    def get_payload(
        self,
        sub_cfg: Dict[str, Any],
        cache_cfg: Dict[str, Any],
        force_refresh: bool = False,
    ) -> Tuple[bytes, Dict[str, str], str, float]:
        """Возвращает данные подписки с проверкой свежести, ретраями и защитой от таймаутов клиента."""
        sub_id = str(sub_cfg["id"])
        cached_body, meta = self.read_cache(sub_id)
        fetched_at = float(meta.get("fetched_at", 0.0))
        cached_headers = meta.get("headers", {})
        age = time.time() - fetched_at if fetched_at else float("inf")

        if cached_body and not force_refresh and age < cache_cfg["ttl_sec"]:
            return cached_body, cached_headers, "fresh", fetched_at

        if cached_body and not force_refresh:
            # Быстрая попытка уложиться до таймаута клиента; при сбое отдаем кэш и докручиваем ретраи в фоне
            fast_timeout = min(float(cache_cfg["timeout_sec"]), 5.0)
            try:
                body, resp_headers, new_ts = self._fetch_with_retries(sub_cfg, fast_timeout, 1)
                return body, resp_headers, "refreshed", new_ts
            except Exception as exc:
                print(f"[!] Подписка [{sub_id}] не ответила вовремя ({exc}), отдаем кэш и обновляем в фоне.")
                self._schedule_background_refresh(sub_cfg, float(cache_cfg["timeout_sec"]), int(cache_cfg["retries"]))
                return cached_body, cached_headers, "stale-cache", fetched_at

        # Принудительное обновление или холодный старт без кэша
        try:
            body, resp_headers, new_ts = self._fetch_with_retries(
                sub_cfg,
                float(cache_cfg["timeout_sec"]),
                int(cache_cfg["retries"]),
            )
            return body, resp_headers, "fetched", new_ts
        except Exception:
            if cached_body:
                return cached_body, cached_headers, "stale-cache", fetched_at
            raise


class SpoofProxyServer:
    """Локальный HTTP-шлюз подписок с поддержкой форматов Xray, Clash/Mihomo и Raw."""

    def __init__(
        self,
        listen_port: Optional[int] = None,
        host: str = "127.0.0.1",
        config_store: Optional[ConfigStore] = None,
    ):
        self.config_store = config_store or ConfigStore()
        cfg = self.config_store.load()
        self.listen_port = listen_port if listen_port is not None else int(cfg.get("listen_port", 54321))
        self.host = cfg.get("listen_host", host) if host == "127.0.0.1" and cfg.get("listen_host") else host
        self.cache = SubscriptionCache(self.config_store.path.parent)

    @staticmethod
    def _detect_format_by_ua(user_agent: str) -> str:
        ua = (user_agent or "").lower()
        if any(k in ua for k in ("clash", "mihomo", "verge", "flclash", "stash")):
            return "clash"
        return "xray"

    @staticmethod
    def _resolve_route(path: str, query_params: Dict[str, List[str]], user_agent: str, sub_count: int) -> Tuple[str, str, str]:
        """Определяет тип маршрута ('status' | 'sub'), источник ('1', 'merged', ...) и формат."""
        clean = "/" + path.strip("/")
        if clean == "/api/status":
            return "status", "", ""

        q_fmt = (query_params.get("format") or [""])[0].lower()
        auto_fmt = q_fmt if q_fmt in ("clash", "xray", "raw") else SpoofProxyServer._detect_format_by_ua(user_agent)

        if clean in ("/clash", "/xray", "/raw"):
            src = "merged" if sub_count > 1 else "1"
            return "sub", src, clean.lstrip("/")

        if clean in ("/", "/sub"):
            src = "merged" if (auto_fmt == "clash" and sub_count > 1) else "1"
            return "sub", src, auto_fmt

        parts = [p for p in clean.split("/") if p]
        if len(parts) >= 2 and parts[0] == "sub":
            src = "merged" if parts[1] in ("merged", "all") else parts[1]
            fmt = parts[2].lower() if len(parts) >= 3 else auto_fmt
            if fmt not in ("clash", "xray", "raw"):
                fmt = auto_fmt
            return "sub", src, fmt

        return "not_found", "", ""

    def create_handler(self):
        parent = self

        class SpoofHandler(http.server.BaseHTTPRequestHandler):
            def _send_bytes(self, status: int, content_type: str, body: bytes, extra_headers: Optional[Dict[str, str]] = None):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Access-Control-Allow-Origin", "*")
                if extra_headers:
                    for k, v in extra_headers.items():
                        if k.lower() != "content-type" and v:
                            self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _handle_status(self, cfg: Dict[str, Any]):
                subs = parent.config_store.get_subscriptions(cfg)
                items = []
                for s in subs:
                    body, meta = parent.cache.read_cache(s["id"])
                    fetched_at = float(meta.get("fetched_at", 0.0))
                    headers = meta.get("headers", {})
                    ui = parse_userinfo(headers.get("Subscription-Userinfo", "") or headers.get("subscription-userinfo", ""))
                    count = 0
                    if body:
                        try:
                            count = len(decode_xray_payload(body))
                        except Exception:
                            count = 0
                    items.append({
                        "id": s["id"],
                        "label": s["label"],
                        "cached": body is not None,
                        "fetched_at": fetched_at,
                        "age_sec": round(time.time() - fetched_at, 1) if fetched_at else None,
                        "config_count": count,
                        "userinfo": ui,
                        "userinfo_text": format_userinfo_summary(s["label"], ui),
                    })
                payload = json.dumps({
                    "listen_port": parent.listen_port,
                    "subscriptions": items,
                }, ensure_ascii=False, indent=2).encode("utf-8")
                self._send_bytes(200, "application/json; charset=utf-8", payload)

            def do_GET(self):
                cfg = parent.config_store.load()
                subs = parent.config_store.get_subscriptions(cfg)
                if not subs:
                    self.send_error(500, "Target URL missing in config.json. Run link capture first.")
                    return

                parsed = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(parsed.query)
                ua = self.headers.get("User-Agent", "")
                kind, src, fmt = parent._resolve_route(parsed.path, qs, ua, len(subs))

                if kind == "not_found":
                    self.send_error(404, f"Unknown route: {parsed.path}")
                    return

                if kind == "status":
                    self._handle_status(cfg)
                    return

                force_refresh = (qs.get("refresh") or ["0"])[0].lower() in ("1", "true", "yes")
                cache_cfg = parent.config_store.get_cache_settings(cfg)

                if src == "merged":
                    selected_subs = subs
                else:
                    selected_subs = [s for s in subs if s["id"] == src]
                    if not selected_subs:
                        self.send_error(404, f"Subscription '{src}' not found in config")
                        return

                payloads: List[Dict[str, Any]] = []
                cache_statuses: List[str] = []
                fetched_timestamps: List[float] = []

                for s in selected_subs:
                    try:
                        body, hdrs, c_status, f_ts = parent.cache.get_payload(s, cache_cfg, force_refresh=force_refresh)
                    except urllib.error.HTTPError as he:
                        self._send_bytes(he.code, "text/plain; charset=utf-8", he.read())
                        return
                    except Exception as exc:
                        self._send_bytes(502, "text/plain; charset=utf-8", str(exc).encode("utf-8"))
                        return

                    cache_statuses.append(f"{s['id']}:{c_status}")
                    fetched_timestamps.append(f_ts)
                    payloads.append({
                        "id": s["id"],
                        "label": s["label"],
                        "raw_bytes": body,
                        "headers": hdrs,
                        "configs": decode_xray_payload(body) if (fmt != "xray" or len(selected_subs) > 1 or cfg.get("xray_chains")) else [],
                    })

                resp_headers: Dict[str, str] = {
                    "X-SubSync-Cache": ", ".join(cache_statuses),
                    "X-SubSync-Fetched-At": str(int(max(fetched_timestamps))) if fetched_timestamps else "0",
                }
                if len(payloads) == 1:
                    for h in FORWARD_HEADERS:
                        if h.lower() != "content-type" and payloads[0]["headers"].get(h):
                            resp_headers[h] = payloads[0]["headers"][h]

                if fmt == "clash":
                    clash_cfg = cfg.get("clash", {}) if isinstance(cfg.get("clash"), dict) else {}
                    yaml_body = build_clash_yaml(payloads, clash_cfg).encode("utf-8")
                    self._send_bytes(200, "text/yaml; charset=utf-8", yaml_body, resp_headers)
                    print(f"[+] GET {parsed.path} -> clash ({len(yaml_body)} байт, {resp_headers['X-SubSync-Cache']})")
                    return

                if fmt == "raw":
                    clash_cfg = cfg.get("clash", {}) if isinstance(cfg.get("clash"), dict) else {}
                    prefix_labels = bool(clash_cfg.get("prefix_merged_labels", True))
                    raw_b64 = build_raw_uris(payloads, prefix_merged_labels=prefix_labels).encode("utf-8")
                    self._send_bytes(200, "text/plain; charset=utf-8", raw_b64, resp_headers)
                    print(f"[+] GET {parsed.path} -> raw ({len(raw_b64)} байт, {resp_headers['X-SubSync-Cache']})")
                    return

                # Формат xray: без модификаций для одиночной подписки без xray_chains
                xray_chains = cfg.get("xray_chains", []) if isinstance(cfg.get("xray_chains"), list) else []
                if len(payloads) == 1 and not xray_chains:
                    raw_bytes = payloads[0]["raw_bytes"]
                    self._send_bytes(200, "application/json; charset=utf-8", raw_bytes, resp_headers)
                    print(f"[+] GET {parsed.path} -> xray-passthrough ({len(raw_bytes)} байт, {resp_headers['X-SubSync-Cache']})")
                    return

                clash_cfg = cfg.get("clash", {}) if isinstance(cfg.get("clash"), dict) else {}
                prefix_labels = bool(clash_cfg.get("prefix_merged_labels", True))
                xray_list = build_xray_configs(payloads, xray_chains, prefix_merged_labels=prefix_labels)
                xray_bytes = json.dumps(xray_list, ensure_ascii=False).encode("utf-8")
                self._send_bytes(200, "application/json; charset=utf-8", xray_bytes, resp_headers)
                print(f"[+] GET {parsed.path} -> xray ({len(xray_list)} конфигов, {resp_headers['X-SubSync-Cache']})")

            def log_message(self, format, *args):
                return

        return SpoofHandler

    def run(self):
        handler = self.create_handler()
        try:
            server = ReusableHTTPServer((self.host, self.listen_port), handler)
        except OSError as e:
            if getattr(e, "errno", None) == 98 or "already in use" in str(e).lower():
                print(f"\n[-] Ошибка: Порт {self.listen_port} уже занят другим процессом!")
                print("[-] Возможно, фоновая служба автозапуска уже работает. Проверьте статус в меню [2].\n")
                return
            raise

        base = f"http://{self.host}:{self.listen_port}"
        print(f"[*] VPN Spoof Proxy запущен на {base}")
        print(f"[!] Happ / автовыбор:  {base}/sub")
        print(f"[!] Clash Verge Rev:   {base}/sub/merged/clash  (или {base}/sub/1/clash)")
        print(f"[!] Raw Base64 URI:    {base}/sub/merged/raw")
        print(f"[!] Статус кэша/квот:  {base}/api/status\n")
        print("Нажмите 'q' для возврата в меню | Ctrl+C для выхода из программы...\n")

        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        stop_ev = threading.Event()
        try:
            def _sig_handler(signum, frame):
                stop_ev.set()

            signal.signal(signal.SIGTERM, _sig_handler)
            signal.signal(signal.SIGINT, _sig_handler)
        except Exception:
            pass

        try:
            res = wait_for_cancel(stop_ev)
            if res == "back":
                print("\n[!] Остановка прокси и возврат в главное меню...")
        finally:
            server.shutdown()
            server.server_close()


def main():
    proxy = SpoofProxyServer()
    proxy.run()


if __name__ == "__main__":
    main()
