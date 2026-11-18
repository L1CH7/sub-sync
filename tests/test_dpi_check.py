import datetime
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
REPO_DIR = Path(__file__).resolve().parent.parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from vpn_spoof.dpi_check import (
    FALLBACK_CDN_TARGETS,
    check_dns_hijack,
    check_l4_25,
    check_siberian,
    check_sni_whitelist,
    detect_physical_source_ip,
    extract_targets_from_configs,
    fetch_local_tcp16_catalog,
    get_diag_cache_dir,
    parse_socks5_proxy,
    parse_target,
    run_batch_diagnostics,
    run_cdn_tcp16_check,
)


def _create_ephemeral_tls_context(tmp_dir: Path) -> ssl.SSLContext:
    """Создаёт временный TLS-контекст на 127.0.0.1 без записи файлов в репозиторий."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_dir / "test_cert.pem"
    key_path = tmp_dir / "test_key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


class _LocalTlsBehaviorServer:
    """Локальный TLS/TCP-сервер для имитации чистого канала и ТСПУ-сценариев."""

    def __init__(self, mode: str, ssl_ctx: ssl.SSLContext):
        self.mode = mode
        self.ssl_ctx = ssl_ctx
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _handle_client(self, raw: socket.socket):
        sni_seen = {"name": None}

        def capture_sni(ssl_sock, server_name, _ctx):
            sni_seen["name"] = server_name

        try:
            if self.mode == "sni_whitelist":
                self.ssl_ctx.sni_callback = capture_sni
            tls = self.ssl_ctx.wrap_socket(raw, server_side=True)
        except Exception:
            raw.close()
            return

        try:
            tls.settimeout(2.0)
            first = tls.recv(4096)
            if self.mode == "freeze_after_bytes":
                # Имитация ТСПУ-заморозки после получения первых байт
                time.sleep(1.2)
                return
            if self.mode == "sni_whitelist" and sni_seen["name"] != "ya.ru":
                time.sleep(1.2)
                return
            if first:
                # Дочитываем остаток небольшого запроса, чтобы клиент не словил reset на sendall
                time.sleep(0.05)
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        except Exception:
            pass
        finally:
            try:
                tls.close()
            except Exception:
                pass

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=1.0)


class _LocalSocks5Server:
    """Минимальный SOCKS5-сервер на 127.0.0.1 для проверки туннелирования."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.proxied_targets = []
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @staticmethod
    def _pipe(src: socket.socket, dst: socket.socket):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass

    def _handle(self, client: socket.socket):
        remote = None
        try:
            greeting = client.recv(16)
            if not greeting.startswith(b"\x05"):
                return
            client.sendall(b"\x05\x00")
            req = client.recv(256)
            atyp = req[3]
            if atyp == 1:
                dst_host = socket.inet_ntoa(req[4:8])
                dst_port = struct.unpack(">H", req[8:10])[0]
            elif atyp == 3:
                alen = req[4]
                dst_host = req[5:5 + alen].decode("ascii")
                dst_port = struct.unpack(">H", req[5 + alen:7 + alen])[0]
            else:
                return
            self.proxied_targets.append((dst_host, dst_port))
            remote = socket.create_connection((dst_host, dst_port), timeout=2.0)
            client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            t1 = threading.Thread(target=self._pipe, args=(client, remote), daemon=True)
            t2 = threading.Thread(target=self._pipe, args=(remote, client), daemon=True)
            t1.start()
            t2.start()
            t1.join(timeout=2.0)
            t2.join(timeout=2.0)
        except Exception:
            pass
        finally:
            for s in (client, remote):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=1.0)


class _LocalDnsServer:
    """Локальный UDP DNS-ответчик для имитации нормального ответа и подмены."""

    def __init__(self, ip_reply: str | None = None, nxdomain: bool = False):
        self.ip_reply = ip_reply
        self.nxdomain = nxdomain
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                pkt, addr = self.sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break
            tid = pkt[:2]
            idx = 12
            while idx < len(pkt) and pkt[idx] != 0:
                idx += pkt[idx] + 1
            question = pkt[12:idx + 5]
            if self.nxdomain:
                hdr = tid + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00"
                self.sock.sendto(hdr + question, addr)
            else:
                hdr = tid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
                answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(self.ip_reply or "1.2.3.4")
                self.sock.sendto(hdr + question + answer, addr)

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=1.0)


class TestDpiCheckUnit(unittest.TestCase):
    def test_parse_target_and_socks_and_cache_outside_repo(self):
        self.assertEqual(parse_target("example.com"), ("example.com", 443, "example.com"))
        self.assertEqual(parse_target("ru1.example.com:7443"), ("ru1.example.com", 7443, "ru1.example.com"))
        self.assertEqual(parse_target("https://cdn.example.com/path"), ("cdn.example.com", 443, "cdn.example.com"))
        self.assertEqual(parse_socks5_proxy("socks5://127.0.0.1:29555"), ("127.0.0.1", 29555))
        self.assertEqual(parse_socks5_proxy("127.0.0.1:7897"), ("127.0.0.1", 7897))

        default_cache = get_diag_cache_dir()
        self.assertFalse(default_cache.resolve().is_relative_to(REPO_DIR.resolve()))

    def test_extract_targets_from_configs_dedup(self):
        configs = [
            {
                "remarks": "Moscow gRPC",
                "outbounds": [{
                    "settings": {"vnext": [{"address": "ru1.example.com", "port": 7443}]},
                    "streamSettings": {"security": "reality", "realitySettings": {"serverName": "ya.ru"}},
                }],
            },
            {
                "remarks": "Moscow Duplicate",
                "outbounds": [{
                    "settings": {"vnext": [{"address": "ru1.example.com", "port": 7443}]},
                    "streamSettings": {"security": "reality", "realitySettings": {"serverName": "ya.ru"}},
                }],
            },
            {
                "remarks": "USA Vision",
                "outbounds": [{
                    "settings": {"vnext": [{"address": "us1.example.com", "port": 443}]},
                    "streamSettings": {"security": "reality", "realitySettings": {"serverName": "us1.example.com"}},
                }],
            },
        ]
        targets = extract_targets_from_configs(configs)
        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0]["sni"], "ya.ru")
        self.assertEqual(targets[1]["port"], 443)

    def test_l4_25_and_siberian_and_socks5_tunnel(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _create_ephemeral_tls_context(Path(tmp))
            clean_srv = _LocalTlsBehaviorServer("clean", ctx)
            frozen_srv = _LocalTlsBehaviorServer("freeze_after_bytes", ctx)
            socks = _LocalSocks5Server()
            try:
                res_ok = check_l4_25("127.0.0.1", clean_srv.port, "127.0.0.1", payload_bytes=24 * 1024, connect_timeout=1.5, freeze_timeout=1.5)
                self.assertEqual(res_ok["v"], "CLEAN")

                res_socks = check_l4_25(
                    "127.0.0.1",
                    clean_srv.port,
                    "127.0.0.1",
                    payload_bytes=20 * 1024,
                    connect_timeout=1.5,
                    freeze_timeout=1.5,
                    socks_proxy=("127.0.0.1", socks.port),
                )
                self.assertEqual(res_socks["v"], "CLEAN")
                self.assertIn(("127.0.0.1", clean_srv.port), socks.proxied_targets)

                res_frozen = check_l4_25("127.0.0.1", frozen_srv.port, "127.0.0.1", payload_bytes=24 * 1024, connect_timeout=1.5, freeze_timeout=0.35)
                self.assertEqual(res_frozen["v"], "FROZEN")

                sib_ok = check_siberian("127.0.0.1", clean_srv.port, "127.0.0.1", connections=3, stagger_sec=0.02, timeout=1.5)
                self.assertEqual(sib_ok["v"], "CLEAN")
            finally:
                clean_srv.close()
                frozen_srv.close()
                socks.close()

    def test_sni_whitelist_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _create_ephemeral_tls_context(Path(tmp))
            wl_srv = _LocalTlsBehaviorServer("sni_whitelist", ctx)
            try:
                res = check_sni_whitelist("127.0.0.1", wl_srv.port, "blocked.example.com", allowed_sni="ya.ru", timeout=0.4, payload_bytes=4096)
                self.assertEqual(res["v"], "WHITELIST_SNI")
            finally:
                wl_srv.close()

    def test_dns_hijack_detection(self):
        good_a = _LocalDnsServer(ip_reply="93.184.216.34")
        good_b = _LocalDnsServer(ip_reply="93.184.216.34")
        spoof_nx = _LocalDnsServer(nxdomain=True)
        spoof_ip = _LocalDnsServer(ip_reply="10.10.10.10")
        try:
            clean = check_dns_hijack("example.com", resolvers={"A": ("127.0.0.1", good_a.port), "B": ("127.0.0.1", good_b.port)}, timeout=1.0)
            self.assertEqual(clean["v"], "CLEAN")

            spoof1 = check_dns_hijack("example.com", resolvers={"A": ("127.0.0.1", good_a.port), "Bad": ("127.0.0.1", spoof_nx.port)}, timeout=1.0)
            self.assertEqual(spoof1["v"], "SPOOFED")

            spoof2 = check_dns_hijack("example.com", resolvers={"A": ("127.0.0.1", good_a.port), "Alt": ("127.0.0.1", spoof_ip.port)}, timeout=1.0)
            self.assertEqual(spoof2["v"], "SPOOFED")
        finally:
            good_a.close()
            good_b.close()
            spoof_nx.close()
            spoof_ip.close()

    def test_local_tcp16_catalog_downloads_only_to_cache_and_reuses_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp) / "diag_cache"
            ctx = _create_ephemeral_tls_context(Path(tmp))
            clean_srv = _LocalTlsBehaviorServer("clean", ctx)
            sample_catalog = [{"id": "T-01", "asn": "AS0", "provider": "LocalTest", "ip": "127.0.0.1", "port": clean_srv.port}]

            class Handler(BaseHTTPRequestHandler):
                hits = 0

                def do_GET(self):
                    Handler.hits += 1
                    body = json.dumps(sample_catalog).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *args):
                    pass

            httpd = HTTPServer(("127.0.0.1", 0), Handler)
            ht = threading.Thread(target=httpd.serve_forever, daemon=True)
            ht.start()
            try:
                url = f"http://127.0.0.1:{httpd.server_address[1]}/tcp16.json"
                items1, src1 = fetch_local_tcp16_catalog(cache_dir=cache_dir, allow_download=True, catalog_url=url)
                self.assertTrue(src1.startswith("downloaded:"))
                self.assertEqual(len(items1), 1)
                self.assertTrue((cache_dir / "tcp16.json").exists())

                # Повторное обращение берёт локальный кэш без повторного HTTP-запроса
                items2, src2 = fetch_local_tcp16_catalog(cache_dir=cache_dir, allow_download=True, catalog_url=url)
                self.assertTrue(src2.startswith("cache:"))
                self.assertEqual(Handler.hits, 1)

                # Проверка среза работает по скачанному локальному кэшу
                rep = run_cdn_tcp16_check(cache_dir=cache_dir, allow_download=False, timeout=1.5)
                self.assertEqual(rep["total"], 1)
                self.assertEqual(rep["ok"], 1)

                # Без кэша и сети используется встроенный компактный резервный список
                fallback_items, fb_src = fetch_local_tcp16_catalog(cache_dir=Path(tmp) / "empty", allow_download=False)
                self.assertEqual(fb_src, "builtin-fallback")
                self.assertEqual(len(fallback_items), len(FALLBACK_CDN_TARGETS))
            finally:
                httpd.shutdown()
                httpd.server_close()
                clean_srv.close()

    def test_cli_check_json_smoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _create_ephemeral_tls_context(Path(tmp))
            clean_srv = _LocalTlsBehaviorServer("clean", ctx)
            try:
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(REPO_DIR / "main.py"),
                        "check",
                        "--host",
                        f"127.0.0.1:{clean_srv.port}",
                        "--no-bypass-tun",
                        "--no-siberian",
                        "--timeout",
                        "1.5",
                        "--json",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                parsed = json.loads(proc.stdout)
                self.assertEqual(len(parsed), 1)
                self.assertEqual(parsed[0]["verdict"], "CLEAN")
            finally:
                clean_srv.close()


@unittest.skipUnless(os.environ.get("SUBSYNC_LIVE_DPI") == "1", "Живая проверка сети включается флагом SUBSYNC_LIVE_DPI=1")
class TestLiveDpiSanity(unittest.TestCase):
    def test_live_clean_and_blocked_subscription_hosts(self):
        phys_ip = detect_physical_source_ip()
        results = run_batch_diagnostics(["us1.static.lolcdn.net:443", "netherlands.wproxier.in:443"], source_ip=phys_ip, timeout=5.0)
        by_host = {r["host"]: r for r in results}
        self.assertEqual(by_host["us1.static.lolcdn.net"]["l4_25"]["v"], "CLEAN")
        self.assertIn(by_host["netherlands.wproxier.in"]["verdict"], ("BLOCKED", "WARN"))


if __name__ == "__main__":
    unittest.main()
