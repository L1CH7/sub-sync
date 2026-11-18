from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .config_store import ConfigStore
from .net_utils import VIRTUAL_IFACE_KEYWORDS, get_candidate_interfaces
from .sub_converter import decode_xray_payload

TCP16_CATALOG_URL = "https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/tcp16.json"
DEFAULT_ALLOWED_SNI = "ya.ru"
DEFAULT_DNS_RESOLVERS: Dict[str, Optional[str]] = {
    "Cloudflare": "1.1.1.1",
    "Google": "8.8.8.8",
    "Yandex": "77.88.88.88",
    "Система": None,
}
LINUX_VIRTUAL_PREFIXES = (
    "lo", "tun", "tap", "wg", "utun", "mihomo", "sing", "happ",
    "docker", "br-", "veth", "virbr", "tailscale", "zt",
)

# Минимальный резервный набор на случай полной недоступности сети при скачивании каталога
FALLBACK_CDN_TARGETS: List[Dict[str, Any]] = [
    {"id": "HE-01", "asn": "24940", "provider": "Hetzner", "ip": "91.98.156.82", "port": 443},
    {"id": "CF-01", "asn": "13335", "provider": "Cloudflare", "ip": "172.67.70.222", "port": 443},
    {"id": "AK-01", "asn": "20940", "provider": "Akamai 1", "ip": "23.222.76.4", "port": 443},
    {"id": "DO-06", "asn": "46652", "provider": "DigitalOcean 2", "ip": "141.0.173.188", "port": 443},
]


def get_diag_cache_dir(cache_dir: Optional[Path] = None) -> Path:
    """Возвращает каталог кэша диагностики строго вне рабочего дерева репозитория."""
    if cache_dir is not None:
        return Path(cache_dir)
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
    return base / "subsync" / "diag"


def is_ipv4(value: str) -> bool:
    """Проверяет, является ли строка IPv4-адресом."""
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


def parse_target(raw: str, default_port: int = 443) -> Tuple[str, int, str]:
    """Разбирает host, host:port или URL в кортеж (host, port, sni)."""
    text = raw.strip()
    if "://" in text:
        parsed = urlparse(text)
        host = parsed.hostname or text
        port = parsed.port or (80 if parsed.scheme == "http" else default_port)
        return host, int(port), host
    if ":" in text and text.count(":") == 1:
        host_part, port_part = text.rsplit(":", 1)
        if port_part.isdigit():
            return host_part.strip(), int(port_part), host_part.strip()
    return text, default_port, text


def parse_socks5_proxy(proxy_url: Optional[str]) -> Optional[Tuple[str, int]]:
    """Преобразует socks5://host:port или host:port в пару (host, port)."""
    if not proxy_url:
        return None
    text = proxy_url.strip()
    if not text:
        return None
    if "://" not in text:
        text = f"socks5://{text}"
    parsed = urlparse(text)
    if not parsed.hostname:
        raise ValueError(f"Некорректный адрес SOCKS5: {proxy_url}")
    return parsed.hostname, int(parsed.port or 1080)


def detect_physical_source_ip() -> Optional[str]:
    """Определяет IPv4 физического исходящего интерфейса для обхода активного TUN."""
    if sys.platform != "win32":
        try:
            routes = subprocess.check_output(["ip", "-4", "route", "show", "default"], text=True, timeout=2)
            candidates: List[Tuple[int, str]] = []
            for line in routes.splitlines():
                parts = line.split()
                if "dev" not in parts:
                    continue
                iface = parts[parts.index("dev") + 1]
                if iface.startswith(LINUX_VIRTUAL_PREFIXES) or any(k in iface.lower() for k in VIRTUAL_IFACE_KEYWORDS):
                    continue
                metric = 0
                if "metric" in parts:
                    try:
                        metric = int(parts[parts.index("metric") + 1])
                    except ValueError:
                        metric = 999
                candidates.append((metric, iface))
            candidates.sort(key=lambda item: item[0])
            for _, iface in candidates:
                addr_out = subprocess.check_output(["ip", "-o", "-4", "addr", "show", "dev", iface], text=True, timeout=2)
                for line in addr_out.splitlines():
                    tokens = line.split()
                    if "inet" in tokens:
                        return tokens[tokens.index("inet") + 1].split("/")[0]
        except Exception:
            pass

    for item in get_candidate_interfaces():
        if not item.get("is_virtual") and item.get("ip") and not str(item["ip"]).startswith("127."):
            return str(item["ip"])
    return None


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise EOFError("Неожиданный разрыв SOCKS5")
        buf.extend(chunk)
    return bytes(buf)


def open_tcp_stream(
    host: str,
    port: int,
    timeout: float = 6.0,
    source_ip: Optional[str] = None,
    socks_proxy: Optional[Tuple[str, int]] = None,
) -> socket.socket:
    """Открывает TCP-соединение напрямую (с привязкой к source_ip) или через SOCKS5."""
    if socks_proxy is None:
        src = (source_ip, 0) if source_ip and not is_loopback_target(host) else None
        sock = socket.create_connection((host, port), timeout=timeout, source_address=src)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock

    proxy_host, proxy_port = socks_proxy
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        greeting = _recv_exact(sock, 2)
        if greeting != b"\x05\x00":
            raise ConnectionError(f"SOCKS5 отклонил handshake без авторизации: {greeting!r}")

        if is_ipv4(host):
            addr_part = b"\x01" + socket.inet_aton(host)
        else:
            host_bytes = host.encode("idna")
            addr_part = b"\x03" + bytes([len(host_bytes)]) + host_bytes

        sock.sendall(b"\x05\x01\x00" + addr_part + struct.pack(">H", port))
        hdr = _recv_exact(sock, 4)
        if hdr[1] != 0:
            raise ConnectionError(f"Ошибка SOCKS5 CONNECT: код {hdr[1]}")
        atyp = hdr[3]
        if atyp == 1:
            _recv_exact(sock, 6)
        elif atyp == 3:
            alen = _recv_exact(sock, 1)[0]
            _recv_exact(sock, alen + 2)
        elif atyp == 4:
            _recv_exact(sock, 18)
        return sock
    except Exception:
        sock.close()
        raise


def is_loopback_target(host: str) -> bool:
    """Проверяет, относится ли адрес к локальному контуру."""
    return host in ("127.0.0.1", "localhost", "::1")


def _wrap_tls(sock: socket.socket, sni: Optional[str], timeout: float) -> ssl.SSLSocket:
    ctx = ssl._create_unverified_context()
    sock.settimeout(timeout)
    return ctx.wrap_socket(sock, server_hostname=(sni or None))


def _resolve_target_ip(host: str, socks_proxy: Optional[Tuple[str, int]]) -> str:
    if socks_proxy is not None or is_ipv4(host):
        return host
    return socket.gethostbyname(host)


def check_l4_25(
    host: str,
    port: int = 443,
    sni: Optional[str] = None,
    *,
    payload_bytes: int = 32 * 1024,
    connect_timeout: float = 5.0,
    freeze_timeout: float = 5.0,
    source_ip: Optional[str] = None,
    socks_proxy: Optional[Tuple[str, int]] = None,
    use_tls: Optional[bool] = None,
) -> Dict[str, Any]:
    """Проверяет заморозку или сброс соединения ТСПУ после передачи 16-32 КБ данных."""
    sni_name = host if sni is None else sni
    tls_enabled = (port != 80) if use_tls is None else use_tls
    res: Dict[str, Any] = {"v": None, "d": "", "sent": 0}
    try:
        sock = open_tcp_stream(host, port, timeout=connect_timeout, source_ip=source_ip, socks_proxy=socks_proxy)
    except Exception as exc:
        res["v"] = "CONN_ERR"
        res["d"] = f"нет TCP-соединения: {exc}"
        return res

    stream: Any = sock
    if tls_enabled:
        try:
            stream = _wrap_tls(sock, sni_name or None, connect_timeout)
        except Exception as exc:
            res["v"] = "TLS_ERR"
            res["d"] = f"TLS не установился ({type(exc).__name__})"
            sock.close()
            return res

    body = os.urandom(payload_bytes)
    req = (
        f"POST / HTTP/1.1\r\nHost: {sni_name or host}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    try:
        stream.sendall(req)
        for idx in range(0, len(body), 2048):
            chunk = body[idx:idx + 2048]
            stream.sendall(chunk)
            res["sent"] += len(chunk)
        stream.settimeout(freeze_timeout)
        stream.recv(4096)
        res["v"] = "CLEAN"
        res["d"] = f"поток {res['sent'] // 1024}KB прошёл"
    except (socket.timeout, TimeoutError):
        res["v"] = "FROZEN"
        res["d"] = f"зависание после {res['sent'] // 1024}KB"
    except (ConnectionResetError, BrokenPipeError, ssl.SSLError, EOFError) as exc:
        res["v"] = "FROZEN"
        res["d"] = f"обрыв ({type(exc).__name__}) на {res['sent'] // 1024}KB"
    finally:
        try:
            stream.close()
        except Exception:
            pass
    return res


def check_siberian(
    host: str,
    port: int = 443,
    sni: Optional[str] = None,
    *,
    connections: int = 5,
    stagger_sec: float = 0.2,
    timeout: float = 5.0,
    source_ip: Optional[str] = None,
    socks_proxy: Optional[Tuple[str, int]] = None,
) -> Dict[str, Any]:
    """Проверяет блокировку при серии параллельных TLS-рукопожатий."""
    sni_name = sni if sni is not None else host
    out: List[Optional[str]] = [None] * connections

    def worker(slot: int):
        try:
            s = open_tcp_stream(host, port, timeout=timeout, source_ip=source_ip, socks_proxy=socks_proxy)
            tls = _wrap_tls(s, sni_name, timeout)
            out[slot] = "ok"
            try:
                tls.close()
            except Exception:
                pass
        except (socket.timeout, TimeoutError):
            out[slot] = "timeout"
        except Exception:
            out[slot] = "err"

    threads: List[threading.Thread] = []
    for i in range(connections):
        th = threading.Thread(target=worker, args=(i,), daemon=True)
        th.start()
        threads.append(th)
        if stagger_sec > 0 and i + 1 < connections:
            time.sleep(stagger_sec)
    for th in threads:
        th.join()

    ok_cnt = sum(1 for item in out if item == "ok")
    frozen_cnt = sum(1 for item in out if item == "timeout")
    err_cnt = sum(1 for item in out if item == "err")

    res = {"v": "", "d": "", "ok": ok_cnt, "frozen": frozen_cnt, "err": err_cnt}
    if frozen_cnt >= 2 and ok_cnt < connections:
        res["v"] = "FROZEN"
        res["d"] = f"{frozen_cnt}/{connections} заморожены"
    elif ok_cnt == connections:
        res["v"] = "CLEAN"
        res["d"] = f"{ok_cnt}/{connections} ok"
    elif ok_cnt == 0 and err_cnt == connections:
        res["v"] = "CONN_ERR"
        res["d"] = f"все {connections} сорвались"
    else:
        res["v"] = "PARTIAL"
        res["d"] = f"{ok_cnt} ok / {frozen_cnt} завис / {err_cnt} сбой"
    return res


def _sni_probe(
    host: str,
    port: int,
    sni: Optional[str],
    *,
    timeout: float,
    payload_bytes: int,
    source_ip: Optional[str],
    socks_proxy: Optional[Tuple[str, int]],
) -> Optional[bool]:
    tls: Optional[ssl.SSLSocket] = None
    try:
        sock = open_tcp_stream(host, port, timeout=timeout, source_ip=source_ip, socks_proxy=socks_proxy)
        tls = _wrap_tls(sock, sni, timeout)
        blob = os.urandom(payload_bytes)
        req = (
            f"POST / HTTP/1.1\r\nHost: {sni or host}\r\n"
            f"Content-Length: {len(blob)}\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        tls.sendall(req)
        tls.sendall(blob)
        tls.settimeout(timeout)
        tls.recv(1024)
        return True
    except (socket.timeout, TimeoutError, ssl.SSLError, ConnectionResetError, BrokenPipeError):
        return False
    except Exception:
        return None
    finally:
        if tls is not None:
            try:
                tls.close()
            except Exception:
                pass


def check_sni_whitelist(
    host: str,
    port: int = 443,
    sni: Optional[str] = None,
    *,
    allowed_sni: str = DEFAULT_ALLOWED_SNI,
    timeout: float = 5.0,
    payload_bytes: int = 20 * 1024,
    source_ip: Optional[str] = None,
    socks_proxy: Optional[Tuple[str, int]] = None,
) -> Dict[str, Any]:
    """Сравнивает прохождение своего SNI с заведомо разрешённым доменом."""
    own_sni = sni if sni is not None else host
    own_ok = _sni_probe(
        host, port, own_sni, timeout=timeout, payload_bytes=payload_bytes, source_ip=source_ip, socks_proxy=socks_proxy
    )
    if own_ok is True:
        return {"v": "CLEAN", "d": f"свой SNI={own_sni} прошёл"}

    wl_ok = _sni_probe(
        host, port, allowed_sni, timeout=timeout, payload_bytes=payload_bytes, source_ip=source_ip, socks_proxy=socks_proxy
    )
    labels = {True: "прошёл", False: "блок/таймаут", None: "ошибка"}
    detail = f"свой={labels[own_ok]}, {allowed_sni}={labels[wl_ok]}"
    if own_ok is False and wl_ok is True:
        return {"v": "WHITELIST_SNI", "d": detail}
    if own_ok is False and wl_ok is False:
        return {"v": "BLOCKED_ALL", "d": detail}
    return {"v": "INCON", "d": detail}


def _query_dns_a(
    resolver: Optional[Tuple[str, int]],
    host: str,
    *,
    timeout: float = 3.0,
    source_ip: Optional[str] = None,
) -> Any:
    if resolver is None:
        try:
            return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
        except Exception:
            return None

    tid = os.urandom(2)
    qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in host.strip(".").split(".")) + b"\x00"
    pkt = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if source_ip and not is_loopback_target(resolver[0]):
            sock.bind((source_ip, 0))
        sock.settimeout(timeout)
        sock.sendto(pkt, resolver)
        data, _ = sock.recvfrom(2048)
    except Exception:
        return None
    finally:
        sock.close()

    if len(data) < 12 or data[:2] != tid:
        return None
    if data[3] & 0x0F == 3:
        return "NXDOMAIN"
    ancount = struct.unpack(">H", data[6:8])[0]
    if ancount == 0:
        return []

    idx = 12
    while idx < len(data) and data[idx] != 0:
        idx += data[idx] + 1
    idx += 5
    ips: List[str] = []
    for _ in range(ancount):
        if idx >= len(data):
            break
        if data[idx] & 0xC0 == 0xC0:
            idx += 2
        else:
            while idx < len(data) and data[idx] != 0:
                idx += data[idx] + 1
            idx += 1
        if idx + 10 > len(data):
            break
        rtype = struct.unpack(">H", data[idx:idx + 2])[0]
        rdlen = struct.unpack(">H", data[idx + 8:idx + 10])[0]
        idx += 10
        if rtype == 1 and rdlen == 4 and idx + 4 <= len(data):
            ips.append(".".join(str(b) for b in data[idx:idx + 4]))
        idx += rdlen
    return sorted(set(ips))


def check_dns_hijack(
    domain: str,
    *,
    resolvers: Optional[Dict[str, Optional[Tuple[str, int] | str]]] = None,
    source_ip: Optional[str] = None,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """Сравнивает DNS A-записи системного резолвера и публичных серверов для выявления подмены."""
    if is_ipv4(domain):
        return {"v": "SKIPPED", "rows": [], "d": "введён IP"}

    raw_resolvers = resolvers or DEFAULT_DNS_RESOLVERS
    norm: Dict[str, Optional[Tuple[str, int]]] = {}
    for name, target in raw_resolvers.items():
        if target is None:
            norm[name] = None
        elif isinstance(target, tuple):
            norm[name] = target
        else:
            norm[name] = (str(target), 53)

    answers: Dict[str, Any] = {}
    for name, target in norm.items():
        answers[name] = _query_dns_a(target, domain, timeout=timeout, source_ip=source_ip)

    public_ips = set()
    public_sets: List[set] = []
    for name, target in norm.items():
        ans = answers[name]
        if target is not None and isinstance(ans, list) and ans:
            s = set(ans)
            public_ips.update(s)
            public_sets.append(s)

    spoofed = False
    rows: List[Tuple[str, str, str]] = []
    for name, target in norm.items():
        ans = answers[name]
        if ans is None:
            rows.append((name, "—", "err"))
        elif ans == "NXDOMAIN":
            rows.append((name, "NXDOMAIN", "SPOOF"))
            spoofed = True
        elif not ans:
            rows.append((name, "(пусто)", "empty"))
        else:
            joined = ",".join(ans[:2])
            if target is None and public_ips and not (set(ans) & public_ips):
                rows.append((name, joined, "SPOOF"))
                spoofed = True
            else:
                rows.append((name, joined, "ok"))

    if not spoofed and len(public_sets) >= 2:
        # Если UDP-запрос к внешним резолверам перехвачен и ответы расходятся с DoT/эталоном
        first = public_sets[0]
        if any(not (first & other) for other in public_sets[1:]):
            spoofed = True

    verdict = "SPOOFED" if spoofed else "CLEAN"
    return {"v": verdict, "rows": rows, "d": "подмена ответа" if spoofed else "совпадает"}


def run_host_diagnostic(
    raw_target: str,
    *,
    sni: Optional[str] = None,
    source_ip: Optional[str] = None,
    socks_proxy: Optional[Tuple[str, int]] = None,
    timeout: float = 5.0,
    include_siberian: bool = True,
    label: Optional[str] = None,
) -> Dict[str, Any]:
    """Выполняет полный набор лёгких проверок для одного хоста или домена."""
    host, port, default_sni = parse_target(raw_target)
    effective_sni = sni if sni is not None else default_sni
    try:
        resolved = _resolve_target_ip(host, socks_proxy)
    except Exception as exc:
        return {
            "label": label or host,
            "host": host,
            "port": port,
            "ip": "—",
            "l4_25": {"v": "DNS_ERR", "d": str(exc)},
            "siberian": {"v": "SKIPPED", "d": "—"},
            "sni": {"v": "SKIPPED", "d": "—"},
            "dns": {"v": "DNS_ERR", "d": str(exc), "rows": []},
            "verdict": "BLOCKED",
        }

    a_res = check_l4_25(
        resolved,
        port,
        effective_sni,
        connect_timeout=timeout,
        freeze_timeout=timeout,
        source_ip=source_ip,
        socks_proxy=socks_proxy,
    )
    b_res = (
        check_siberian(resolved, port, effective_sni, timeout=timeout, source_ip=source_ip, socks_proxy=socks_proxy)
        if include_siberian
        else {"v": "SKIPPED", "d": "выкл."}
    )
    e_res = check_sni_whitelist(resolved, port, effective_sni, timeout=timeout, source_ip=source_ip, socks_proxy=socks_proxy)
    d_res = check_dns_hijack(host, source_ip=source_ip, timeout=min(timeout, 3.0)) if not is_ipv4(host) and socks_proxy is None else {"v": "SKIPPED", "d": "—", "rows": []}

    blocked = (
        a_res["v"] in ("FROZEN", "CONN_ERR", "TLS_ERR")
        or b_res["v"] == "FROZEN"
        or e_res["v"] in ("WHITELIST_SNI", "BLOCKED_ALL")
    )
    if a_res["v"] == "CLEAN" and b_res["v"] in ("CLEAN", "SKIPPED") and e_res["v"] == "CLEAN" and d_res["v"] in ("CLEAN", "SKIPPED"):
        verdict = "CLEAN"
    elif blocked:
        verdict = "BLOCKED"
    else:
        verdict = "WARN"

    return {
        "label": label or host,
        "host": host,
        "port": port,
        "ip": resolved,
        "l4_25": a_res,
        "siberian": b_res,
        "sni": e_res,
        "dns": d_res,
        "verdict": verdict,
    }


def extract_targets_from_configs(configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Извлекает уникальные (host, port, sni) из декодированных конфигов Xray."""
    seen = set()
    targets: List[Dict[str, Any]] = []
    for cfg in configs:
        outbounds = cfg.get("outbounds") or []
        if not outbounds:
            continue
        ob = outbounds[0]
        stream = ob.get("streamSettings") or {}
        if stream.get("security") not in ("tls", "reality", ""):
            continue
        vnext = (ob.get("settings") or {}).get("vnext") or []
        if not vnext:
            continue
        server = vnext[0]
        host = str(server.get("address") or "").strip()
        port = int(server.get("port") or 443)
        if not host or (host, port) in seen:
            continue
        seen.add((host, port))
        reality = stream.get("realitySettings") or {}
        tls_set = stream.get("tlsSettings") or {}
        sni = str(reality.get("serverName") or tls_set.get("serverName") or host)
        targets.append({
            "host": host,
            "port": port,
            "sni": sni,
            "label": str(cfg.get("remarks") or host),
        })
    return targets


def load_targets_from_store(store: Optional[ConfigStore] = None, timeout: float = 5.0) -> List[Dict[str, Any]]:
    """Скачивает настроенные подписки из config.json и собирает список уникальных хостов."""
    cfg_store = store or ConfigStore()
    cfg = cfg_store.load()
    subs = ConfigStore.get_subscriptions(cfg)
    if not subs:
        return []

    all_configs: List[Dict[str, Any]] = []
    for sub in subs:
        req = urllib.request.Request(sub["target_url"], headers=sub.get("headers") or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            all_configs.extend(decode_xray_payload(resp.read()))
    return extract_targets_from_configs(all_configs)


def fetch_local_tcp16_catalog(
    *,
    cache_dir: Optional[Path] = None,
    ttl_sec: int = 86400,
    allow_download: bool = True,
    timeout: float = 6.0,
    catalog_url: str = TCP16_CATALOG_URL,
) -> Tuple[List[Dict[str, str]], str]:
    """Локально кэширует лёгкий JSON-каталог tcp16.json вне репозитория."""
    target_dir = get_diag_cache_dir(cache_dir)
    cache_file = target_dir / "tcp16.json"
    now = time.time()

    if cache_file.exists() and (now - cache_file.stat().st_mtime) < ttl_sec:
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            if isinstance(data, list) and data:
                return data, f"cache:{cache_file}"
        except Exception:
            pass

    if allow_download:
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            req = urllib.request.Request(catalog_url, headers={"User-Agent": "subsync-diag/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
            parsed = json.loads(raw)
            if isinstance(parsed, list) and parsed:
                cache_file.write_text(json.dumps(parsed, ensure_ascii=False), encoding="utf-8")
                return parsed, f"downloaded:{cache_file}"
        except Exception:
            pass

    if cache_file.exists():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            if isinstance(data, list) and data:
                return data, f"stale:{cache_file}"
        except Exception:
            pass

    return list(FALLBACK_CDN_TARGETS), "builtin-fallback"


def run_batch_diagnostics(
    targets: List[Any],
    *,
    source_ip: Optional[str] = None,
    socks_proxy: Optional[Tuple[str, int]] = None,
    timeout: float = 5.0,
    max_workers: int = 8,
    include_siberian: bool = True,
    on_result: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> List[Dict[str, Any]]:
    """Параллельно проверяет список хостов, URL или словарей {host, port, sni, label}."""
    if not targets:
        return []

    def submit_one(item: Any) -> Dict[str, Any]:
        if isinstance(item, dict):
            raw = f"{item['host']}:{item.get('port', 443)}"
            return run_host_diagnostic(
                raw,
                sni=item.get("sni"),
                label=item.get("label"),
                source_ip=source_ip,
                socks_proxy=socks_proxy,
                timeout=timeout,
                include_siberian=include_siberian,
            )
        return run_host_diagnostic(
            str(item),
            source_ip=source_ip,
            socks_proxy=socks_proxy,
            timeout=timeout,
            include_siberian=include_siberian,
        )

    results: List[Optional[Dict[str, Any]]] = [None] * len(targets)
    with ThreadPoolExecutor(max_workers=min(max_workers, len(targets))) as pool:
        future_map = {pool.submit(submit_one, tgt): idx for idx, tgt in enumerate(targets)}
        for future in as_completed(future_map):
            idx = future_map[future]
            res = future.result()
            results[idx] = res
            if on_result:
                on_result(res)
    return [r for r in results if r is not None]


def run_cdn_tcp16_check(
    *,
    cache_dir: Optional[Path] = None,
    allow_download: bool = True,
    source_ip: Optional[str] = None,
    socks_proxy: Optional[Tuple[str, int]] = None,
    timeout: float = 4.0,
    max_workers: int = 24,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Проверяет срез TCP 16-20KB по локально кэшируемому каталогу CDN-узлов."""
    catalog, source = fetch_local_tcp16_catalog(cache_dir=cache_dir, allow_download=allow_download)
    items = catalog[:limit] if limit else catalog
    rows: List[Optional[Dict[str, Any]]] = [None] * len(items)

    def probe(entry: Dict[str, Any]) -> Dict[str, Any]:
        port = int(entry.get("port") or 443)
        ip = str(entry["ip"])
        sni = str(entry.get("sni") or "")
        res = check_l4_25(
            ip,
            port,
            sni,
            payload_bytes=24 * 1024,
            connect_timeout=timeout,
            freeze_timeout=timeout,
            source_ip=source_ip,
            socks_proxy=socks_proxy,
            use_tls=(port != 80),
        )
        return {
            "id": str(entry.get("id") or ip),
            "asn": str(entry.get("asn") or ""),
            "provider": str(entry.get("provider") or ""),
            "ip": ip,
            "port": port,
            "status": res["v"],
            "detail": res["d"],
        }

    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(items)))) as pool:
        fmap = {pool.submit(probe, item): idx for idx, item in enumerate(items)}
        for future in as_completed(fmap):
            rows[fmap[future]] = future.result()

    final_rows = [r for r in rows if r is not None]
    ok_count = sum(1 for r in final_rows if r["status"] == "CLEAN")
    return {
        "catalog_source": source,
        "total": len(final_rows),
        "ok": ok_count,
        "rows": final_rows,
    }
