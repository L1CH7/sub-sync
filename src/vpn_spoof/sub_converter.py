import base64
import copy
import datetime
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


def parse_userinfo(header_val: str) -> Dict[str, int]:
    """Разбирает заголовок Subscription-Userinfo в словарь числовых полей."""
    result: Dict[str, int] = {}
    if not header_val:
        return result
    for part in header_val.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        try:
            result[k.strip().lower()] = int(float(v.strip()))
        except ValueError:
            continue
    return result


def format_userinfo_summary(label: str, info: Dict[str, int]) -> str:
    """Форматирует читаемую строку квоты трафика и срока действия подписки."""
    if not info:
        return ""
    used_bytes = info.get("upload", 0) + info.get("download", 0)
    used_gb = used_bytes / (1024 ** 3)
    total_bytes = info.get("total", 0)

    if total_bytes > 0:
        total_gb = total_bytes / (1024 ** 3)
        left_gb = max(0.0, (total_bytes - used_bytes) / (1024 ** 3))
        quota_str = f"Ост. {left_gb:.1f}/{total_gb:.1f} ГБ"
    else:
        quota_str = f"Безлимит (исп. {used_gb:.1f} ГБ)"

    expire_ts = info.get("expire", 0)
    expire_str = ""
    if expire_ts > 0:
        dt = datetime.datetime.fromtimestamp(expire_ts, tz=datetime.timezone.utc)
        days_left = max(0, (dt.date() - datetime.datetime.now(datetime.timezone.utc).date()).days)
        expire_str = f" | до {dt.strftime('%Y-%m-%d')} ({days_left} дн.)"

    return f"📊 [{label}] {quota_str}{expire_str}"


def _unique_name(base: str, used: set) -> str:
    """Гарантирует уникальность имени узла в рамках одного профиля."""
    candidate = base.strip() or "node"
    if candidate not in used:
        used.add(candidate)
        return candidate
    idx = 2
    while f"{candidate} #{idx}" in used:
        idx += 1
    unique = f"{candidate} #{idx}"
    used.add(unique)
    return unique


def _endpoint_key(outbound: Dict[str, Any]) -> Optional[Tuple[Any, ...]]:
    """Возвращает ключ уникальности конечной точки для дедупликации узлов."""
    proto = outbound.get("protocol") or outbound.get("type")
    if proto == "vless":
        vnext = outbound.get("settings", {}).get("vnext", [{}])[0]
        ss = outbound.get("streamSettings", {})
        rs = ss.get("realitySettings", {})
        return ("vless", vnext.get("address"), vnext.get("port"), ss.get("network", "tcp"), rs.get("serverName", ""))
    if proto == "hysteria":
        sett = outbound.get("settings", {})
        return ("hysteria", sett.get("address"), sett.get("port"), "udp", "")
    if proto in ("trojan", "shadowsocks"):
        srv = outbound.get("settings", {}).get("servers", [{}])[0]
        return (proto, srv.get("address"), srv.get("port"), outbound.get("streamSettings", {}).get("network", "tcp"), "")
    return None


def _parse_uri_to_xray_config(uri: str) -> Optional[Dict[str, Any]]:
    """Преобразует одиночную URI-ссылку (vless://, hysteria2://) в минимальный конфиг Xray."""
    uri = uri.strip()
    if not uri:
        return None
    parsed = urllib.parse.urlparse(uri)
    scheme = parsed.scheme.lower()
    remark = urllib.parse.unquote(parsed.fragment) or f"{parsed.hostname}:{parsed.port}"
    qs = urllib.parse.parse_qs(parsed.query)

    def qget(key: str, default: str = "") -> str:
        vals = qs.get(key)
        return vals[0] if vals else default

    if scheme == "vless" and parsed.hostname and parsed.port:
        net = qget("type", "tcp")
        sec = qget("security", "none")
        stream: Dict[str, Any] = {"network": net, "security": sec}
        if sec == "reality":
            stream["realitySettings"] = {
                "serverName": qget("sni", parsed.hostname),
                "publicKey": qget("pbk"),
                "shortId": qget("sid"),
                "fingerprint": qget("fp", "firefox"),
            }
        elif sec == "tls":
            stream["tlsSettings"] = {
                "serverName": qget("sni", parsed.hostname),
                "fingerprint": qget("fp", "firefox"),
            }
        if net == "grpc":
            stream["grpcSettings"] = {"serviceName": qget("serviceName", "")}
        elif net == "ws":
            stream["wsSettings"] = {"path": qget("path", "/"), "headers": {"Host": qget("host", parsed.hostname)}}
        elif net in ("xhttp", "splithttp"):
            stream["xhttpSettings"] = {"path": qget("path", "/"), "mode": qget("mode", "auto")}

        return {
            "remarks": remark,
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": parsed.hostname,
                        "port": parsed.port,
                        "users": [{
                            "id": urllib.parse.unquote(parsed.username or ""),
                            "encryption": qget("encryption", "none"),
                            "flow": qget("flow", ""),
                        }],
                    }]
                },
                "streamSettings": stream,
            }],
        }

    if scheme in ("hysteria2", "hy2") and parsed.hostname and parsed.port:
        return {
            "remarks": remark,
            "outbounds": [{
                "tag": "proxy",
                "protocol": "hysteria",
                "settings": {"address": parsed.hostname, "port": parsed.port, "version": 2},
                "streamSettings": {
                    "network": "hysteria",
                    "hysteriaSettings": {
                        "version": 2,
                        "auth": urllib.parse.unquote(parsed.username or ""),
                    },
                    "tlsSettings": {"serverName": qget("sni", parsed.hostname)},
                },
            }],
        }
    return None


def decode_xray_payload(raw_bytes: bytes) -> List[Dict[str, Any]]:
    """Декодирует ответ провайдера в список Xray-конфигов (поддерживает JSON и Base64 URI)."""
    text = raw_bytes.decode("utf-8", errors="replace").strip()
    if not text:
        return []

    if text.startswith("[") or text.startswith("{"):
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else [parsed]

    # Попытка декодировать Base64-список URI
    decoded = text
    if "://" not in text[:64]:
        try:
            padded = text + "=" * ((4 - len(text) % 4) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
        except Exception:
            pass

    configs: List[Dict[str, Any]] = []
    for line in decoded.splitlines():
        cfg = _parse_uri_to_xray_config(line)
        if cfg:
            configs.append(cfg)
    return configs


def extract_unique_nodes(
    subscriptions_payloads: List[Dict[str, Any]],
    prefix_merged_labels: bool = True,
    include_extra_outbounds: bool = False,
) -> List[Dict[str, Any]]:
    """Извлекает дедуплицированный список узлов из всех подписок без фильтрации по странам."""
    nodes: List[Dict[str, Any]] = []
    seen_endpoints: set = set()
    used_names: set = set()
    multi = len(subscriptions_payloads) > 1

    # Сначала регистрируем основные узлы (первый прокси-аутбаунд каждого элемента подписки)
    for sub in subscriptions_payloads:
        label = sub.get("label", sub.get("id", ""))
        prefix = f"[{label}] " if (multi and prefix_merged_labels and label) else ""
        for cfg in sub.get("configs", []):
            rem = str(cfg.get("remarks", "")).strip()
            proxy_obs = [
                o for o in cfg.get("outbounds", [])
                if (o.get("protocol") or o.get("type")) not in ("freedom", "blackhole", "dns", None)
            ]
            if not proxy_obs:
                continue
            primary = proxy_obs[0]
            ep = _endpoint_key(primary)
            if ep is not None:
                seen_endpoints.add((sub.get("id"), ep))
            node_name = _unique_name(f"{prefix}{rem or primary.get('tag', 'node')}", used_names)
            nodes.append({
                "name": node_name,
                "sub_id": sub.get("id"),
                "sub_label": label,
                "tag": primary.get("tag", "proxy"),
                "outbound": primary,
            })

    # Опционально добавляем дополнительные аутбаунды из мульти-аутбаунд профилей (без дублей)
    if include_extra_outbounds:
        for sub in subscriptions_payloads:
            label = sub.get("label", sub.get("id", ""))
            prefix = f"[{label}] " if (multi and prefix_merged_labels and label) else ""
            for cfg in sub.get("configs", []):
                rem = str(cfg.get("remarks", "")).strip()
                proxy_obs = [
                    o for o in cfg.get("outbounds", [])
                    if (o.get("protocol") or o.get("type")) not in ("freedom", "blackhole", "dns", None)
                ]
                for extra in proxy_obs[1:]:
                    ep = _endpoint_key(extra)
                    if ep is None or (sub.get("id"), ep) in seen_endpoints:
                        continue
                    seen_endpoints.add((sub.get("id"), ep))
                    tag = extra.get("tag", "alt")
                    node_name = _unique_name(f"{prefix}{rem} · {tag}", used_names)
                    nodes.append({
                        "name": node_name,
                        "sub_id": sub.get("id"),
                        "sub_label": label,
                        "tag": tag,
                        "outbound": extra,
                    })
    return nodes


def outbound_to_clash_proxy(
    name: str,
    outbound: Dict[str, Any],
    dialer_proxy: Optional[str] = None,
    reality_mlkem768: bool = True,
    reality_fingerprint: str = "chrome",
) -> Optional[Dict[str, Any]]:
    """Преобразует Xray outbound в формат узла Clash/Mihomo."""
    proto = outbound.get("protocol") or outbound.get("type")
    ss = outbound.get("streamSettings", {})

    if proto == "vless":
        vnext = outbound.get("settings", {}).get("vnext", [{}])[0]
        user = vnext.get("users", [{}])[0]
        addr = vnext.get("address")
        port = vnext.get("port")
        if not addr or not port:
            return None

        net = ss.get("network", "tcp")
        sec = ss.get("security", "")
        p: Dict[str, Any] = {
            "name": name,
            "type": "vless",
            "server": addr,
            "port": int(port),
            "uuid": user.get("id", ""),
            "udp": True,
            "tls": sec in ("reality", "tls"),
            "network": "http" if net in ("xhttp", "splithttp") else net,
        }
        if user.get("flow"):
            p["flow"] = user["flow"]

        if net == "grpc":
            grpc_sett = ss.get("grpcSettings", {})
            p["grpc-opts"] = {"grpc-service-name": grpc_sett.get("serviceName") or ""}
        elif net == "ws":
            ws_sett = ss.get("wsSettings", {})
            p["ws-opts"] = {
                "path": ws_sett.get("path", "/"),
                "headers": ws_sett.get("headers", {}),
            }

        if sec == "reality":
            rs = ss.get("realitySettings", {})
            p["servername"] = rs.get("serverName", addr)
            reality_opts: Dict[str, Any] = {
                "public-key": rs.get("publicKey", ""),
                "short-id": rs.get("shortId", ""),
            }
            if reality_mlkem768:
                reality_opts["support-x25519mlkem768"] = True
            p["reality-opts"] = reality_opts
            if reality_mlkem768 and reality_fingerprint:
                p["client-fingerprint"] = reality_fingerprint
            elif rs.get("fingerprint"):
                p["client-fingerprint"] = rs["fingerprint"]
        elif sec == "tls":
            ts = ss.get("tlsSettings", {})
            if ts.get("serverName"):
                p["servername"] = ts["serverName"]
            if ts.get("fingerprint"):
                p["client-fingerprint"] = ts["fingerprint"]

        if dialer_proxy:
            p["dialer-proxy"] = dialer_proxy
        return p

    if proto == "hysteria":
        sett = outbound.get("settings", {})
        h_sett = ss.get("hysteriaSettings", {})
        ts = ss.get("tlsSettings", {})
        addr = sett.get("address")
        port = sett.get("port")
        if not addr or not port:
            return None
        p = {
            "name": name,
            "type": "hysteria2",
            "server": addr,
            "port": int(port),
            "password": h_sett.get("auth", ""),
            "udp": True,
        }
        if ts.get("serverName"):
            p["sni"] = ts["serverName"]
        if dialer_proxy:
            p["dialer-proxy"] = dialer_proxy
        return p

    return None


def _match_regex(pattern: Optional[str], text: str) -> bool:
    if not pattern:
        return False
    try:
        return re.search(pattern, text, re.IGNORECASE) is not None
    except re.error:
        return False


def to_yaml(data: Any, indent: int = 0) -> str:
    """Компактный сериализатор Python-структур в чистый YAML без внешних библиотек."""
    pad = "  " * indent
    if isinstance(data, dict):
        if not data:
            return "{}"
        lines: List[str] = []
        for k, v in data.items():
            key_str = str(k)
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{key_str}:")
                lines.append(to_yaml(v, indent + 1))
            else:
                lines.append(f"{pad}{key_str}: {to_yaml(v, 0)}")
        return "\n".join(lines)

    if isinstance(data, list):
        if not data:
            return "[]"
        lines = []
        for item in data:
            if isinstance(item, dict) and item:
                first = True
                for k, v in item.items():
                    prefix = f"{pad}- " if first else f"{pad}  "
                    first = False
                    if isinstance(v, (dict, list)) and v:
                        lines.append(f"{prefix}{k}:")
                        lines.append(to_yaml(v, indent + 2))
                    else:
                        lines.append(f"{prefix}{k}: {to_yaml(v, 0)}")
            elif isinstance(item, list) and item:
                lines.append(f"{pad}-")
                lines.append(to_yaml(item, indent + 1))
            else:
                lines.append(f"{pad}- {to_yaml(item, 0)}")
        return "\n".join(lines)

    if isinstance(data, bool):
        return "true" if data else "false"
    if data is None:
        return "null"
    if isinstance(data, (int, float)):
        return str(data)
    return json.dumps(str(data), ensure_ascii=False)


def build_clash_yaml(
    subscriptions_payloads: List[Dict[str, Any]],
    clash_cfg: Dict[str, Any],
) -> str:
    """Формирует конфигурацию Clash/Mihomo в плоской (2 карточки) или групповой раскладке."""
    prefix_labels = bool(clash_cfg.get("prefix_merged_labels", True))
    show_limits = bool(clash_cfg.get("show_limits_in_merged", True))
    layout = str(clash_cfg.get("layout", "flat")).lower()
    include_extra = bool(clash_cfg.get("include_extra_outbounds", False))
    exclude_nodes = str(clash_cfg.get("exclude_nodes", ""))
    reality_mlkem768 = bool(clash_cfg.get("reality_mlkem768", True))
    reality_fingerprint = str(clash_cfg.get("reality_fingerprint", "chrome"))

    nodes = extract_unique_nodes(
        subscriptions_payloads,
        prefix_merged_labels=prefix_labels,
        include_extra_outbounds=include_extra,
    )
    if exclude_nodes:
        nodes = [n for n in nodes if not _match_regex(exclude_nodes, n["name"])]

    proxies: List[Dict[str, Any]] = []
    direct_names: List[str] = []
    used_names: set = set()

    # Информационные строки лимитов при объединении нескольких подписок
    info_proxy_names: List[str] = []
    if len(subscriptions_payloads) > 1 and show_limits:
        for sub in subscriptions_payloads:
            ui = parse_userinfo(sub.get("headers", {}).get("Subscription-Userinfo", ""))
            summary = format_userinfo_summary(sub.get("label", sub.get("id", "")), ui)
            if summary:
                iname = _unique_name(summary, used_names)
                proxies.append({"name": iname, "type": "socks", "server": "127.0.0.1", "port": 1})
                info_proxy_names.append(iname)

    for n in nodes:
        n["name"] = _unique_name(n["name"], used_names)

    entry_group_name = clash_cfg.get("entry_group_name", "✈️ 1. Вход (Шаг 1)")
    entry_auto_name = clash_cfg.get("entry_auto_name", "⚡ Авто · Вход")
    entry_match = clash_cfg.get("entry_match", "")
    entry_sub_ids = {str(x) for x in clash_cfg.get("entry_subscription_ids", [])}

    # Определяем входных кандидатов строго по конфигу (regex или ID подписки)
    entry_candidates_raw: List[str] = [
        n["name"]
        for n in nodes
        if (str(n["sub_id"]) in entry_sub_ids) or _match_regex(entry_match, n["name"])
    ]
    entry_set = set(entry_candidates_raw)
    direct_only_match = str(clash_cfg.get("direct_only_match", ""))

    for n in nodes:
        uname = n["name"]
        dialer = None
        if layout != "grouped" and entry_candidates_raw and (uname not in entry_set) and not _match_regex(direct_only_match, uname):
            dialer = entry_group_name
        cp = outbound_to_clash_proxy(
            uname,
            n["outbound"],
            dialer_proxy=dialer,
            reality_mlkem768=reality_mlkem768,
            reality_fingerprint=reality_fingerprint,
        )
        if cp:
            proxies.append(cp)
            direct_names.append(uname)

    entry_candidates = [name for name in entry_candidates_raw if name in direct_names]
    configured_groups = clash_cfg.get("groups", [])
    proxy_groups: List[Dict[str, Any]] = []

    if layout != "grouped":
        exit_group_name = clash_cfg.get("exit_group_name", "🌍 2. Выход (Сервер)")
        exclude_entry_from_exit = bool(clash_cfg.get("exclude_entry_from_exit", True))
        exit_pool = (
            [name for name in direct_names if name not in entry_set]
            if (exclude_entry_from_exit and entry_candidates)
            else list(direct_names)
        )
        ordered_exit_list: List[str] = []
        seen_in_order: set = set()

        for g in configured_groups:
            g_match = g.get("match", "")
            g_exclude = g.get("exclude", "")
            if not g_match:
                continue
            for name in exit_pool:
                if name in seen_in_order:
                    continue
                if _match_regex(g_match, name) and not _match_regex(g_exclude, name):
                    ordered_exit_list.append(name)
                    seen_in_order.add(name)

        for name in exit_pool:
            if name not in seen_in_order:
                ordered_exit_list.append(name)
                seen_in_order.add(name)

        ordered_exit_list.append("DIRECT")
        ordered_exit_list.extend(info_proxy_names)

        proxy_groups.append({"name": exit_group_name, "type": "select", "proxies": ordered_exit_list})
        if entry_candidates:
            proxy_groups.append({
                "name": entry_group_name,
                "type": "select",
                "proxies": [entry_auto_name, "DIRECT"] + entry_candidates,
            })
            proxy_groups.append({
                "name": entry_auto_name,
                "type": "url-test",
                "hidden": True,
                "proxies": entry_candidates,
                "url": clash_cfg.get("entry_health_url", "https://cp.cloudflare.com/generate_204"),
                "interval": int(clash_cfg.get("entry_health_interval", 90)),
                "tolerance": int(clash_cfg.get("entry_health_tolerance", 80)),
            })
        default_target_group = exit_group_name
    else:
        main_group_name = clash_cfg.get("main_group_name", "🛡️ Режим")
        bridge_prefix = clash_cfg.get("bridge_node_prefix", "[Мост] ")
        bridge_group_prefix = clash_cfg.get("bridge_group_prefix", "🌉 ")

        # Клонируем узлы для каскада (dialer-proxy на Шаг 1), если заданы входные кандидаты
        bridge_names: List[str] = []
        bridge_map: Dict[str, str] = {}
        if entry_candidates:
            for p in list(proxies):
                if p["name"] in info_proxy_names:
                    continue
                bp = copy.deepcopy(p)
                bname = _unique_name(f"{bridge_prefix}{p['name']}", used_names)
                bp["name"] = bname
                bp["dialer-proxy"] = entry_group_name
                proxies.append(bp)
                bridge_names.append(bname)
                bridge_map[p["name"]] = bname

        main_options: List[str] = []
        regional_direct_groups: List[Dict[str, Any]] = []
        regional_bridge_groups: List[Dict[str, Any]] = []

        for g in configured_groups:
            g_name = g.get("name")
            g_match = g.get("match", "")
            g_exclude = g.get("exclude", "")
            if not g_name or not g_match:
                continue
            matched = [
                name for name in direct_names
                if _match_regex(g_match, name) and not _match_regex(g_exclude, name)
            ]
            if not matched:
                continue
            regional_direct_groups.append({"name": g_name, "type": "select", "proxies": matched})
            if entry_candidates and g.get("bridge", True):
                b_matched = [bridge_map[m] for m in matched if m in bridge_map]
                if b_matched:
                    bg_name = f"{bridge_group_prefix}{g_name}"
                    regional_bridge_groups.append({"name": bg_name, "type": "select", "proxies": b_matched})

        for bg in regional_bridge_groups:
            main_options.append(bg["name"])
        for dg in regional_direct_groups:
            main_options.append(dg["name"])

        all_bridge_group_name = clash_cfg.get("all_bridge_group_name", "🎯 Все серверы (Мост)")
        all_direct_group_name = clash_cfg.get("all_direct_group_name", "⚡ Все серверы (Прямой)")

        if bridge_names:
            main_options.append(all_bridge_group_name)
        if direct_names:
            main_options.append(all_direct_group_name)
        main_options.append("DIRECT")

        proxy_groups.append({"name": main_group_name, "type": "select", "proxies": main_options})

        if entry_candidates:
            proxy_groups.append({
                "name": entry_group_name,
                "type": "select",
                "proxies": [entry_auto_name, "DIRECT"] + entry_candidates,
            })
            proxy_groups.append({
                "name": entry_auto_name,
                "type": "url-test",
                "hidden": True,
                "proxies": entry_candidates,
                "url": clash_cfg.get("entry_health_url", "https://cp.cloudflare.com/generate_204"),
                "interval": int(clash_cfg.get("entry_health_interval", 90)),
                "tolerance": int(clash_cfg.get("entry_health_tolerance", 80)),
            })

        proxy_groups.extend(regional_bridge_groups)
        proxy_groups.extend(regional_direct_groups)

        if bridge_names:
            proxy_groups.append({"name": all_bridge_group_name, "type": "select", "proxies": bridge_names})
        if direct_names:
            proxy_groups.append({"name": all_direct_group_name, "type": "select", "proxies": info_proxy_names + direct_names})
        default_target_group = main_group_name

    rules = clash_cfg.get("rules") or [f"MATCH,{default_target_group}"]
    if not any(str(r).startswith("MATCH,") for r in rules):
        rules = list(rules) + [f"MATCH,{default_target_group}"]

    full_cfg: Dict[str, Any] = {
        "mixed-port": int(clash_cfg.get("mixed_port", 7890)),
        "allow-lan": bool(clash_cfg.get("allow_lan", False)),
        "mode": clash_cfg.get("mode", "rule"),
        "log-level": clash_cfg.get("log_level", "info"),
        "ipv6": bool(clash_cfg.get("ipv6", False)),
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": rules,
    }
    return to_yaml(full_cfg) + "\n"


def _strip_finalmask(outbound: Dict[str, Any]) -> None:
    """Удаляет Xray-фрагментацию tlshello на звеньях каскада во избежание RECORD_LAYER_FAILURE."""
    ss = outbound.get("streamSettings")
    if isinstance(ss, dict) and "finalmask" in ss:
        del ss["finalmask"]


def build_xray_configs(
    subscriptions_payloads: List[Dict[str, Any]],
    xray_chains_cfg: List[Dict[str, Any]],
    prefix_merged_labels: bool = True,
) -> List[Dict[str, Any]]:
    """Собирает итоговый массив Xray-конфигов с инлайновыми цепочками из конфига."""
    result: List[Dict[str, Any]] = []
    multi = len(subscriptions_payloads) > 1

    for sub in subscriptions_payloads:
        label = sub.get("label", sub.get("id", ""))
        prefix = f"[{label}] " if (multi and prefix_merged_labels and label) else ""
        for cfg in sub.get("configs", []):
            cloned = copy.deepcopy(cfg)
            if prefix and cloned.get("remarks"):
                cloned["remarks"] = f"{prefix}{cloned['remarks']}"
            result.append(cloned)

    if not xray_chains_cfg:
        return result

    def find_matching_config(pattern: str) -> Optional[Dict[str, Any]]:
        for cfg in result:
            rem = str(cfg.get("remarks", ""))
            if _match_regex(pattern, rem):
                return cfg
            for o in cfg.get("outbounds", []):
                vnext = o.get("settings", {}).get("vnext", [{}])
                addr = vnext[0].get("address", "") if vnext else ""
                if addr and _match_regex(pattern, addr):
                    return cfg
        return None

    for chain in xray_chains_cfg:
        name = chain.get("name")
        via_pat = chain.get("via", "")
        to_pat = chain.get("to", "")
        if not name or not via_pat or not to_pat:
            continue
        via_cfg = find_matching_config(via_pat)
        to_cfg = find_matching_config(to_pat)
        if not via_cfg or not to_cfg:
            continue

        via_obs = [
            o for o in via_cfg.get("outbounds", [])
            if (o.get("protocol") or o.get("type")) not in ("freedom", "blackhole", "dns", None)
        ]
        if not via_obs:
            continue

        via_ob = copy.deepcopy(via_obs[0])
        via_ob["tag"] = "chain_entry"
        _strip_finalmask(via_ob)

        chained_cfg = copy.deepcopy(to_cfg)
        chained_cfg["remarks"] = name
        outbounds = chained_cfg.get("outbounds", [])
        for o in outbounds:
            proto = o.get("protocol") or o.get("type")
            if proto in ("freedom", "blackhole", "dns", None):
                continue
            tag = o.get("tag", "")
            if tag.startswith("proxy") or tag == "chain_exit":
                _strip_finalmask(o)
                ss = o.setdefault("streamSettings", {})
                sockopt = ss.setdefault("sockopt", {})
                sockopt["dialerProxy"] = "chain_entry"

        outbounds.append(via_ob)
        result.append(chained_cfg)

    return result


def build_raw_uris(subscriptions_payloads: List[Dict[str, Any]], prefix_merged_labels: bool = True) -> str:
    """Формирует Base64-кодированный список ссылок vless:// и hysteria2://."""
    nodes = extract_unique_nodes(subscriptions_payloads, prefix_merged_labels=prefix_merged_labels)
    uris: List[str] = []

    for n in nodes:
        o = n["outbound"]
        proto = o.get("protocol") or o.get("type")
        ss = o.get("streamSettings", {})
        frag = urllib.parse.quote(n["name"], safe="")

        if proto == "vless":
            vnext = o.get("settings", {}).get("vnext", [{}])[0]
            user = vnext.get("users", [{}])[0]
            addr = vnext.get("address")
            port = vnext.get("port")
            uuid = user.get("id", "")
            if not addr or not port:
                continue
            params: Dict[str, str] = {
                "encryption": user.get("encryption", "none"),
                "type": ss.get("network", "tcp"),
                "security": ss.get("security", "none"),
            }
            if user.get("flow"):
                params["flow"] = user["flow"]
            if params["security"] == "reality":
                rs = ss.get("realitySettings", {})
                params["sni"] = rs.get("serverName", addr)
                params["pbk"] = rs.get("publicKey", "")
                params["sid"] = rs.get("shortId", "")
                if rs.get("fingerprint"):
                    params["fp"] = rs["fingerprint"]
            elif params["security"] == "tls":
                ts = ss.get("tlsSettings", {})
                if ts.get("serverName"):
                    params["sni"] = ts["serverName"]
                if ts.get("fingerprint"):
                    params["fp"] = ts["fingerprint"]
            if params["type"] == "grpc":
                sn = ss.get("grpcSettings", {}).get("serviceName")
                if sn:
                    params["serviceName"] = sn
            query = urllib.parse.urlencode(params)
            uris.append(f"vless://{uuid}@{addr}:{port}?{query}#{frag}")

        elif proto == "hysteria":
            sett = o.get("settings", {})
            h_sett = ss.get("hysteriaSettings", {})
            ts = ss.get("tlsSettings", {})
            addr = sett.get("address")
            port = sett.get("port")
            auth = urllib.parse.quote(h_sett.get("auth", ""), safe="")
            if not addr or not port:
                continue
            q = urllib.parse.urlencode({"sni": ts.get("serverName", addr)})
            uris.append(f"hysteria2://{auth}@{addr}:{port}?{q}#{frag}")

    return base64.b64encode("\n".join(uris).encode("utf-8")).decode("ascii")
