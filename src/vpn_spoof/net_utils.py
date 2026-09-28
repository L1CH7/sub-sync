import socket
import subprocess
import sys
import os
import re
from pathlib import Path
from typing import List, Dict, Optional

DATA_DIR = Path(__file__).absolute().parent.parent.parent / "data"
VM_HOST_FILE = DATA_DIR / "vm_host_ip.txt"

VIRTUAL_IFACE_KEYWORDS = [
    "vethernet", "wsl", "virtualbox", "vmware", "radmin", "happ",
    "xray", "sing-box", "clash", "tap", "wintun", "wireguard",
    "tailscale", "zerotier", "loopback", "pseudo"
]

def get_vm_host_override() -> Optional[str]:
    if override := os.environ.get("VPN_SPOOF_IP"):
        return override.strip()
    if VM_HOST_FILE.exists():
        try:
            with open(VM_HOST_FILE, "r", encoding="utf-8") as f:
                ip = f.read().strip()
                if ip:
                    return ip
        except Exception:
            pass
    return None

def _get_windows_adapters() -> Dict[str, str]:
    """Parse Windows ipconfig in ~0.08s to map IP -> Clean Interface Name."""
    if sys.platform != "win32":
        return {}
    try:
        res = subprocess.run(["ipconfig"], capture_output=True, text=True, errors="ignore", timeout=3)
        adapters = {}
        current_adapter = "LAN"
        for line in res.stdout.splitlines():
            raw = line
            line = line.strip()
            if not line:
                continue
            if not raw.startswith(" ") and not raw.startswith("\t") and line.endswith(":"):
                current_adapter = line[:-1].strip()
            elif "ipv4" in line.lower() or "ip-адрес" in line.lower():
                m = re.search(r":\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
                if m:
                    ip = m.group(1)
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        clean_name = re.sub(
                            r"^(Ethernet adapter|Wireless LAN adapter|Адаптер беспроводной локальной сети|Адаптер Ethernet|Unknown adapter)\s*",
                            "",
                            current_adapter,
                            flags=re.IGNORECASE
                        )
                        adapters[ip] = clean_name.strip()
        return adapters
    except Exception:
        return {}

def get_candidate_interfaces() -> List[Dict[str, any]]:
    """
    Returns detected IPv4 network interfaces with clean names and virtual flags.
    Prioritizes real physical Wi-Fi / Hotspot / LAN interfaces over virtual/VPN adapters.
    """
    vm_ip = get_vm_host_override()
    if vm_ip:
        return [{"ip": vm_ip, "name": "Override (VPN_SPOOF_IP / vm_host_ip.txt)", "is_virtual": False}]

    found_ips: List[str] = []

    # 1. Primary socket test (quickest hint)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.254.254.254", 1))
            primary_ip = s.getsockname()[0]
            if primary_ip and not primary_ip.startswith("127.") and not primary_ip.startswith("169.254."):
                found_ips.append(primary_ip)
    except Exception:
        pass

    # 2. Hostname check
    try:
        host_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        for ip in host_ips:
            if not ip.startswith("127.") and not ip.startswith("169.254.") and ip not in found_ips:
                found_ips.append(ip)
    except Exception:
        pass

    # 3. Windows ipconfig or Linux ip route fallback
    win_adapters = _get_windows_adapters() if sys.platform == "win32" else {}
    for ip in win_adapters:
        if ip not in found_ips:
            found_ips.append(ip)

    if sys.platform != "win32":
        try:
            out = subprocess.check_output(["ip", "-4", "addr", "show"], text=True, timeout=2)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet ") and not line.startswith("inet 127.") and not line.startswith("inet 169.254."):
                    ip_part = line.split()[1].split("/")[0]
                    if ip_part not in found_ips:
                        found_ips.append(ip_part)
        except Exception:
            pass

    if not found_ips:
        found_ips = ["127.0.0.1"]

    candidates = []
    for ip in found_ips:
        alias = win_adapters.get(ip, "LAN")
        alias_lower = alias.lower()
        is_virt = any(kw in alias_lower for kw in VIRTUAL_IFACE_KEYWORDS)
        candidates.append({
            "ip": ip,
            "name": alias,
            "is_virtual": is_virt
        })

    def iface_priority(item):
        ip = item["ip"]
        name = item["name"].lower()
        is_virt = item["is_virtual"]

        # Virtual / VPN adapters are deprioritized to bottom
        if is_virt:
            return 100
        # iPhone hotspot (172.20.10.x)
        if ip.startswith("172.20.10."):
            return 0
        # Wi-Fi or wireless adapter
        if any(w in name for w in ["wi-fi", "wifi", "беспроводная"]):
            return 1
        # Physical Ethernet
        if "ethernet" in name:
            return 2
        # Standard home LAN subnets (192.168.x.x, 10.x.x.x)
        if ip.startswith("192.168."):
            return 3
        if ip.startswith("10."):
            return 4
        return 10

    candidates.sort(key=iface_priority)
    return candidates

def get_all_ip_addresses() -> List[str]:
    return [c["ip"] for c in get_candidate_interfaces()]

def get_best_local_ip() -> str:
    candidates = get_candidate_interfaces()
    return candidates[0]["ip"] if candidates else "127.0.0.1"
