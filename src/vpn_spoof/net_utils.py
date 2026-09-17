import socket
import subprocess
import sys
import os
from pathlib import Path

DATA_DIR = Path(__file__).absolute().parent.parent.parent / "data"
VM_HOST_FILE = DATA_DIR / "vm_host_ip.txt"

def get_vm_host_override() -> str | None:
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

def get_all_ip_addresses():
    vm_ip = get_vm_host_override()
    if vm_ip:
        return [vm_ip]

    ips = []
    # 1. Dummy UDP check
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.254.254.254", 1))
            primary_ip = s.getsockname()[0]
            if primary_ip and not primary_ip.startswith("127."):
                ips.append(primary_ip)
    except Exception:
        pass

    # 2. Hostname check
    try:
        host_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        for ip in host_ips:
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass

    # 3. Linux ip route fallback
    if sys.platform != "win32":
        try:
            out = subprocess.check_output(["ip", "-4", "addr", "show"], text=True)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet ") and not line.startswith("inet 127."):
                    ip_part = line.split()[1].split("/")[0]
                    if ip_part not in ips:
                        ips.append(ip_part)
        except Exception:
            pass

    # Priority sorting: hotspot (172.20.10.x) > LAN (192.168.x.x / 10.x.x.x) > NAT
    def ip_priority(ip):
        if ip.startswith("172.20.10."): return 0
        if ip.startswith("192.168.1.") or ip.startswith("192.168.0."): return 1
        if ip.startswith("10."): return 2
        return 10

    ips.sort(key=ip_priority)
    return ips if ips else ["127.0.0.1"]

def get_best_local_ip():
    vm_ip = get_vm_host_override()
    if vm_ip:
        return vm_ip
    return get_all_ip_addresses()[0]
