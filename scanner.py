# language: Python 3.11, file: scanner.py
# Ядро: ping-sweep, ARP, порты (параллельно по хостам), resume
import os
import json
import time
import ipaddress
import threading
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

IS_WINDOWS = platform.system() == "Windows"

def _enc():
    return "cp866" if IS_WINDOWS else "utf-8"

def _run(cmd, timeout=5):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
            timeout=timeout, encoding=_enc(), errors="replace")
    except Exception:
        return ""

def local_subnet() -> ipaddress.IPv4Network:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    o = local_ip.split(".")
    return ipaddress.IPv4Network(f"{o[0]}.{o[1]}.{o[2]}.0/24", strict=False)

def arp_table() -> dict[str, str]:
    out = {}
    try:
        from scapy.all import ARP, Ether, srp
        net = local_subnet()
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
        answered, _ = srp(pkt, timeout=3, verbose=0)
        for _, rcv in answered:
            out[rcv.psrc] = rcv.hwsrc.lower()
    except Exception:
        pass
    if not out:
        raw = _run(["arp", "-a"], 5) if IS_WINDOWS else _run(["arp", "-n"], 5)
        for line in raw.splitlines():
            parts = line.split()
            if IS_WINDOWS and len(parts) >= 2 and parts[0].count(".") == 3:
                ip, mac = parts[0], parts[1].replace("-", ":").lower()
                if len(mac) == 17:
                    out[ip] = mac
            elif not IS_WINDOWS and len(parts) >= 4:
                if parts[2].count(":") == 5:
                    out[parts[0]] = parts[2].lower()
    return out

def ping(ip: str, timeout: float = 1.0) -> bool:
    cmd = (["ping", "-n", "1", "-w", str(int(timeout*1000)), ip] if IS_WINDOWS
           else ["ping", "-c", "1", "-W", str(int(timeout)), ip])
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=timeout+1).returncode == 0
    except Exception:
        return False

def ping_sweep(ips: list[str], timeout: float = 0.5, workers: int = 64) -> list[str]:
    alive = []
    lock = threading.Lock()
    def check(ip):
        if ping(ip, timeout):
            with lock:
                alive.append(ip)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(check, ips))
    return alive

def scan_ports_one(ip: str, ports=None, timeout: float = 0.4) -> list[int]:
    if ports is None:
        ports = [21, 22, 23, 53, 80, 135, 139, 443, 445, 3389, 8080, 9100]
    out = []
    def check(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p)) == 0:
                out.append(p)
        finally:
            s.close()
    ts = [threading.Thread(target=check, args=(p,)) for p in ports]
    for t in ts: t.start()
    for t in ts: t.join()
    return sorted(out)

def scan_ports_parallel(ips: list[str], ports=None,
                        timeout: float = 0.4,
                        workers: int = 32) -> dict[str, list[int]]:
    """Параллельный скан портов по многим хостам."""
    result = {}
    lock = threading.Lock()
    def work(ip):
        res = scan_ports_one(ip, ports, timeout)
        with lock:
            result[ip] = res
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(work, ips))
    return result

def icmp_ttl(ip: str):
    raw = _run(["ping", "-n", "1", "-w", "1000", ip] if IS_WINDOWS
               else ["ping", "-c", "1", "-W", "1", ip], 3)
    import re
    m = re.search(r"TTL=(\d+)", raw, re.I)
    return int(m.group(1)) if m else None

def os_hint(ip: str, open_ports: list[int]) -> str:
    ttl = icmp_ttl(ip)
    if 53 in open_ports and (80 in open_ports or 443 in open_ports):
        return "Network device (router)"
    if ttl:
        if ttl <= 64:  return "Linux/Unix"
        if ttl <= 128: return "Windows"
        if ttl <= 255: return "Network device (router/switch)"
    if 3389 in open_ports or 445 in open_ports or 139 in open_ports:
        return "Windows"
    if 22 in open_ports:
        return "Linux/Unix"
    if 80 in open_ports or 443 in open_ports:
        return "Web-сервер / IoT"
    return "unknown"

def hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

# --- resume ---
def load_checkpoint(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"done": [], "results": {}}

def save_checkpoint(path: str, data: dict):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)