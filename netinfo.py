# language: Python 3.11, file: netinfo.py
import socket
import ipaddress
import subprocess
import platform
import threading
from concurrent.futures import ThreadPoolExecutor

IS_WINDOWS = platform.system() == "Windows"

# --- кодировка консоли Windows ---
def _console_encoding() -> str:
    if IS_WINDOWS:
        return "cp866"   # русская консоль
    return "utf-8"

def _run(cmd: list[str], timeout: float = 5.0) -> str:
    """Запускает команду, возвращает stdout с правильной кодировкой."""
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=timeout,
            encoding=_console_encoding(), errors="replace",
        )
    except Exception:
        return ""

def local_subnet() -> ipaddress.IPv4Network:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    octets = local_ip.split(".")
    return ipaddress.IPv4Network(f"{octets[0]}.{octets[1]}.{octets[2]}.0/24", strict=False)

# --- ARP: основной путь — scapy, fallback — arp -a ---
def arp_table() -> dict[str, str]:
    """{ip: mac} через scapy ARP-scan (надёжно), с fallback на arp -a."""
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

    # fallback — системная ARP-таблица
    if not out:
        try:
            if IS_WINDOWS:
                raw = _run(["arp", "-a"], timeout=5)
                for line in raw.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].count(".") == 3:
                        ip, mac = parts[0], parts[1].replace("-", ":").lower()
                        if len(mac) == 17 and mac.count(":") == 5:
                            out[ip] = mac
            else:
                raw = _run(["arp", "-n"], timeout=5)
                for line in raw.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[2].count(":") == 5:
                        out[parts[0]] = parts[2].lower()
        except Exception:
            pass
    return out

def ping(ip: str, timeout: int = 1) -> bool:
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,
                              timeout=timeout + 1).returncode == 0
    except Exception:
        return False

def ping_sweep(network: ipaddress.IPv4Network, workers: int = 64) -> list[str]:
    hosts = [str(h) for h in network.hosts()]
    alive: list[str] = []
    lock = threading.Lock()
    def check(ip):
        if ping(ip):
            with lock:
                alive.append(ip)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(check, hosts))
    return alive

def scan_ports(ip: str, ports=None, timeout: float = 0.4) -> list[int]:
    if ports is None:
        ports = [21, 22, 23, 53, 80, 135, 139, 443, 445, 3389, 8080, 9100]
    open_: list[int] = []
    def check(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p)) == 0:
                open_.append(p)
        finally:
            s.close()
    threads = [threading.Thread(target=check, args=(p,)) for p in ports]
    for t in threads: t.start()
    for t in threads: t.join()
    return sorted(open_)

def _icmp_ttl(ip: str):
    raw = _run(["ping", "-n", "1", "-w", "1000", ip] if IS_WINDOWS
               else ["ping", "-c", "1", "-W", "1", ip], timeout=3)
    import re
    m = re.search(r"TTL=(\d+)", raw, re.I)
    return int(m.group(1)) if m else None

def os_hint(ip: str, open_ports: list[int]) -> str:
    ttl = _icmp_ttl(ip)
    # роутер: 53/80/443 открыты и TTL 64 — но не Linux-сервер
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