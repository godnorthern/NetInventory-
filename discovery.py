# language: Python 3.11, file: discovery.py
# mDNS и SSDP — находим "тихие" устройства: телефоны, ТВ, принтеры, роутеры
import socket
import struct
import time

# --- mDNS ---
MDNS_GROUP = ("224.0.0.251", 5353)

def mdns_services(timeout: float = 3.0) -> dict[str, list[str]]:
    """Спрашивает у сети список сервисов через mDNS."""
    results: dict[str, list[str]] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout)
    try:
        s.bind(("", 0))
        # PTR-запрос на _services._dns-sd._udp.local
        query = _build_mdns_query(b"_services._dns-sd._udp.local")
        s.sendto(query, MDNS_GROUP)
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            svc = _parse_mdns_name(data)
            if svc:
                results.setdefault(addr[0], []).append(svc)
    except Exception:
        pass
    finally:
        s.close()
    return results


def _build_mdns_query(name: bytes) -> bytes:
    tid = b"\x00\x00"
    flags = b"\x00\x00"
    qd = b"\x00\x01"
    an = b"\x00\x00"
    ns = b"\x00\x00"
    ar = b"\x00\x00"
    q = b""
    for part in name.split(b"."):
        if not part:
            continue
        q += bytes([len(part)]) + part
    q += b"\x00"
    q += b"\x00\x0c"  # PTR
    q += b"\x00\x01"  # IN
    return tid + flags + qd + an + ns + ar + q


def _parse_mdns_name(data: bytes) -> str | None:
    """Очень грубый парсер: вытаскиваем имена сервисов из ответа."""
    try:
        # ищем ASCII-строку с точками и _ в теле пакета
        txt = data.decode("latin-1", errors="ignore")
        for token in txt.split():
            if "_" in token and "." in token and len(token) < 100:
                return token
    except Exception:
        pass
    return None


# --- SSDP ---
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

def ssdp_devices(timeout: float = 3.0) -> list[dict]:
    """Шлёт M-SEARCH, собирает UPnP-устройства."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()

    results: list[dict] = []
    seen = set()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (SSDP_ADDR, SSDP_PORT))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            if addr[0] in seen:
                continue
            seen.add(addr[0])
            info = {"ip": addr[0], "server": "", "location": ""}
            for line in data.decode("latin-1", errors="ignore").splitlines():
                low = line.lower()
                if low.startswith("server:"):
                    info["server"] = line.split(":", 1)[1].strip()
                elif low.startswith("location:"):
                    info["location"] = line.split(":", 1)[1].strip()
            if info["server"] or info["location"]:
                results.append(info)
    except Exception:
        pass
    finally:
        s.close()
    return results


def discover_all(timeout: float = 3.0) -> dict:
    """Полное обнаружение: mDNS + SSDP."""
    return {
        "mdns": mdns_services(timeout),
        "ssdp": ssdp_devices(timeout),
    }