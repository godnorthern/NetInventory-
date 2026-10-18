# language: Python 3.11, file: oui.py
from mac_vendor_lookup import MacLookup, BaseMacLookup
import os, pathlib

# кладём базу в папку проекта, чтобы не качать каждый раз
_cache = pathlib.Path(__file__).parent / "oui_cache"
_cache.mkdir(exist_ok=True)
BaseMacLookup.cache_path = str(_cache / "manuf")

_lookup = MacLookup()
try:
    _lookup.load_vendors()
except Exception:
    pass  # база уже есть локально

def vendor_for(mac: str) -> str:
    if not mac:
        return "unknown"
    try:
        return _lookup.lookup(mac)
    except Exception:
        return "unknown"

def is_random_mac(mac: str) -> bool:
    """True, если MAC локально-администрируемый (рандомизация iOS/Android)."""
    if not mac:
        return False
    try:
        first = int(mac.split(":")[0], 16)
    except Exception:
        return False
    return bool(first & 0x02)  # бит 2 первого октета