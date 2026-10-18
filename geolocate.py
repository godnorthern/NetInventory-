# language: Python 3.11, file: geolocate.py
import urllib.request
import json

def public_ip():
    """Мой внешний IP."""
    with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
        return r.read().decode().strip()

def geo(ip=None):
    """Город/страна/провайдер по IP. Без IP — по внешнему."""
    target = ip or public_ip()
    url = "https://ipinfo.io/" + target + "/json"
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())