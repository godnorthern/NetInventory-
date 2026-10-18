# language: Python 3.11, file: menu.py
# Интерактивное меню: скан, настройки, экспорт, mDNS, SSDP
import os
import sys

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def pause():
    input("\nEnter — продолжить...")

def ask(prompt: str, default: str = "") -> str:
    val = input(f"{prompt} [{default}]: ").strip()
    return val or default

def menu_main():
    while True:
        clear()
        print("=" * 60)
        print("  NetInventory — сканер сети")
        print("=" * 60)
        print("  1. Сканировать свою подсеть")
        print("  2. Сканировать другую подсеть (CIDR)")
        print("  3. Сканировать один IP")
        print("  4. Сканировать диапазон IP")
        print("  5. Список из файла")
        print("  6. mDNS-устройства (телефоны, ТВ, принтеры)")
        print("  7. SSDP-устройства (UPnP, роутеры, ТВ)")
        print("  8. Экспорт последнего скана (CSV/JSON/HTML)")
        print("  9. Настройки (timeout, потоки)")
        print("  0. Выход")
        print("=" * 60)
        choice = input("  Выбор: ").strip()

        if choice == "0":
            print("  До связи.")
            return
        elif choice == "1":
            scan_subnet(None)
        elif choice == "2":
            cidr = ask("CIDR", "192.168.1.0/24")
            scan_subnet(cidr)
        elif choice == "3":
            ip = ask("IP")
            if ip: scan_subnet(ip)
        elif choice == "4":
            r = ask("Диапазон", "192.168.1.1-192.168.1.50")
            scan_range(r)
        elif choice == "5":
            path = ask("Путь к файлу")
            if path: scan_file(path)
        elif choice == "6":
            mdns_view()
        elif choice == "7":
            ssdp_view()
        elif choice == "8":
            export_last()
        elif choice == "9":
            settings_view()
        else:
            print("  Нет такого пункта.")
            pause()

_last_result = []

def scan_subnet(target):
    from scanner import (local_subnet, ping_sweep, arp_table,
                         scan_ports_parallel, os_hint, hostname)
    from oui import vendor_for, is_random_mac
    import ipaddress, time

    if target is None:
        net = local_subnet()
        ips = [str(h) for h in net.hosts()]
        print(f"\n[*] Своя подсеть: {net}")
    elif "/" in target:
        try:
            net = ipaddress.IPv4Network(target, strict=False)
            ips = [str(h) for h in net.hosts()]
        except ValueError as e:
            print(f"[!] {e}"); pause(); return
    else:
        ips = [target]

    timeout = SETTINGS["timeout"]
    workers = SETTINGS["workers"]
    print(f"[*] Целей: {len(ips)} (timeout={timeout}, workers={workers})")

    print("[*] Ping-sweep...")
    alive = ping_sweep(ips, timeout, workers)
    print(f"    живых: {len(alive)}")

    time.sleep(0.5)
    print("[*] ARP...")
    known = arp_table()
    print(f"    ARP: {len(known)}")

    all_ips = list(set(alive) | set(known))
    print(f"[*] Скан портов ({workers} потоков)...")
    ports_map = scan_ports_parallel(all_ips, timeout=0.4, workers=workers)

    devices = []
    for ip in sorted(all_ips, key=lambda x: tuple(int(p) for p in x.split("."))):
        if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239."):
            continue
        mac = known.get(ip, "").lower()
        ven = vendor_for(mac) if mac else "no MAC"
        if is_random_mac(mac):
            ven = "randomized MAC"
        devices.append({
            "ip": ip, "mac": mac or "-", "hostname": hostname(ip) or "-",
            "vendor": ven, "os": os_hint(ip, ports_map.get(ip, [])),
            "open_ports": ports_map.get(ip, []),
        })

    global _last_result
    _last_result = devices

    print(f"\n{'IP':16s} {'MAC':18s} {'VENDOR':30s} {'OS':24s} {'HOST':18s} PORTS")
    print("-" * 130)
    for d in devices:
        print(f"{d['ip']:16s} {d['mac']:18s} {d['vendor'][:29]:30s} "
              f"{d['os'][:23]:24s} {d['hostname'][:17]:18s} {d['open_ports']}")
    print(f"\n[*] Найдено устройств: {len(devices)}")
    pause()

def scan_range(rng):
    try:
        start, end = rng.split("-")
        import ipaddress
        a = int(ipaddress.IPv4Address(start.strip()))
        b = int(ipaddress.IPv4Address(end.strip()))
        ips = [str(ipaddress.IPv4Address(i)) for i in range(a, b + 1)]
        # переиспользуем логику: временно сканируем через 'скан подсети' не выйдет,
        # поэтому делаем отдельный вызов
        from scanner import ping_sweep, arp_table, scan_ports_parallel, os_hint, hostname
        from oui import vendor_for, is_random_mac
        import time
        print(f"\n[*] Диапазон: {len(ips)} адресов")
        timeout, workers = SETTINGS["timeout"], SETTINGS["workers"]
        alive = ping_sweep(ips, timeout, workers)
        time.sleep(0.5)
        known = arp_table()
        all_ips = list(set(alive) | set(known))
        ports_map = scan_ports_parallel(all_ips, timeout=0.4, workers=workers)
        devices = []
        for ip in sorted(all_ips, key=lambda x: tuple(int(p) for p in x.split("."))):
            mac = known.get(ip, "").lower()
            ven = vendor_for(mac) if mac else "no MAC"
            if is_random_mac(mac): ven = "randomized MAC"
            devices.append({"ip": ip, "mac": mac or "-",
                "hostname": hostname(ip) or "-", "vendor": ven,
                "os": os_hint(ip, ports_map.get(ip, [])),
                "open_ports": ports_map.get(ip, [])})
        global _last_result
        _last_result = devices
        for d in devices:
            print(f"{d['ip']:16s} {d['mac']:18s} {d['vendor'][:29]:30s} "
                  f"{d['os'][:23]:24s} {d['hostname'][:17]:18s} {d['open_ports']}")
        pause()
    except Exception as e:
        print(f"[!] {e}"); pause()

def scan_file(path):
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        for line in lines:
            print(f"\n[*] Обрабатываю: {line}")
            scan_subnet(line)
    except FileNotFoundError:
        print(f"[!] Нет файла: {path}"); pause()

def mdns_view():
    from discovery import mdns_services
    print("\n[*] mDNS (ждём 3 сек)...")
    res = mdns_services(3.0)
    if not res:
        print("  ничего не найдено")
    for ip, svcs in res.items():
        print(f"  {ip}")
        for s in svcs:
            print(f"      {s}")
    pause()

def ssdp_view():
    from discovery import ssdp_devices
    print("\n[*] SSDP (ждём 3 сек)...")
    res = ssdp_devices(3.0)
    if not res:
        print("  ничего не найдено")
    for d in res:
        print(f"  {d['ip']:16s} {d['server'][:40]:42s} {d['location']}")
    pause()

def export_last():
    if not _last_result:
        print("  нечего экспортировать — сначала скан"); pause(); return
    print("  1. CSV  2. JSON  3. HTML")
    ch = input("  Формат: ").strip()
    name = input("  Имя файла: ").strip() or "scan"
    if ch == "1":
        import csv
        with open(name + ".csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["ip","mac","hostname","vendor","os","open_ports"])
            w.writeheader()
            for d in _last_result:
                row = dict(d); row["open_ports"] = ";".join(map(str, d["open_ports"]))
                w.writerow(row)
        print(f"  -> {name}.csv")
    elif ch == "2":
        import json
        with open(name + ".json", "w", encoding="utf-8") as f:
            json.dump(_last_result, f, indent=2, ensure_ascii=False)
        print(f"  -> {name}.json")
    elif ch == "3":
        from report import write_html
        write_html(_last_result, name + ".html")
        print(f"  -> {name}.html")
    pause()

SETTINGS = {"timeout": 0.5, "workers": 64}

def settings_view():
    clear()
    print("=" * 60)
    print("  Настройки")
    print("=" * 60)
    print(f"  1. timeout ping/port: {SETTINGS['timeout']}")
    print(f"  2. workers:           {SETTINGS['workers']}")
    print("  0. Назад")
    ch = input("  Выбор: ").strip()
    if ch == "1":
        try: SETTINGS["timeout"] = float(input("  Новый timeout: "))
        except: print("  не число"); pause()
    elif ch == "2":
        try: SETTINGS["workers"] = int(input("  Новые workers: "))
        except: print("  не число"); pause()
    elif ch == "0":
        return
    settings_view()