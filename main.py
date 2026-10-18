
# language: Python 3.11, file: main.py
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(
        description="NetInventory — сканер сети. Без аргументов — меню.")
    parser.add_argument("--subnet")
    parser.add_argument("--ip")
    parser.add_argument("--range")
    parser.add_argument("--from-file", dest="from_file")
    parser.add_argument("--csv"); parser.add_argument("--json"); parser.add_argument("--html")
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--workers", type=int, default=64)
    parser.add_argument("--mdns", action="store_true")
    parser.add_argument("--ssdp", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if not any([args.subnet, args.ip, args.range, args.from_file,
                args.mdns, args.ssdp]):
        from menu import menu_main
        menu_main()
        return

    if args.mdns:
        from discovery import mdns_services
        print("[*] mDNS...")
        for ip, svcs in mdns_services(3.0).items():
            print(f"  {ip}: {', '.join(svcs)}")
    if args.ssdp:
        from discovery import ssdp_devices
        print("[*] SSDP...")
        for d in ssdp_devices(3.0):
            print(f"  {d['ip']:16s} {d['server'][:40]}")
    if args.mdns or args.ssdp:
        return

    # CLI-скан (один из вариантов)
    import ipaddress, time, csv, json
    from scanner import (local_subnet, ping_sweep, arp_table,
        scan_ports_parallel, os_hint, hostname)
    from oui import vendor_for, is_random_mac
    from geolocate import geo, public_ip

    ips = []
    if args.subnet:
        net = ipaddress.IPv4Network(args.subnet, strict=False)
        ips = [str(h) for h in net.hosts()]
    elif args.ip:
        ips = [args.ip]
    elif args.range:
        a, b = args.range.split("-")
        a, b = int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b))
        ips = [str(ipaddress.IPv4Address(i)) for i in range(a, b+1)]
    elif args.from_file:
        with open(args.from_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if "/" in line:
                        net = ipaddress.IPv4Network(line, strict=False)
                        ips.extend(str(h) for h in net.hosts())
                    else:
                        ips.append(line)

    if not args.quiet:
        try:
            ip = public_ip(); g = geo(ip)
            print(f"[*] Внешний IP: {ip}")
            print(f"[*] Гео: {g.get('city')}, {g.get('country')} — {g.get('org')}")
        except Exception: pass

    print(f"[*] Целей: {len(ips)}")
    alive = ping_sweep(ips, args.timeout, args.workers)
    print(f"[*] Живых: {len(alive)}")
    time.sleep(0.5)
    known = arp_table()
    all_ips = list(set(alive) | set(known))
    ports_map = scan_ports_parallel(all_ips, timeout=0.4, workers=args.workers)

    devices = []
    for ip in sorted(all_ips, key=lambda x: tuple(int(p) for p in x.split("."))):
        if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239."):
            continue
        mac = known.get(ip, "").lower()
        ven = vendor_for(mac) if mac else "no MAC"
        if is_random_mac(mac): ven = "randomized MAC"
        devices.append({"ip": ip, "mac": mac or "-",
            "hostname": hostname(ip) or "-", "vendor": ven,
            "os": os_hint(ip, ports_map.get(ip, [])),
            "open_ports": ports_map.get(ip, [])})

    print(f"\n{'IP':16s} {'MAC':18s} {'VENDOR':30s} {'OS':24s} {'HOST':18s} PORTS")
    print("-" * 130)
    for d in devices:
        print(f"{d['ip']:16s} {d['mac']:18s} {d['vendor'][:29]:30s} "
              f"{d['os'][:23]:24s} {d['hostname'][:17]:18s} {d['open_ports']}")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["ip","mac","hostname","vendor","os","open_ports"])
            w.writeheader()
            for d in devices:
                r = dict(d); r["open_ports"] = ";".join(map(str, d["open_ports"]))
                w.writerow(r)
        print(f"[*] CSV: {args.csv}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(devices, f, indent=2, ensure_ascii=False)
        print(f"[*] JSON: {args.json}")
    if args.html:
        from report import write_html
        write_html(devices, args.html)
        print(f"[*] HTML: {args.html}")

if __name__ == "__main__":
    main()