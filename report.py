# language: Python 3.11, file: report.py
# HTML-отчёт: таблица с сортировкой, поиск, вендор, ОС, порты
import json
import datetime

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>NetInventory — {ts}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0e1116;
color:#d0d7de;margin:0;padding:24px}}
h1{{color:#58a6ff;font-size:20px}}
.meta{{color:#8b949e;margin-bottom:16px}}
table{{width:100%;border-collapse:collapse;background:#161b22;
border-radius:6px;overflow:hidden}}
th,td{{padding:8px 10px;text-align:left;border-bottom:1px solid #30363d;
font-size:13px}}
th{{background:#21262d;color:#8b949e;cursor:pointer;user-select:none;
font-weight:600}}
tr:hover td{{background:#1c2128}}
.ports{{color:#7ee787;font-family:monospace}}
.mac{{font-family:monospace;color:#79c0ff}}
.vendor{{color:#ffa657}}
input{{padding:8px;width:300px;background:#21262d;border:1px solid #30363d;
color:#d0d7de;border-radius:4px;margin-bottom:12px}}
</style></head><body>
<h1>NetInventory</h1>
<div class="meta">Сгенерировано: {ts} · Устройств: {count}</div>
<input id="search" placeholder="Поиск по IP, MAC, вендору, хосту..."
 oninput="filter()">
<table id="tbl"><thead><tr>
<th onclick="sort(0)">IP</th><th onclick="sort(1)">MAC</th>
<th onclick="sort(2)">Вендор</th><th onclick="sort(3)">ОС</th>
<th onclick="sort(4)">Хост</th><th onclick="sort(5)">Порты</th>
</tr></thead><tbody>{rows}</tbody></table>
<script>
function filter(){{const q=document.getElementById('search').value.toLowerCase();
document.querySelectorAll('#tbl tbody tr').forEach(r=>{{
r.style.display = r.textContent.toLowerCase().includes(q)?'':'none';}});}}
function sort(c){{const tb=document.querySelector('#tbl tbody');
const rows=[...tb.rows];const dir=tb.dataset.dir==='asc'?-1:1;
rows.sort((a,b)=>{{
const x=a.cells[c].textContent.trim(), y=b.cells[c].textContent.trim();
const nx=parseFloat(x), ny=parseFloat(y);
return (isNaN(nx)||isNaN(ny))?x.localeCompare(y)*dir:(nx-ny)*dir;}});
tb.dataset.dir=dir===1?'desc':'asc';
rows.forEach(r=>tb.appendChild(r));}}
</script></body></html>"""


def write_html(devices: list[dict], path: str):
    rows = ""
    for d in devices:
        ports = ", ".join(str(p) for p in d["open_ports"]) or "-"
        rows += (
            f"<tr><td>{d['ip']}</td>"
            f"<td class='mac'>{d['mac']}</td>"
            f"<td class='vendor'>{d['vendor']}</td>"
            f"<td>{d['os']}</td>"
            f"<td>{d['hostname']}</td>"
            f"<td class='ports'>{ports}</td></tr>\n"
        )
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = HTML_TEMPLATE.format(ts=ts, count=len(devices), rows=rows)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)