"""Dashboard web BountyStrike."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .database import ScanDatabase


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="fr"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BountyStrike Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#0a0e17;color:#e2e8f0}
.header{background:linear-gradient(135deg,#dc2626,#991b1b);padding:1.5rem 2rem}
.header h1{font-size:1.8rem}.header p{opacity:.8;margin-top:.3rem}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;padding:1.5rem 2rem}
.stat{background:#1a1f2e;border:1px solid #2d3748;border-radius:8px;padding:1rem;text-align:center}
.stat .num{font-size:2rem;font-weight:bold;color:#ef4444}
.stat .label{color:#94a3b8;font-size:.85rem}
table{width:calc(100% - 4rem);margin:0 2rem 2rem;border-collapse:collapse}
th,td{padding:.75rem;text-align:left;border-bottom:1px solid #2d3748}
th{background:#1a1f2e;color:#94a3b8}
.critical{color:#ef4444}.high{color:#f97316}.medium{color:#eab308}
.content{padding:0 2rem 2rem}
</style></head><body>
<div class="header"><h1>⚡ BountyStrike Dashboard</h1><p>Strike First. Hunt Smart.</p></div>
<div class="stats" id="stats"></div>
<div class="content"><h2 style="margin-bottom:1rem">Scans récents</h2>
<table><thead><tr><th>ID</th><th>Cible</th><th>Date</th><th>Findings</th><th>Critical</th><th>High</th><th>Durée</th></tr></thead>
<tbody id="scans"></tbody></table></div>
<script>
fetch('/api/stats').then(r=>r.json()).then(d=>{
  document.getElementById('stats').innerHTML=[
    ['Scans',d.scans],['Findings',d.findings],['Critical',d.critical]
  ].map(([l,n])=>'<div class="stat"><div class="num">'+n+'</div><div class="label">'+l+'</div></div>').join('');
});
fetch('/api/scans').then(r=>r.json()).then(scans=>{
  document.getElementById('scans').innerHTML=scans.map(s=>'<tr><td>'+s.id+'</td><td>'+s.target+
    '</td><td>'+s.started_at+'</td><td>'+s.total_findings+'</td><td class="critical">'+
    s.critical+'</td><td class="high">'+s.high+'</td><td>'+(s.duration||0).toFixed(1)+'s</td></tr>').join('');
});
</script></body></html>"""


class DashboardServer:
    """Serveur HTTP pour le dashboard."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8888):
        self.host = host
        self.port = port
        self.db = ScanDatabase()

    def start(self, blocking: bool = False) -> None:
        db = self.db

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path == "/":
                    self._respond(200, "text/html", DASHBOARD_HTML)
                elif parsed.path == "/api/stats":
                    self._respond(200, "application/json", json.dumps(db.get_stats()))
                elif parsed.path == "/api/scans":
                    self._respond(200, "application/json", json.dumps(db.get_recent_scans()))
                elif parsed.path.startswith("/api/findings/"):
                    scan_id = int(parsed.path.split("/")[-1])
                    self._respond(200, "application/json", json.dumps(db.get_findings(scan_id)))
                else:
                    self._respond(404, "text/plain", "Not found")

            def _respond(self, code, ctype, body):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.end_headers()
                self.wfile.write(body.encode() if isinstance(body, str) else body)

        server = HTTPServer((self.host, self.port), Handler)
        if blocking:
            print(f"Dashboard: http://{self.host}:{self.port}")
            server.serve_forever()
        else:
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
