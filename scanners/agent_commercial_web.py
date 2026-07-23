#!/usr/bin/env python3
"""
Interface web — Agent commercial.
Collez une URL → récupérez emails et téléphones du prospect.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# Permet l'import depuis le même dossier
sys.path.insert(0, str(Path(__file__).resolve().parent))

from commercial_agent import (  # noqa: E402
    load_offers_config,
    prospect_to_dict,
    scan_prospect,
)

HTML_PAGE = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Agent Commercial — Contacts</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=Instrument+Serif:ital@0;1&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg0: #0f1a14;
      --bg1: #16241c;
      --ink: #e8f0ea;
      --muted: #8fa898;
      --accent: #3d9a6a;
      --accent-soft: rgba(61, 154, 106, 0.15);
      --warn: #c4a35a;
      --danger: #c45c5c;
      --line: rgba(232, 240, 234, 0.12);
      --panel: rgba(22, 36, 28, 0.85);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "DM Sans", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(ellipse 80% 50% at 10% -10%, rgba(61, 154, 106, 0.22), transparent 55%),
        radial-gradient(ellipse 60% 40% at 90% 10%, rgba(196, 163, 90, 0.12), transparent 50%),
        linear-gradient(165deg, var(--bg0), var(--bg1) 55%, #0c1410);
    }
    .wrap {
      width: min(920px, calc(100% - 2rem));
      margin: 0 auto;
      padding: 3rem 0 4rem;
    }
    header {
      margin-bottom: 2.25rem;
    }
    .brand {
      font-family: "Instrument Serif", Georgia, serif;
      font-size: clamp(2.4rem, 5vw, 3.4rem);
      font-weight: 400;
      letter-spacing: -0.02em;
      line-height: 1.05;
      margin: 0 0 0.6rem;
    }
    .brand em {
      font-style: italic;
      color: #7ecfa0;
    }
    .lede {
      margin: 0;
      max-width: 36rem;
      color: var(--muted);
      font-size: 1.05rem;
      line-height: 1.5;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      backdrop-filter: blur(8px);
      padding: 1.35rem 1.4rem 1.5rem;
    }
    label {
      display: block;
      font-size: 0.78rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 0.55rem;
    }
    .row {
      display: flex;
      gap: 0.75rem;
      flex-wrap: wrap;
    }
    input[type="url"] {
      flex: 1 1 280px;
      min-width: 0;
      background: rgba(8, 14, 11, 0.65);
      border: 1px solid var(--line);
      color: var(--ink);
      font: inherit;
      font-size: 1rem;
      padding: 0.85rem 1rem;
      outline: none;
    }
    input[type="url"]:focus {
      border-color: rgba(61, 154, 106, 0.55);
      box-shadow: 0 0 0 3px var(--accent-soft);
    }
    button {
      font: inherit;
      font-weight: 600;
      border: none;
      cursor: pointer;
      background: var(--accent);
      color: #06140c;
      padding: 0.85rem 1.35rem;
      transition: transform 0.15s ease, filter 0.15s ease;
    }
    button:hover { filter: brightness(1.08); }
    button:active { transform: translateY(1px); }
    button:disabled {
      opacity: 0.55;
      cursor: wait;
    }
    .opts {
      display: flex;
      gap: 1.25rem;
      flex-wrap: wrap;
      margin-top: 1rem;
      color: var(--muted);
      font-size: 0.92rem;
    }
    .opts label {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      text-transform: none;
      letter-spacing: 0;
      font-size: 0.92rem;
      margin: 0;
      cursor: pointer;
      color: var(--muted);
    }
    .status {
      margin-top: 1rem;
      min-height: 1.4rem;
      color: var(--muted);
      font-size: 0.95rem;
    }
    .status.err { color: var(--danger); }
    .results {
      margin-top: 1.75rem;
      display: none;
      animation: rise 0.35s ease;
    }
    .results.show { display: block; }
    @keyframes rise {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem 1.25rem;
      margin-bottom: 1.25rem;
      color: var(--muted);
      font-size: 0.92rem;
    }
    .meta strong { color: var(--ink); font-weight: 600; }
    .score {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.2rem 0.55rem;
      background: var(--accent-soft);
      color: #7ecfa0;
      font-weight: 600;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1rem;
    }
    .block {
      border: 1px solid var(--line);
      background: rgba(8, 14, 11, 0.45);
      padding: 1.1rem 1.15rem 1.2rem;
    }
    .block h2 {
      margin: 0 0 0.85rem;
      font-size: 0.78rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--muted);
      font-weight: 600;
    }
    .item {
      padding: 0.55rem 0;
      border-top: 1px solid var(--line);
      word-break: break-all;
    }
    .item:first-of-type { border-top: none; padding-top: 0; }
    .item a {
      color: #9fd9b8;
      text-decoration: none;
    }
    .item a:hover { text-decoration: underline; }
    .reason {
      display: block;
      margin-top: 0.2rem;
      color: var(--muted);
      font-size: 0.82rem;
    }
    .empty {
      color: var(--warn);
      font-size: 0.95rem;
    }
    .actions {
      margin-top: 1.15rem;
      display: flex;
      gap: 0.65rem;
      flex-wrap: wrap;
    }
    .ghost {
      background: transparent;
      color: var(--ink);
      border: 1px solid var(--line);
    }
    footer {
      margin-top: 2.5rem;
      color: var(--muted);
      font-size: 0.82rem;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1 class="brand">Agent <em>Commercial</em></h1>
      <p class="lede">
        Donnez l’URL d’un prospect : l’agent parcourt le site (accueil, contact, à propos…)
        et extrait les emails et numéros de téléphone exploitables.
      </p>
    </header>

    <section class="panel">
      <label for="url">URL du prospect</label>
      <form id="form" class="row">
        <input id="url" name="url" type="url" required
               placeholder="https://entreprise-exemple.fr"
               autocomplete="url" />
        <button type="submit" id="go">Analyser</button>
      </form>
      <div class="opts">
        <label><input type="checkbox" id="follow" checked /> Parcourir pages contact / à propos</label>
        <label>Région tél.
          <select id="region" style="margin-left:.35rem;background:#0c1410;color:var(--ink);border:1px solid var(--line);padding:.25rem .4rem;font:inherit">
            <option value="FR">FR</option>
            <option value="BE">BE</option>
            <option value="CH">CH</option>
            <option value="CA">CA</option>
            <option value="US">US</option>
          </select>
        </label>
      </div>
      <div class="status" id="status"></div>
    </section>

    <section class="results" id="results">
      <div class="meta" id="meta"></div>
      <div class="grid">
        <div class="block">
          <h2>Emails</h2>
          <div id="emails"></div>
        </div>
        <div class="block">
          <h2>Téléphones</h2>
          <div id="phones"></div>
        </div>
      </div>
      <div class="actions">
        <button type="button" class="ghost" id="copy">Copier les contacts</button>
        <button type="button" class="ghost" id="download">Télécharger JSON</button>
      </div>
    </section>

    <footer>Usage commercial / prospection — respectez le RGPD et les CGU des sites ciblés.</footer>
  </div>

  <script>
    const form = document.getElementById("form");
    const statusEl = document.getElementById("status");
    const results = document.getElementById("results");
    const go = document.getElementById("go");
    let lastPayload = null;

    function esc(s) {
      return String(s).replace(/[&<>"']/g, c => ({
        "&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"
      })[c]);
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const url = document.getElementById("url").value.trim();
      const follow = document.getElementById("follow").checked;
      const region = document.getElementById("region").value;
      statusEl.className = "status";
      statusEl.textContent = "Analyse en cours… l’agent visite les pages pertinentes.";
      results.classList.remove("show");
      go.disabled = true;

      try {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url, follow_pages: follow, region }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Échec de l’analyse");
        lastPayload = data;
        render(data);
        statusEl.textContent = data.error
          ? ("Terminé avec erreur : " + data.error)
          : ("Analyse terminée — " + (data.pages_scanned || []).length + " page(s).");
        if (data.error) statusEl.classList.add("err");
      } catch (err) {
        statusEl.textContent = err.message || String(err);
        statusEl.classList.add("err");
      } finally {
        go.disabled = false;
      }
    });

    function render(data) {
      document.getElementById("meta").innerHTML =
        "<span><strong>" + esc(data.company_name || "Prospect") + "</strong></span>" +
        "<span>" + esc(data.url || "") + "</span>" +
        (data.sector ? "<span>Secteur : " + esc(data.sector) + "</span>" : "") +
        "<span class=\\"score\\">Score " + esc(String(data.opportunity_score ?? 0)) + "/100</span>";

      const emails = data.emails || [];
      const phones = data.phones || [];
      document.getElementById("emails").innerHTML = emails.length
        ? emails.map(e =>
            "<div class=\\"item\\"><a href=\\"mailto:" + esc(e.email) + "\\">" + esc(e.email) +
            "</a><span class=\\"reason\\">" + esc(e.reason || "") + "</span></div>"
          ).join("")
        : "<p class=\\"empty\\">Aucun email trouvé</p>";

      document.getElementById("phones").innerHTML = phones.length
        ? phones.map(p =>
            "<div class=\\"item\\"><a href=\\"tel:" + esc(p.replace(/\\s/g, "")) + "\\">" + esc(p) + "</a></div>"
          ).join("")
        : "<p class=\\"empty\\">Aucun téléphone trouvé</p>";

      results.classList.add("show");
    }

    document.getElementById("copy").addEventListener("click", async () => {
      if (!lastPayload) return;
      const emails = (lastPayload.emails || []).map(e => e.email).join("\\n");
      const phones = (lastPayload.phones || []).join("\\n");
      const text = "Emails:\\n" + (emails || "(aucun)") + "\\n\\nTéléphones:\\n" + (phones || "(aucun)");
      await navigator.clipboard.writeText(text);
      statusEl.textContent = "Contacts copiés dans le presse-papiers.";
    });

    document.getElementById("download").addEventListener("click", () => {
      if (!lastPayload) return;
      const blob = new Blob([JSON.stringify(lastPayload, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "dossier-prospect.json";
      a.click();
      URL.revokeObjectURL(a.href);
    });
  </script>
</body>
</html>
"""


class CommercialAgentHandler(BaseHTTPRequestHandler):
    server_version = "AgentCommercial/1.0"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, HTML_PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/health":
            self._json(200, {"ok": True, "service": "agent-commercial"})
            return
        self._json(404, {"error": "Introuvable"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/api/scan":
            self._json(404, {"error": "Introuvable"})
            return

        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        content_type = self.headers.get("Content-Type", "")

        try:
            if "application/json" in content_type:
                data = json.loads(raw.decode("utf-8") or "{}")
            else:
                form = parse_qs(raw.decode("utf-8"))
                data = {
                    "url": (form.get("url") or [""])[0],
                    "follow_pages": (form.get("follow_pages") or ["true"])[0].lower() != "false",
                    "region": (form.get("region") or ["FR"])[0],
                }
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._json(400, {"error": f"Corps de requête invalide : {exc}"})
            return

        url = (data.get("url") or "").strip()
        if not url:
            self._json(400, {"error": "Fournissez une URL."})
            return

        follow = bool(data.get("follow_pages", True))
        region = (data.get("region") or "FR").strip() or "FR"
        timeout = int(data.get("timeout") or 15)
        offers = getattr(self.server, "offers", None)

        try:
            profile = scan_prospect(
                url,
                follow_pages=follow,
                timeout=timeout,
                region=region,
                offers=offers,
            )
            self._json(200, prospect_to_dict(profile))
        except Exception as exc:  # noqa: BLE001 — surface error to UI
            self._json(500, {"error": str(exc)})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Interface web de l'agent commercial (emails + téléphones depuis une URL)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Hôte (défaut: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Port (défaut: 8765)")
    parser.add_argument("--offers", help="Fichier JSON d'offres pour le matching")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    offers = load_offers_config(args.offers) if args.offers else None

    server = ThreadingHTTPServer((args.host, args.port), CommercialAgentHandler)
    server.offers = offers

    print(f"[*] Agent commercial web → http://{args.host}:{args.port}")
    print("[*] Collez une URL pour récupérer emails et téléphones.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Arrêt.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
