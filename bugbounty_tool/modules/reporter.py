"""
Génération de rapports (JSON + HTML autonome).
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from ..core import Finding, SEVERITY_ORDER, sort_findings


SEVERITY_STYLES = {
    "critical": ("#b91c1c", "#fee2e2"),
    "high":     ("#c2410c", "#ffedd5"),
    "medium":   ("#a16207", "#fef9c3"),
    "low":      ("#0e7490", "#cffafe"),
    "info":     ("#1e40af", "#dbeafe"),
}


def _summary(findings: List[Finding]) -> Dict[str, int]:
    return dict(Counter(f.severity for f in findings))


def write_json(findings: List[Finding], meta: Dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"report-{meta.get('id', 'ncscan')}.json"
    payload = {
        "meta": meta,
        "summary": _summary(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    return path


def write_html(findings: List[Finding], meta: Dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"report-{meta.get('id', 'ncscan')}.html"

    ordered = sort_findings(findings)
    summary = _summary(findings)
    total = len(findings)

    # Cartes récapitulatives
    cards = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        fg, bg = SEVERITY_STYLES[sev]
        count = summary.get(sev, 0)
        cards += (
            f'<div class="card" style="border-color:{fg};background:{bg};color:{fg}">'
            f'<div class="num">{count}</div>'
            f'<div class="lbl">{sev.upper()}</div></div>'
        )

    # Lignes
    rows = ""
    for i, f in enumerate(ordered, 1):
        fg, bg = SEVERITY_STYLES.get(f.severity, ("#334155", "#e2e8f0"))
        payload_html = (
            f'<div class="kv"><b>Payload :</b> <code>{html.escape(f.payload)}</code></div>'
            if f.payload else ""
        )
        cwe_html = (
            f'<div class="kv"><b>CWE :</b> {html.escape(f.cwe)}</div>' if f.cwe else ""
        )
        rows += f"""
        <details class="row">
          <summary>
            <span class="badge" style="background:{fg};color:#fff">{f.severity.upper()}</span>
            <span class="mod">{html.escape(f.module)}</span>
            <span class="ttl">{html.escape(f.title)}</span>
            <span class="url" title="{html.escape(f.url)}">{html.escape(f.url)}</span>
          </summary>
          <div class="body">
            <div class="kv"><b>Description :</b> {html.escape(f.description) or '—'}</div>
            <div class="kv"><b>Preuve :</b> <code>{html.escape(f.evidence) or '—'}</code></div>
            {payload_html}
            {cwe_html}
            <div class="kv"><b>Remédiation :</b> {html.escape(f.remediation) or '—'}</div>
          </div>
        </details>
        """

    doc = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>NCScan — Rapport {html.escape(meta.get('target', ''))}</title>
<style>
  :root {{
    --bg:#0f172a; --panel:#111827; --fg:#e2e8f0; --muted:#94a3b8; --line:#1f2937;
  }}
  * {{ box-sizing:border-box }}
  body {{
    margin:0; font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
    background:linear-gradient(180deg,#020617,#0f172a); color:var(--fg); min-height:100vh;
  }}
  header {{
    padding:32px 40px; border-bottom:1px solid var(--line);
    background:rgba(15,23,42,.7); backdrop-filter:blur(6px);
  }}
  header h1 {{ margin:0 0 8px 0; font-size:26px; letter-spacing:.5px }}
  header .meta {{ color:var(--muted); font-size:13px }}
  header .meta b {{ color:var(--fg) }}
  main {{ padding:32px 40px; max-width:1200px; margin:0 auto }}
  .cards {{ display:grid; grid-template-columns:repeat(5,1fr); gap:14px; margin-bottom:28px }}
  .card {{
    border:1px solid; border-radius:12px; padding:18px; text-align:center;
    font-weight:600;
  }}
  .card .num {{ font-size:32px; line-height:1 }}
  .card .lbl {{ font-size:11px; letter-spacing:2px; margin-top:6px }}
  h2 {{ margin:24px 0 12px; font-size:18px; color:var(--fg); border-left:3px solid #38bdf8; padding-left:10px }}
  .row {{
    background:var(--panel); border:1px solid var(--line); border-radius:10px;
    margin-bottom:8px; overflow:hidden;
  }}
  .row summary {{
    list-style:none; padding:14px 16px; display:grid;
    grid-template-columns:110px 110px 1fr 320px; gap:12px; align-items:center;
    cursor:pointer;
  }}
  .row summary::-webkit-details-marker {{ display:none }}
  .row[open] summary {{ background:#0b1220 }}
  .badge {{
    text-align:center; font-size:11px; padding:4px 8px; border-radius:6px; letter-spacing:1px;
  }}
  .mod {{ color:#38bdf8; font-family:ui-monospace,Menlo,monospace; font-size:12px }}
  .ttl {{ font-weight:600 }}
  .url {{
    color:var(--muted); font-family:ui-monospace,Menlo,monospace; font-size:12px;
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis; text-align:right;
  }}
  .body {{ padding:12px 20px 18px; border-top:1px solid var(--line); background:#0b1220 }}
  .kv {{ margin:6px 0; font-size:14px }}
  .kv b {{ color:#f8fafc }}
  code {{
    background:#020617; padding:2px 6px; border-radius:4px;
    font-family:ui-monospace,Menlo,monospace; font-size:12px; color:#facc15;
    word-break:break-all;
  }}
  footer {{ padding:22px 40px; color:var(--muted); font-size:12px; text-align:center }}
</style>
</head>
<body>
<header>
  <h1>NCScan — Rapport de Bug Bounty Web</h1>
  <div class="meta">
    <b>Cible :</b> {html.escape(meta.get('target', ''))} &nbsp;•&nbsp;
    <b>Date :</b> {html.escape(meta.get('timestamp', ''))} &nbsp;•&nbsp;
    <b>Modules :</b> {html.escape(', '.join(meta.get('modules', [])))} &nbsp;•&nbsp;
    <b>Total :</b> {total}
  </div>
</header>
<main>
  <div class="cards">{cards}</div>
  <h2>Résultats détaillés</h2>
  {rows or '<p style="color:var(--muted)">Aucune découverte.</p>'}
</main>
<footer>
  Généré par NCScan — Niger Certify Offensive Lab.
  Rappel : utiliser uniquement sur des cibles avec autorisation écrite.
</footer>
</body>
</html>"""
    path.write_text(doc, encoding="utf-8")
    return path


def build_meta(target: str, modules: List[str], run_id: str) -> Dict:
    return {
        "id": run_id,
        "target": target,
        "modules": modules,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "tool": "NCScan",
    }
