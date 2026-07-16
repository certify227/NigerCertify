"""Génération des rapports (console, JSON, HTML)."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Dict, List

from .findings import SEVERITY_COLORS, Finding, Severity

_RESET = "\033[0m"
_BOLD = "\033[1m"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def dedup(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for f in findings:
        k = f.dedup_key()
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-int(f.severity), f.check, f.url))


def severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts = {s.label: 0 for s in Severity}
    for f in findings:
        counts[f.severity.label] += 1
    return counts


def print_console(findings: List[Finding], color: bool = True) -> None:
    findings = sort_findings(findings)
    if not findings:
        print("\n[+] Aucune découverte. (Cela ne garantit pas l'absence de failles.)")
        return

    print("\n" + "=" * 70)
    print(f"{_BOLD}RÉSULTATS DE L'AUDIT{_RESET}" if color else "RÉSULTATS DE L'AUDIT")
    print("=" * 70)

    for f in findings:
        col = SEVERITY_COLORS.get(f.severity, "") if color else ""
        rst = _RESET if color else ""
        tag = f"[{f.severity.label.upper()}]"
        print(f"\n{col}{tag}{rst} {f.title}")
        print(f"    check   : {f.check}")
        print(f"    url     : {f.url}")
        if f.evidence:
            print(f"    preuve  : {f.evidence[:200]}")
        if f.remediation:
            print(f"    conseil : {f.remediation}")

    print("\n" + "-" * 70)
    counts = severity_counts(findings)
    summary = "  ".join(f"{k}: {v}" for k, v in counts.items() if v)
    print(f"Total: {len(findings)} découverte(s)  |  {summary}")
    print("-" * 70)


def write_json(path: str, target: str, findings: List[Finding], meta: Dict) -> None:
    data = {
        "tool": "WebHunt",
        "target": target,
        "generated_at": _now(),
        "summary": severity_counts(findings),
        "meta": meta,
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


_SEV_HTML_COLOR = {
    "Critical": "#8e24aa",
    "High": "#e53935",
    "Medium": "#fb8c00",
    "Low": "#1e88e5",
    "Info": "#00897b",
}


def write_html(path: str, target: str, findings: List[Finding], meta: Dict) -> None:
    findings = sort_findings(findings)
    counts = severity_counts(findings)
    rows = []
    for f in findings:
        color = _SEV_HTML_COLOR.get(f.severity.label, "#666")
        refs = "".join(
            f'<a href="{html.escape(r)}">{html.escape(r)}</a><br>' for r in f.references
        )
        rows.append(
            f"""
            <tr>
              <td><span class="badge" style="background:{color}">{f.severity.label}</span></td>
              <td>{html.escape(f.title)}</td>
              <td class="mono">{html.escape(f.check)}</td>
              <td class="mono">{html.escape(f.url)}</td>
              <td class="mono small">{html.escape(f.evidence[:300])}</td>
              <td>{html.escape(f.remediation)}{('<br>'+refs) if refs else ''}</td>
            </tr>"""
        )
    badges = "".join(
        f'<span class="pill" style="background:{_SEV_HTML_COLOR.get(k, "#666")}">{k}: {v}</span>'
        for k, v in counts.items()
        if v
    )
    doc = f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebHunt - Rapport {html.escape(target)}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 0; background:#0f1420; color:#e6e9ef; }}
  header {{ padding: 24px 32px; background:#161c2c; border-bottom:1px solid #263049; }}
  h1 {{ margin:0; font-size: 22px; }}
  .meta {{ color:#93a1c0; font-size: 13px; margin-top:6px; }}
  .pills, .badges {{ margin:16px 32px; }}
  .pill {{ display:inline-block; color:#fff; padding:4px 10px; border-radius:20px;
           font-size:12px; margin-right:8px; }}
  table {{ width: calc(100% - 64px); margin: 16px 32px 48px; border-collapse: collapse;
           background:#141a28; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #26314c;
            vertical-align:top; font-size:13px; }}
  th {{ color:#9fb0d0; text-transform:uppercase; font-size:11px; letter-spacing:.05em; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }}
  .mono {{ font-family: ui-monospace, Menlo, monospace; }}
  .small {{ font-size:11px; color:#aab6d0; max-width:320px; word-break:break-all; }}
  a {{ color:#6fa8ff; }}
</style></head>
<body>
<header>
  <h1>WebHunt &mdash; Rapport d'audit</h1>
  <div class="meta">Cible : <b>{html.escape(target)}</b> &middot; Généré le {_now()}
   &middot; {len(findings)} découverte(s)</div>
</header>
<div class="pills">{badges}</div>
<table>
  <thead><tr>
    <th>Gravité</th><th>Titre</th><th>Check</th><th>URL</th>
    <th>Preuve</th><th>Remédiation</th>
  </tr></thead>
  <tbody>{''.join(rows) if rows else '<tr><td colspan="6">Aucune découverte.</td></tr>'}</tbody>
</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
