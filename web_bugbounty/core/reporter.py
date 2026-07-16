"""Génération de rapports : console, JSON, HTML et Markdown."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Iterable, List

from .findings import Finding, Severity, sort_findings

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

HTML_COLORS = {
    Severity.CRITICAL: "#8e44ad",
    Severity.HIGH: "#e74c3c",
    Severity.MEDIUM: "#f39c12",
    Severity.LOW: "#3498db",
    Severity.INFO: "#7f8c8d",
}


def summarize(findings: Iterable[Finding]) -> dict:
    counts = {s.label: 0 for s in SEVERITY_ORDER}
    total = 0
    for f in findings:
        counts[f.severity.label] += 1
        total += 1
    counts["total"] = total
    return counts


def to_json(findings: List[Finding], target: str, meta: dict | None = None) -> str:
    payload = {
        "tool": "web_bugbounty",
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summarize(findings),
        "meta": meta or {},
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_markdown(findings: List[Finding], target: str, meta: dict | None = None) -> str:
    summary = summarize(findings)
    lines = [
        f"# Rapport d'audit — {target}",
        "",
        f"_Généré le {datetime.now(timezone.utc).isoformat()} par web_bugbounty_",
        "",
        "## Résumé",
        "",
        "| Sévérité | Nombre |",
        "|----------|--------|",
    ]
    for s in SEVERITY_ORDER:
        lines.append(f"| {s.label} | {summary[s.label]} |")
    lines.append(f"| **Total** | **{summary['total']}** |")
    lines.append("")
    lines.append("## Détails")
    lines.append("")
    for f in sort_findings(findings):
        lines.append(f"### [{f.severity.label}] {f.title}")
        lines.append("")
        lines.append(f"- **Cible :** `{f.target}`")
        lines.append(f"- **Module :** {f.module}")
        if f.description:
            lines.append(f"- **Description :** {f.description}")
        if f.evidence:
            lines.append(f"- **Preuve :** `{f.evidence}`")
        if f.remediation:
            lines.append(f"- **Remédiation :** {f.remediation}")
        if f.references:
            refs = ", ".join(f.references)
            lines.append(f"- **Références :** {refs}")
        lines.append("")
    return "\n".join(lines)


def to_html(findings: List[Finding], target: str, meta: dict | None = None) -> str:
    summary = summarize(findings)
    rows = []
    for f in sort_findings(findings):
        color = HTML_COLORS.get(f.severity, "#333")
        refs = ""
        if f.references:
            refs = "<br>".join(html.escape(r) for r in f.references)
        rows.append(
            f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f.severity.label}</span></td>
          <td>{html.escape(f.title)}</td>
          <td class="mono">{html.escape(f.target)}</td>
          <td>{html.escape(f.description)}</td>
          <td class="mono">{html.escape(f.evidence)}</td>
          <td>{html.escape(f.remediation)}<br><small>{refs}</small></td>
        </tr>"""
        )
    cards = "".join(
        f'<div class="card" style="border-color:{HTML_COLORS[s]}">'
        f'<div class="num">{summary[s.label]}</div>'
        f'<div class="lbl">{s.label}</div></div>'
        for s in SEVERITY_ORDER
    )
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport web_bugbounty — {html.escape(target)}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0f1220;color:#e6e6ee}}
 header{{padding:24px 32px;background:#171a2b;border-bottom:1px solid #2a2e45}}
 h1{{margin:0;font-size:20px}} .sub{{color:#8a8fb0;font-size:13px;margin-top:4px}}
 .cards{{display:flex;gap:12px;padding:24px 32px;flex-wrap:wrap}}
 .card{{background:#171a2b;border-left:4px solid;border-radius:8px;padding:14px 18px;min-width:96px}}
 .num{{font-size:26px;font-weight:700}} .lbl{{color:#8a8fb0;font-size:12px}}
 table{{width:calc(100% - 64px);margin:0 32px 40px;border-collapse:collapse;background:#171a2b;border-radius:8px;overflow:hidden}}
 th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #2a2e45;vertical-align:top;font-size:13px}}
 th{{background:#1f2340;color:#b9bde0}}
 .badge{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}}
 .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all}}
 small{{color:#8a8fb0}}
</style></head>
<body>
<header>
  <h1>Rapport d'audit — {html.escape(target)}</h1>
  <div class="sub">Généré le {datetime.now(timezone.utc).isoformat()} · {summary['total']} findings · web_bugbounty</div>
</header>
<div class="cards">{cards}</div>
<table>
  <thead><tr><th>Sévérité</th><th>Titre</th><th>Cible</th><th>Description</th><th>Preuve</th><th>Remédiation</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table>
</body></html>"""


def console_report(findings: List[Finding], use_color: bool = True) -> str:
    if not findings:
        return "Aucun finding détecté."
    out = []
    for f in sort_findings(findings):
        out.append(f.colored_line(use_color))
    summary = summarize(findings)
    parts = [f"{s.label}={summary[s.label]}" for s in SEVERITY_ORDER]
    out.append("")
    out.append(f"Résumé : total={summary['total']} | " + " ".join(parts))
    return "\n".join(out)
