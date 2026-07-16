"""Génération de rapports pour BountyStrike."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .brand import TOOL_NAME, TOOL_VERSION
from .utils import Colors, Finding


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SEVERITY_COLORS_HTML = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#17a2b8",
    "info": "#6c757d",
}


class ReportGenerator:
    """Génère des rapports JSON et HTML des findings."""

    def __init__(self, target: str, findings: list[Finding], recon_data: dict | None = None):
        self.target = target
        self.findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 5))
        self.recon_data = recon_data or {}
        self.timestamp = datetime.utcnow().isoformat()

    def summary(self) -> dict[str, Any]:
        """Résumé statistique des findings."""
        counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        categories: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            categories[f.category] = categories.get(f.category, 0) + 1
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "total": len(self.findings),
            "by_severity": counts,
            "by_category": categories,
        }

    def to_json(self, output_path: Path) -> Path:
        """Exporte le rapport en JSON."""
        report = {
            "summary": self.summary(),
            "recon": self.recon_data,
            "findings": [f.to_dict() for f in self.findings],
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        return output_path

    def to_html(self, output_path: Path) -> Path:
        """Exporte le rapport en HTML."""
        summary = self.summary()
        findings_html = ""
        for f in self.findings:
            color = SEVERITY_COLORS_HTML.get(f.severity, "#6c757d")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}">
                <div class="finding-header">
                    <span class="badge" style="background:{color}">{f.severity.upper()}</span>
                    <h3>{_escape(f.title)}</h3>
                </div>
                <p class="category"><strong>Catégorie:</strong> {_escape(f.category)}</p>
                <p class="url"><strong>URL:</strong> <a href="{_escape(f.url)}">{_escape(f.url)}</a></p>
                <p><strong>Description:</strong> {_escape(f.description)}</p>
                {"<p><strong>Preuve:</strong> <code>" + _escape(f.evidence[:500]) + "</code></p>" if f.evidence else ""}
                {"<p><strong>Remédiation:</strong> " + _escape(f.remediation) + "</p>" if f.remediation else ""}
            </div>
            """

        recon_html = ""
        if self.recon_data:
            techs = self.recon_data.get("technologies", [])
            subdomains = self.recon_data.get("subdomains", [])
            if techs:
                recon_html += f"<p><strong>Technologies:</strong> {', '.join(_escape(t) for t in techs)}</p>"
            if subdomains:
                recon_html += "<p><strong>Sous-domaines:</strong></p><ul>"
                for sd in subdomains:
                    recon_html += f"<li>{_escape(sd)}</li>"
                recon_html += "</ul>"

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{TOOL_NAME} Report — {_escape(self.target)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        h1 {{ color: #58a6ff; margin-bottom: 0.5rem; font-size: 1.8rem; }}
        .meta {{ color: #8b949e; margin-bottom: 2rem; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; }}
        .stat .num {{ font-size: 2rem; font-weight: bold; }}
        .stat .label {{ color: #8b949e; font-size: 0.85rem; }}
        .finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.2rem; margin-bottom: 1rem; }}
        .finding-header {{ display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.8rem; }}
        .badge {{ color: white; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
        h3 {{ font-size: 1.1rem; }}
        .category, .url {{ color: #8b949e; font-size: 0.9rem; margin-bottom: 0.4rem; }}
        a {{ color: #58a6ff; }}
        code {{ background: #0d1117; padding: 0.2rem 0.4rem; border-radius: 3px; font-size: 0.85rem; word-break: break-all; }}
        .recon {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.2rem; margin-bottom: 2rem; }}
        .recon h2 {{ color: #58a6ff; margin-bottom: 1rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ {TOOL_NAME} v{TOOL_VERSION} — Rapport de Bug Bounty</h1>
        <p class="meta">Cible: {_escape(self.target)} | Généré: {self.timestamp}</p>

        <div class="stats">
            <div class="stat"><div class="num" style="color:#dc3545">{summary['by_severity'].get('critical', 0)}</div><div class="label">Critical</div></div>
            <div class="stat"><div class="num" style="color:#fd7e14">{summary['by_severity'].get('high', 0)}</div><div class="label">High</div></div>
            <div class="stat"><div class="num" style="color:#ffc107">{summary['by_severity'].get('medium', 0)}</div><div class="label">Medium</div></div>
            <div class="stat"><div class="num" style="color:#17a2b8">{summary['by_severity'].get('low', 0)}</div><div class="label">Low</div></div>
            <div class="stat"><div class="num" style="color:#6c757d">{summary['by_severity'].get('info', 0)}</div><div class="label">Info</div></div>
            <div class="stat"><div class="num">{summary['total']}</div><div class="label">Total</div></div>
        </div>

        {"<div class='recon'><h2>Reconnaissance</h2>" + recon_html + "</div>" if recon_html else ""}

        <h2 style="color:#58a6ff; margin-bottom:1rem;">Findings ({summary['total']})</h2>
        {findings_html if findings_html else "<p>Aucun finding détecté.</p>"}
    </div>
</body>
</html>"""

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        return output_path

    def print_summary(self) -> None:
        """Affiche un résumé dans le terminal."""
        summary = self.summary()
        print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}RÉSUMÉ DU SCAN{Colors.RESET}")
        print(f"{'='*60}")
        print(f"  Cible: {self.target}")
        print(f"  Total findings: {summary['total']}")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = summary["by_severity"].get(sev, 0)
            if count:
                color = Colors.SEVERITY.get(sev, Colors.WHITE)
                print(f"  {color}{sev.upper()}: {count}{Colors.RESET}")


def _escape(text: str) -> str:
    """Échappe le HTML."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
