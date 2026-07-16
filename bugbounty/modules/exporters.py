"""Exports HackerOne, Burp, diff de scans."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .utils import Finding


class ReportExporter:
    """Exporte les findings vers différents formats."""

    @staticmethod
    def to_hackerone(findings: list[Finding], output: Path) -> Path:
        lines = []
        for i, f in enumerate(findings, 1):
            if f.severity in ("critical", "high", "medium"):
                lines.append(f"## {i}. {f.title}\n")
                lines.append(f"**Severity:** {f.severity.upper()}\n")
                lines.append(f"**URL:** {f.url}\n")
                lines.append(f"**Description:** {f.description}\n")
                if f.evidence:
                    lines.append(f"**Proof:**\n```\n{f.evidence}\n```\n")
                if f.remediation:
                    lines.append(f"**Remediation:** {f.remediation}\n")
                lines.append("---\n")
        output.write_text("\n".join(lines), encoding="utf-8")
        return output

    @staticmethod
    def to_burp_xml(findings: list[Finding], output: Path) -> Path:
        items = []
        for f in findings:
            items.append(f"""    <item>
      <time>{f.timestamp}</time>
      <url><![CDATA[{f.url}]]></url>
      <hostname>{f.url.split('/')[2] if '/' in f.url else ''}</hostname>
      <path>{f.url}</path>
      <severity>{f.severity}</severity>
      <issueDetail><![CDATA[{f.description}]]></issueDetail>
      <issueBackground><![CDATA[{f.evidence}]]></issueBackground>
      <remediationBackground><![CDATA[{f.remediation}]]></remediationBackground>
      <name><![CDATA[{f.title}]]></name>
    </item>""")
        xml = f"""<?xml version="1.0"?>
<issues burpVersion="2024.1" exportTime="{datetime.utcnow().isoformat()}">
{chr(10).join(items)}
</issues>"""
        output.write_text(xml, encoding="utf-8")
        return output

    @staticmethod
    def diff_scans(old_json: Path, new_json: Path, output: Path) -> dict:
        old_data = json.loads(old_json.read_text())
        new_data = json.loads(new_json.read_text())
        old_titles = {f["title"] for f in old_data.get("findings", [])}
        new_findings = [f for f in new_data.get("findings", []) if f["title"] not in old_titles]
        result = {
            "old_total": old_data.get("summary", {}).get("total", 0),
            "new_total": new_data.get("summary", {}).get("total", 0),
            "new_findings": new_findings,
            "delta": len(new_findings),
        }
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        return result
