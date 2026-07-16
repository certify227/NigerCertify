"""Intégration Nuclei + checks CVE intégrés pour WebBounty."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import requests

from .utils import Finding, get_base_url, normalize_url, safe_request

# Checks CVE/intégrés quand Nuclei n'est pas installé
BUILTIN_NUCLEI_CHECKS = [
    {
        "name": "Spring Boot Actuator exposed",
        "path": "/actuator",
        "match": ["_links", "health", "beans"],
        "severity": "high",
    },
    {
        "name": "Spring Boot env exposed",
        "path": "/actuator/env",
        "match": ["propertySources", "systemProperties"],
        "severity": "critical",
    },
    {
        "name": "Docker API exposed",
        "path": "/v1.24/containers/json",
        "match": ["Id", "Names", "Image"],
        "severity": "critical",
    },
    {
        "name": "Kubernetes API exposed",
        "path": "/api/v1/namespaces",
        "match": ["items", "metadata"],
        "severity": "critical",
    },
    {
        "name": "Elasticsearch exposed",
        "path": "/_cat/indices",
        "match": ["health", "index", "docs.count"],
        "severity": "critical",
    },
    {
        "name": "Redis unauthorized",
        "path": "/",
        "match": ["redis_version"],
        "severity": "critical",
        "headers": {"Command": "INFO"},
    },
    {
        "name": "Jenkins script console",
        "path": "/script",
        "match": ["println", "groovy", "Jenkins"],
        "severity": "critical",
    },
    {
        "name": "GitLab user enum",
        "path": "/users/sign_in",
        "match": ["GitLab", "sign_in"],
        "severity": "info",
    },
    {
        "name": "Swagger UI exposed",
        "path": "/swagger-ui.html",
        "match": ["swagger", "api-docs"],
        "severity": "medium",
    },
    {
        "name": "Debug mode Laravel",
        "path": "/",
        "match": ["Whoops", "Illuminate\\", "vendor/laravel"],
        "severity": "high",
    },
    {
        "name": "Symfony profiler",
        "path": "/_profiler",
        "match": ["profiler", "Symfony"],
        "severity": "high",
    },
    {
        "name": "PHPMyAdmin exposed",
        "path": "/phpmyadmin/",
        "match": ["phpMyAdmin", "pma_"],
        "severity": "high",
    },
    {
        "name": "Tomcat manager",
        "path": "/manager/html",
        "match": ["Tomcat", "manager"],
        "severity": "critical",
    },
    {
        "name": "WebDAV enabled",
        "path": "/",
        "match": [],
        "severity": "medium",
        "method": "PROPFIND",
    },
    {
        "name": "CORS preflight wildcard",
        "path": "/",
        "match": [],
        "severity": "medium",
        "check_cors": True,
    },
    {
        "name": "Exposed .DS_Store",
        "path": "/.DS_Store",
        "match": ["Bud1"],
        "severity": "low",
        "binary": True,
    },
    {
        "name": "Server Status Apache",
        "path": "/server-status",
        "match": ["Apache Server Status", "Server Version"],
        "severity": "medium",
    },
    {
        "name": "Exposed backup files",
        "path": "/backup.zip",
        "match": ["PK"],
        "severity": "high",
        "binary": True,
    },
    {
        "name": "WordPress debug log",
        "path": "/wp-content/debug.log",
        "match": ["PHP", "error", "warning"],
        "severity": "high",
    },
    {
        "name": "Exposed API keys in JS",
        "path": "/static/js/main.js",
        "match": ["api_key", "apikey", "secret_key", "aws_access"],
        "severity": "high",
    },
]


class NucleiScanner:
    """Intégration Nuclei + scanner CVE intégré."""

    def __init__(self, target: str, session: requests.Session, templates: str | None = None):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.templates = templates
        self.findings: list[Finding] = []
        self.nuclei_available = shutil.which("nuclei") is not None

    def run_full_scan(self) -> list[Finding]:
        """Lance Nuclei si disponible, sinon checks intégrés."""
        if self.nuclei_available:
            self._run_nuclei()
        else:
            self.findings.append(
                Finding(
                    title="Nuclei non installé — utilisation des checks intégrés",
                    severity="info",
                    category="Nuclei",
                    url=self.target,
                    description="Installez Nuclei: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                )
            )
            self._run_builtin_checks()
        return self.findings

    def _run_nuclei(self) -> None:
        """Exécute Nuclei et parse les résultats JSON."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_file = tmp.name

        cmd = [
            "nuclei",
            "-u", self.target,
            "-jsonl",
            "-o", output_file,
            "-silent",
            "-nc",
            "-rate-limit", "50",
            "-timeout", "10",
        ]

        if self.templates:
            cmd.extend(["-t", self.templates])
        else:
            cmd.extend([
                "-severity", "critical,high,medium",
                "-tags", "cve,misconfig,exposure,default-login,takeover",
            ])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            output_path = Path(output_file)
            if output_path.exists():
                for line in output_path.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        finding_data = json.loads(line)
                        self.findings.append(self._parse_nuclei_finding(finding_data))
                    except json.JSONDecodeError:
                        continue
                output_path.unlink(missing_ok=True)

            if result.returncode not in (0, 1) and not self.findings:
                self.findings.append(
                    Finding(
                        title="Erreur Nuclei",
                        severity="info",
                        category="Nuclei",
                        url=self.target,
                        description=f"Nuclei exit code: {result.returncode}",
                        evidence=result.stderr[:500],
                    )
                )
        except subprocess.TimeoutExpired:
            self.findings.append(
                Finding(
                    title="Nuclei timeout (300s)",
                    severity="info",
                    category="Nuclei",
                    url=self.target,
                    description="Le scan Nuclei a dépassé le timeout",
                )
            )
        except FileNotFoundError:
            self.nuclei_available = False
            self._run_builtin_checks()

    def _parse_nuclei_finding(self, data: dict[str, Any]) -> Finding:
        """Convertit un finding Nuclei en Finding WebBounty."""
        info = data.get("info", {})
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
            "unknown": "info",
        }
        return Finding(
            title=f"[Nuclei] {info.get('name', data.get('template-id', 'Unknown'))}",
            severity=severity_map.get(info.get("severity", "info"), "info"),
            category=f"Nuclei — {info.get('tags', ['cve'])[0] if info.get('tags') else 'scan'}",
            url=data.get("matched-at", data.get("host", self.target)),
            description=info.get("description", ""),
            evidence=data.get("curl-command", "")[:300] or json.dumps(data.get("extracted-results", ""))[:300],
            remediation=info.get("reference", [""])[0] if info.get("reference") else "",
        )

    def _run_builtin_checks(self) -> None:
        """Exécute les checks CVE intégrés."""
        for check in BUILTIN_NUCLEI_CHECKS:
            self._run_single_check(check)

    def _run_single_check(self, check: dict[str, Any]) -> None:
        """Exécute un check intégré."""
        url = f"{self.base_url}{check['path']}"
        method = check.get("method", "GET")
        headers = check.get("headers", {})

        if check.get("check_cors"):
            resp = safe_request(
                self.session, "OPTIONS", url,
                headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"},
            )
            if resp and resp.headers.get("Access-Control-Allow-Origin") == "*":
                self.findings.append(
                    Finding(
                        title=f"[Builtin] {check['name']}",
                        severity=check["severity"],
                        category="Nuclei-Builtin",
                        url=url,
                        description="CORS wildcard détecté",
                        evidence=str(dict(resp.headers))[:300],
                    )
                )
            return

        resp = safe_request(self.session, method, url, headers=headers)
        if not resp or resp.status_code not in (200, 201, 204, 301, 302, 401, 403):
            return

        if check.get("binary"):
            content = resp.content[:500]
            matched = any(m.encode() in content for m in check["match"]) if check["match"] else True
        else:
            content = resp.text[:2000]
            matched = all(m.lower() in content.lower() for m in check["match"]) if check["match"] else resp.status_code == 200

        if matched:
            self.findings.append(
                Finding(
                    title=f"[Builtin] {check['name']}",
                    severity=check["severity"],
                    category="Nuclei-Builtin",
                    url=url,
                    description=f"Check intégré positif: {check['name']}",
                    evidence=content[:300] if not check.get("binary") else f"HTTP {resp.status_code}, {len(resp.content)} bytes",
                )
            )
