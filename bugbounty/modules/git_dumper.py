"""Git/SVN dump et clickjacking/CSP."""

from __future__ import annotations

import re

import requests

from .utils import Finding, get_base_url, normalize_url, safe_request


class GitDumper:
    """Détecte et extrait les dépôts .git exposés."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.findings: list[Finding] = []

    def run_full_scan(self) -> list[Finding]:
        git_files = [
            (".git/HEAD", "ref:"),
            (".git/config", "[core]"),
            (".git/index", None),
            (".git/logs/HEAD", None),
            (".git/COMMIT_EDITMSG", None),
        ]
        exposed = 0
        for path, indicator in git_files:
            url = f"{self.base_url}/{path}"
            resp = safe_request(self.session, "GET", url)
            if resp and resp.status_code == 200 and len(resp.content) > 0:
                if indicator is None or indicator in resp.text:
                    exposed += 1
                    self.findings.append(
                        Finding(
                            title=f"Git exposé: /{path}",
                            severity="critical" if path == ".git/config" else "high",
                            category="Source Code Exposure",
                            url=url,
                            description="Fichier git accessible — dump possible avec git-dumper",
                            evidence=resp.text[:150],
                            remediation="Bloquer l'accès au dossier .git",
                        )
                    )
        if exposed >= 2:
            self.findings.append(
                Finding(
                    title="Dépôt .git entièrement dumpable",
                    severity="critical",
                    category="Source Code Exposure",
                    url=f"{self.base_url}/.git/",
                    description=f"{exposed} fichiers git accessibles — utiliser git-dumper",
                    remediation="Supprimer .git du webroot immédiatement",
                )
            )
        return self.findings


class ClickjackCSPScanner:
    """Clickjacking et CSP bypass."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.session = session
        self.findings: list[Finding] = []

    def run_full_scan(self) -> list[Finding]:
        resp = safe_request(self.session, "GET", self.target)
        if not resp:
            return self.findings

        xfo = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")

        if not xfo and "frame-ancestors" not in csp.lower():
            self.findings.append(
                Finding(
                    title="Vulnérable au clickjacking",
                    severity="medium",
                    category="Clickjacking",
                    url=self.target,
                    description="Ni X-Frame-Options ni CSP frame-ancestors",
                    remediation="Ajouter X-Frame-Options: DENY ou CSP frame-ancestors 'none'",
                )
            )

        if csp:
            bypasses = []
            if "unsafe-inline" in csp:
                bypasses.append("unsafe-inline")
            if "unsafe-eval" in csp:
                bypasses.append("unsafe-eval")
            if "*" in csp and "default-src" in csp:
                bypasses.append("wildcard default-src")
            if "data:" in csp:
                bypasses.append("data: URI")
            if bypasses:
                self.findings.append(
                    Finding(
                        title="CSP contournable",
                        severity="medium",
                        category="CSP Bypass",
                        url=self.target,
                        description=f"Faiblesses CSP: {', '.join(bypasses)}",
                        evidence=csp[:300],
                    )
                )
        return self.findings
