"""WAF detection et intégrations outils externes."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import requests

from .utils import Finding, normalize_url, safe_request

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF": ["awselb", "x-amzn-RequestId", "x-amz-cf-id"],
    "Akamai": ["akamai", "x-akamai-transformed"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-cdn"],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "ModSecurity": ["mod_security", "NOYB"],
    "F5 BIG-IP": ["BIGipServer", "F5_ST"],
    "Barracuda": ["barra_counter_session"],
    "Fortinet": ["FORTIWAFSID"],
    "Wordfence": ["wordfence"],
}


class WAFDetector:
    """Détecte le WAF et suggère des bypass."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.session = session
        self.findings: list[Finding] = []
        self.waf: str | None = None

    def run_full_scan(self) -> list[Finding]:
        resp = safe_request(self.session, "GET", self.target)
        if resp:
            headers_body = str(resp.headers).lower() + resp.text[:500].lower()
            for waf, sigs in WAF_SIGNATURES.items():
                if any(s.lower() in headers_body for s in sigs):
                    self.waf = waf
                    self.findings.append(
                        Finding(
                            title=f"WAF détecté: {waf}",
                            severity="info",
                            category="WAF",
                            url=self.target,
                            description=f"Web Application Firewall: {waf}",
                            evidence=next(s for s in sigs if s.lower() in headers_body),
                        )
                    )
                    break

        # Trigger WAF with malicious payload
        malicious = safe_request(self.session, "GET", f"{self.target}?id=1' OR '1'='1")
        if malicious and malicious.status_code in (403, 406, 429, 503):
            self.findings.append(
                Finding(
                    title="WAF bloque les payloads (403/429)",
                    severity="info",
                    category="WAF",
                    url=self.target,
                    description=f"Status {malicious.status_code} — tester bypass encoding/commentaires",
                )
            )
        return self.findings


class ExternalToolsIntegration:
    """Intègre ffuf, dalfox, sqlmap si installés."""

    def __init__(self, target: str, output_dir: Path):
        self.target = normalize_url(target)
        self.output_dir = output_dir
        self.findings: list[Finding] = []

    def run_all(self) -> list[Finding]:
        self._run_ffuf()
        self._run_dalfox()
        self._run_sqlmap()
        return self.findings

    def _run_ffuf(self) -> None:
        if not shutil.which("ffuf"):
            return
        wordlist = Path(__file__).parent.parent / "wordlists" / "directories.txt"
        if not wordlist.exists():
            return
        try:
            result = subprocess.run(
                ["ffuf", "-u", f"{self.target}/FUZZ", "-w", str(wordlist),
                 "-mc", "200,301,302,403", "-t", "20", "-s", "-timeout", "5"],
                capture_output=True, text=True, timeout=120,
            )
            if result.stdout.strip():
                self.findings.append(
                    Finding(
                        title="ffuf: répertoires trouvés",
                        severity="info",
                        category="External Tool",
                        url=self.target,
                        description="Résultats ffuf",
                        evidence=result.stdout[:500],
                    )
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def _run_dalfox(self) -> None:
        if not shutil.which("dalfox"):
            return
        try:
            result = subprocess.run(
                ["dalfox", "url", self.target, "--silence", "--no-color"],
                capture_output=True, text=True, timeout=120,
            )
            if result.stdout.strip() and "not found" not in result.stdout.lower():
                self.findings.append(
                    Finding(
                        title="Dalfox: XSS trouvé",
                        severity="high",
                        category="External Tool",
                        url=self.target,
                        description="XSS détecté par Dalfox",
                        evidence=result.stdout[:500],
                    )
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def _run_sqlmap(self) -> None:
        if not shutil.which("sqlmap"):
            return
        try:
            result = subprocess.run(
                ["sqlmap", "-u", self.target, "--batch", "--level=1", "--risk=1",
                 "--random-agent", "--timeout=10", "--threads=1"],
                capture_output=True, text=True, timeout=180,
            )
            if "is vulnerable" in result.stdout.lower():
                self.findings.append(
                    Finding(
                        title="SQLMap: injection confirmée",
                        severity="critical",
                        category="External Tool",
                        url=self.target,
                        description="SQLi confirmée par SQLMap",
                        evidence=result.stdout[:500],
                    )
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
