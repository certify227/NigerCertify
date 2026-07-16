"""Détection d'en-têtes de sécurité manquants ou faibles."""

from __future__ import annotations

from typing import List

from ..findings import Finding, Severity
from .base import BaseCheck, CheckContext

_REQUIRED_HEADERS = [
    (
        "content-security-policy",
        Severity.MEDIUM,
        "Content-Security-Policy absent",
        "Une CSP réduit fortement l'impact des XSS et injections de contenu.",
        "Définir une politique CSP restrictive adaptée à l'application.",
    ),
    (
        "strict-transport-security",
        Severity.MEDIUM,
        "HSTS absent",
        "Sans HSTS, les utilisateurs restent vulnérables au downgrade HTTPS.",
        "Ajouter 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    (
        "x-content-type-options",
        Severity.LOW,
        "X-Content-Type-Options absent",
        "Le navigateur peut « sniffer » le type MIME et exécuter du contenu.",
        "Ajouter 'X-Content-Type-Options: nosniff'.",
    ),
    (
        "x-frame-options",
        Severity.LOW,
        "Protection anti-clickjacking absente",
        "La page peut être intégrée dans une iframe (clickjacking).",
        "Ajouter 'X-Frame-Options: DENY' ou une directive CSP frame-ancestors.",
    ),
    (
        "referrer-policy",
        Severity.INFO,
        "Referrer-Policy absent",
        "Des URLs sensibles peuvent fuiter via l'en-tête Referer.",
        "Ajouter 'Referrer-Policy: strict-origin-when-cross-origin'.",
    ),
]


class SecurityHeadersCheck(BaseCheck):
    name = "security-headers"
    description = "Vérifie la présence des en-têtes de sécurité HTTP."
    active = False

    def run(self, ctx: CheckContext) -> List[Finding]:
        findings: List[Finding] = []
        resp = ctx.client.get(ctx.base_url)
        if resp is None:
            return findings
        headers = {k.lower(): v for k, v in resp.headers.items()}

        for key, sev, title, desc, fix in _REQUIRED_HEADERS:
            if key == "strict-transport-security" and not ctx.base_url.lower().startswith("https"):
                continue
            if key not in headers:
                findings.append(
                    Finding(
                        check=self.name,
                        title=title,
                        severity=sev,
                        url=ctx.base_url,
                        description=desc,
                        evidence=f"En-tête '{key}' non présent dans la réponse.",
                        remediation=fix,
                        references=[
                            "https://owasp.org/www-project-secure-headers/"
                        ],
                    )
                )

        # CSP présente mais dangereuse.
        csp = headers.get("content-security-policy", "")
        if csp and ("unsafe-inline" in csp or "*" == csp.strip()):
            findings.append(
                Finding(
                    check=self.name,
                    title="Content-Security-Policy permissive",
                    severity=Severity.LOW,
                    url=ctx.base_url,
                    description="La CSP autorise du contenu inline ou toutes origines.",
                    evidence=csp[:200],
                    remediation="Retirer 'unsafe-inline' et restreindre les sources.",
                )
            )
        return findings
