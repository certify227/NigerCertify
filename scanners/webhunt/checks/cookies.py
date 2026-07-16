"""Analyse des attributs de sécurité des cookies."""

from __future__ import annotations

import re
from typing import List

from ..findings import Finding, Severity
from .base import BaseCheck, CheckContext


class CookieCheck(BaseCheck):
    name = "cookies"
    description = "Vérifie les attributs Secure/HttpOnly/SameSite des cookies."
    active = False

    def run(self, ctx: CheckContext) -> List[Finding]:
        findings: List[Finding] = []
        resp = ctx.client.get(ctx.base_url)
        if resp is None:
            return findings

        # requests fusionne les Set-Cookie ; on relit les en-têtes bruts.
        raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
        if not raw_cookies:
            sc = resp.headers.get("Set-Cookie")
            raw_cookies = [sc] if sc else []

        is_https = ctx.base_url.lower().startswith("https")

        for cookie in raw_cookies:
            name = cookie.split("=", 1)[0].strip()
            low = cookie.lower()
            issues = []
            sev = Severity.LOW

            if is_https and "secure" not in low:
                issues.append("attribut Secure manquant")
            if "httponly" not in low:
                issues.append("attribut HttpOnly manquant")
                if re.search(r"session|sess|auth|token", name, re.I):
                    sev = Severity.MEDIUM
            if "samesite" not in low:
                issues.append("attribut SameSite manquant")

            if issues:
                findings.append(
                    Finding(
                        check=self.name,
                        title=f"Cookie '{name}' faiblement protégé",
                        severity=sev,
                        url=ctx.base_url,
                        description="; ".join(issues),
                        evidence=cookie[:200],
                        remediation=(
                            "Ajouter les attributs Secure, HttpOnly et "
                            "SameSite=Lax/Strict aux cookies sensibles."
                        ),
                        references=[
                            "https://owasp.org/www-community/controls/SecureCookieAttribute"
                        ],
                    )
                )
        return findings
