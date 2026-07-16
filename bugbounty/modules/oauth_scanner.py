"""OAuth, SAML et Account Takeover."""

from __future__ import annotations

import re
import urllib.parse

import requests

from .utils import Finding, get_base_url, normalize_url, safe_request

OAUTH_PATHS = ["/oauth/authorize", "/oauth2/authorize", "/auth/oauth", "/login/oauth", "/api/oauth"]
SAML_PATHS = ["/saml/sso", "/saml/login", "/sso/saml", "/auth/saml"]


class OAuthScanner:
    """Détecte les misconfigurations OAuth/SAML."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.findings: list[Finding] = []

    def run_full_scan(self) -> list[Finding]:
        self._scan_oauth()
        self._scan_saml()
        self._scan_password_reset()
        self._scan_email_change()
        return self.findings

    def _scan_oauth(self) -> None:
        for path in OAUTH_PATHS:
            url = f"{self.base_url}{path}"
            # redirect_uri manipulation
            for malicious_redirect in (
                "https://evil.com",
                "https://evil.com%40legit.com",
                f"{self.base_url}.evil.com",
                "http://localhost",
            ):
                params = {
                    "client_id": "test",
                    "redirect_uri": malicious_redirect,
                    "response_type": "code",
                    "scope": "openid email",
                }
                resp = safe_request(self.session, "GET", url, params=params, allow_redirects=False)
                if not resp:
                    continue
                location = resp.headers.get("Location", "")
                if "evil.com" in location or resp.status_code in (301, 302, 303):
                    if malicious_redirect.split("%")[0] in location:
                        self.findings.append(
                            Finding(
                                title="OAuth redirect_uri non validé",
                                severity="critical",
                                category="OAuth",
                                url=url,
                                description=f"redirect_uri accepté: {malicious_redirect}",
                                evidence=f"Location: {location}",
                                remediation="Whitelist stricte des redirect_uri",
                            )
                        )
                        return

            # state parameter missing
            resp = safe_request(self.session, "GET", url, params={
                "client_id": "test", "redirect_uri": self.target, "response_type": "code",
            })
            if resp and resp.status_code == 200 and "state" not in resp.text.lower():
                self.findings.append(
                    Finding(
                        title="OAuth sans paramètre state",
                        severity="medium",
                        category="OAuth",
                        url=url,
                        description="CSRF possible sur le flow OAuth",
                        remediation="Exiger et valider le paramètre state",
                    )
                )

    def _scan_saml(self) -> None:
        for path in SAML_PATHS:
            url = f"{self.base_url}{path}"
            resp = safe_request(self.session, "GET", url)
            if resp and resp.status_code == 200:
                if any(kw in resp.text.lower() for kw in ("saml", "assertion", "entityid", "sso")):
                    self.findings.append(
                        Finding(
                            title=f"Endpoint SAML découvert: {path}",
                            severity="info",
                            category="SAML",
                            url=url,
                            description="Tester XML signature bypass et comment injection",
                        )
                    )

    def _scan_password_reset(self) -> None:
        reset_paths = ["/reset", "/forgot", "/forgot-password", "/password/reset", "/api/reset-password"]
        for path in reset_paths:
            url = f"{self.base_url}{path}"
            # Host header poisoning
            resp = safe_request(
                self.session, "POST", url,
                data={"email": "test@test.com"},
                headers={"Host": "evil.com", "X-Forwarded-Host": "evil.com"},
            )
            if resp and resp.status_code in (200, 302) and "evil.com" in resp.text:
                self.findings.append(
                    Finding(
                        title="Password Reset Poisoning",
                        severity="critical",
                        category="Account Takeover",
                        url=url,
                        description="Host header injecté dans le lien de reset",
                        evidence="evil.com reflected",
                        remediation="Utiliser un domaine fixe pour les liens de reset",
                    )
                )

    def _scan_email_change(self) -> None:
        paths = ["/change-email", "/api/user/email", "/profile/email", "/account/email"]
        for path in paths:
            url = f"{self.base_url}{path}"
            resp = safe_request(self.session, "POST", url, json={"email": "attacker@evil.com"})
            if resp and resp.status_code in (200, 201):
                self.findings.append(
                    Finding(
                        title=f"Change email sans confirmation: {path}",
                        severity="high",
                        category="Account Takeover",
                        url=url,
                        description="Email modifiable sans vérification",
                        remediation="Exiger confirmation par email",
                    )
                )
