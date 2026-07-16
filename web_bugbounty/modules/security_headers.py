"""Analyse des en-têtes de sécurité HTTP et des attributs de cookies."""
from __future__ import annotations

from typing import List

from ..core.findings import Finding, Severity
from ..core.http_client import HttpClient

# (nom d'en-tête, sévérité si absent, remédiation)
SECURITY_HEADERS = [
    (
        "content-security-policy",
        Severity.MEDIUM,
        "Définir une CSP restrictive pour limiter le XSS et l'injection de contenu.",
    ),
    (
        "strict-transport-security",
        Severity.MEDIUM,
        "Activer HSTS (max-age >= 31536000; includeSubDomains) pour forcer HTTPS.",
    ),
    (
        "x-frame-options",
        Severity.LOW,
        "Ajouter X-Frame-Options: DENY ou une directive frame-ancestors dans la CSP (anti clickjacking).",
    ),
    (
        "x-content-type-options",
        Severity.LOW,
        "Ajouter X-Content-Type-Options: nosniff pour empêcher le MIME sniffing.",
    ),
    (
        "referrer-policy",
        Severity.LOW,
        "Définir Referrer-Policy (ex: strict-origin-when-cross-origin).",
    ),
    (
        "permissions-policy",
        Severity.INFO,
        "Restreindre les fonctionnalités du navigateur via Permissions-Policy.",
    ),
]

# En-têtes qui divulguent des informations.
INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


def _check_hsts_value(value: str) -> str | None:
    v = value.lower()
    problems = []
    if "max-age" in v:
        try:
            age = int(v.split("max-age=")[1].split(";")[0].strip())
            if age < 31536000:
                problems.append(f"max-age faible ({age})")
        except (ValueError, IndexError):
            problems.append("max-age illisible")
    if "includesubdomains" not in v:
        problems.append("includeSubDomains manquant")
    return "; ".join(problems) if problems else None


def run(client: HttpClient, url: str, ctx: dict | None = None) -> List[Finding]:
    findings: List[Finding] = []
    resp = client.get(url)
    if resp is None:
        return findings
    headers = {k.lower(): v for k, v in resp.headers.items()}

    for name, severity, remediation in SECURITY_HEADERS:
        if name not in headers:
            findings.append(
                Finding(
                    title=f"En-tête de sécurité manquant : {name}",
                    severity=severity,
                    target=url,
                    module="security_headers",
                    description=f"L'en-tête HTTP {name} n'est pas renvoyé.",
                    remediation=remediation,
                    references=["https://owasp.org/www-project-secure-headers/"],
                )
            )
        elif name == "strict-transport-security":
            issue = _check_hsts_value(headers[name])
            if issue:
                findings.append(
                    Finding(
                        title="Configuration HSTS faible",
                        severity=Severity.LOW,
                        target=url,
                        module="security_headers",
                        description="HSTS présent mais mal configuré.",
                        evidence=f"{headers[name]} → {issue}",
                        remediation="max-age >= 31536000; includeSubDomains; preload.",
                    )
                )

    leaks = [f"{h}: {headers[h]}" for h in INFO_LEAK_HEADERS if h in headers]
    if leaks:
        findings.append(
            Finding(
                title="Divulgation d'informations via en-têtes",
                severity=Severity.LOW,
                target=url,
                module="security_headers",
                description="Des en-têtes révèlent le serveur / la techno et leur version.",
                evidence=" | ".join(leaks),
                remediation="Supprimer ou masquer ces en-têtes.",
            )
        )

    findings += _check_cookies(resp, url)
    return findings


def _check_cookies(resp, url: str) -> List[Finding]:
    findings: List[Finding] = []
    is_https = url.lower().startswith("https://")
    # requests fusionne les Set-Cookie ; on relit les en-têtes bruts si possible.
    raw_cookies = resp.headers.get("set-cookie")
    set_cookie_values = []
    if hasattr(resp, "raw") and getattr(resp.raw, "headers", None):
        try:
            set_cookie_values = resp.raw.headers.getlist("Set-Cookie")  # type: ignore[attr-defined]
        except Exception:
            set_cookie_values = []
    if not set_cookie_values and raw_cookies:
        set_cookie_values = [raw_cookies]

    for cookie in set_cookie_values:
        low = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        problems = []
        if "httponly" not in low:
            problems.append("HttpOnly manquant")
        if is_https and "secure" not in low:
            problems.append("Secure manquant")
        if "samesite" not in low:
            problems.append("SameSite manquant")
        if problems:
            findings.append(
                Finding(
                    title=f"Cookie non durci : {name}",
                    severity=Severity.LOW,
                    target=url,
                    module="security_headers",
                    description="Attributs de sécurité manquants sur un cookie.",
                    evidence="; ".join(problems),
                    remediation="Ajouter les attributs HttpOnly, Secure et SameSite.",
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                )
            )
    return findings
