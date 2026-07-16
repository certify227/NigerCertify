"""
Audit des en-têtes de sécurité, de CORS et des cookies.
"""

from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from ..core import Finding, HttpClient, log_info


REQUIRED_HEADERS = {
    "Strict-Transport-Security": (
        "medium",
        "HSTS force HTTPS et prévient les downgrades.",
        "Ajouter : Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    ),
    "Content-Security-Policy": (
        "medium",
        "CSP réduit la surface XSS et l'exfiltration de données.",
        "Ajouter une CSP stricte (default-src 'self'; object-src 'none'; ...)",
    ),
    "X-Content-Type-Options": (
        "low",
        "Empêche le MIME-sniffing dangereux.",
        "Ajouter : X-Content-Type-Options: nosniff",
    ),
    "X-Frame-Options": (
        "low",
        "Prévient le clickjacking (ou utiliser frame-ancestors dans CSP).",
        "Ajouter : X-Frame-Options: DENY ou frame-ancestors 'none' dans la CSP",
    ),
    "Referrer-Policy": (
        "low",
        "Contrôle la fuite d'URL via Referer.",
        "Ajouter : Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": (
        "info",
        "Restreint l'usage d'API navigateur puissantes.",
        "Ajouter une Permissions-Policy adaptée (camera=(), geolocation=(), ...)",
    ),
}


def audit(http: HttpClient, target: str) -> List[Finding]:
    log_info(f"Audit d'en-têtes de sécurité sur {target}")
    findings: List[Finding] = []
    r = http.get(target)
    if not r:
        return findings

    headers = {k.lower(): v for k, v in r.headers.items()}

    # ------------------------------------------------------------------
    # En-têtes manquants
    # ------------------------------------------------------------------
    for h, (sev, desc, remediation) in REQUIRED_HEADERS.items():
        if h.lower() not in headers:
            findings.append(Finding(
                module="headers",
                title=f"En-tête de sécurité manquant : {h}",
                severity=sev,
                url=target,
                description=desc,
                evidence="Absent",
                remediation=remediation,
            ))

    # ------------------------------------------------------------------
    # HSTS faible
    # ------------------------------------------------------------------
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        low = hsts.lower()
        try:
            max_age = int(next(
                (part.split("=")[1] for part in low.replace(" ", "").split(";")
                 if part.startswith("max-age=")),
                "0",
            ))
        except ValueError:
            max_age = 0
        if max_age < 15552000:
            findings.append(Finding(
                module="headers",
                title="HSTS max-age trop faible",
                severity="low",
                url=target,
                description=f"max-age={max_age} < 15552000 (6 mois).",
                evidence=f"Strict-Transport-Security: {hsts}",
                remediation="Utiliser max-age ≥ 31536000 et includeSubDomains.",
            ))

    # ------------------------------------------------------------------
    # CORS ouvert
    # ------------------------------------------------------------------
    origin_test = "https://ncscan.evil.example.com"
    r2 = http.get(target, headers={"Origin": origin_test})
    if r2 and r2.headers.get("Access-Control-Allow-Origin"):
        allow = r2.headers.get("Access-Control-Allow-Origin")
        creds = r2.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if allow == "*" and creds:
            findings.append(Finding(
                module="headers",
                title="CORS dangereux : * + credentials",
                severity="high",
                url=target,
                description="Combinaison non permise par la spec, mais dangereuse si respectée.",
                evidence=f"ACAO={allow} + ACAC={creds}",
                remediation="Restreindre ACAO à une liste blanche stricte d'origines.",
                cwe="CWE-942",
            ))
        elif allow == "*":
            findings.append(Finding(
                module="headers",
                title="CORS ouvert à toute origine",
                severity="low",
                url=target,
                description="Access-Control-Allow-Origin: * : les données publiques peuvent être lues par n'importe quel site.",
                evidence=f"ACAO={allow}",
                remediation="Restreindre à des origines identifiées si des données non publiques transitent.",
            ))
        elif allow == origin_test:
            findings.append(Finding(
                module="headers",
                title="CORS reflète Origin arbitraire",
                severity="high" if creds else "medium",
                url=target,
                description="Le serveur reflète l'Origin de la requête sans validation.",
                evidence=f"Origin envoyée: {origin_test} — ACAO renvoyé: {allow} — credentials={creds}",
                remediation="Valider l'Origin contre une liste blanche.",
                cwe="CWE-942",
            ))

    # ------------------------------------------------------------------
    # Cookies
    # ------------------------------------------------------------------
    scheme = urlparse(target).scheme
    for cookie in r.cookies:
        issues = []
        if scheme == "https" and not cookie.secure:
            issues.append("sans Secure")
        # http.cookiejar : httponly / samesite dans _rest
        rest = getattr(cookie, "_rest", {}) or {}
        rest_l = {k.lower(): v for k, v in rest.items()}
        if "httponly" not in rest_l:
            issues.append("sans HttpOnly")
        if "samesite" not in rest_l:
            issues.append("sans SameSite")
        if issues:
            findings.append(Finding(
                module="headers",
                title=f"Cookie non sécurisé : {cookie.name}",
                severity="medium",
                url=target,
                description="Un cookie est défini sans attributs de protection standards.",
                evidence=", ".join(issues),
                remediation="Activer Secure, HttpOnly et SameSite (Lax/Strict) selon l'usage.",
                cwe="CWE-614",
            ))

    # ------------------------------------------------------------------
    # HTTP → HTTPS
    # ------------------------------------------------------------------
    if scheme == "http":
        findings.append(Finding(
            module="headers",
            title="Application servie en HTTP",
            severity="high",
            url=target,
            description="L'application est accessible en clair, exposant les échanges.",
            evidence=f"URL: {target}",
            remediation="Rediriger tout HTTP vers HTTPS et activer HSTS.",
            cwe="CWE-319",
        ))

    return findings
