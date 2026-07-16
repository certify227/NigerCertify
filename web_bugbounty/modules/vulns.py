"""Checks de vulnérabilités non destructifs (probes légers et sûrs)."""
from __future__ import annotations

import re
import uuid
from typing import List
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..core.findings import Finding, Severity
from ..core.http_client import HttpClient

# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #
def check_cors(client: HttpClient, url: str) -> List[Finding]:
    findings: List[Finding] = []
    evil = "https://evil-bugbounty-test.example"
    resp = client.get(url, headers={"Origin": evil})
    if resp is None:
        return findings
    acao = resp.headers.get("access-control-allow-origin")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()
    if not acao:
        return findings

    if acao == "*":
        sev = Severity.LOW
        desc = "ACAO renvoie '*'. Risque limité sans credentials, mais expose les données publiques cross-origin."
        if acac == "true":
            sev = Severity.HIGH
            desc = "ACAO '*' combiné à Allow-Credentials: true (config invalide mais parfois acceptée)."
        findings.append(
            Finding(
                title="CORS permissif (wildcard)",
                severity=sev,
                target=url,
                module="vulns",
                description=desc,
                evidence=f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac or 'absent'}",
                remediation="Restreindre ACAO à une liste blanche d'origines de confiance.",
                references=["https://portswigger.net/web-security/cors"],
            )
        )
    elif acao == evil or acao == evil + "/":
        sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
        findings.append(
            Finding(
                title="CORS : reflet de l'Origin arbitraire",
                severity=sev,
                target=url,
                module="vulns",
                description="Le serveur reflète l'en-tête Origin fourni par l'attaquant.",
                evidence=f"Origin={evil} → ACAO={acao}; Allow-Credentials={acac or 'absent'}",
                remediation="Valider strictement l'Origin contre une liste blanche; ne jamais refléter aveuglément.",
                references=["https://portswigger.net/web-security/cors"],
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Open redirect
# --------------------------------------------------------------------------- #
REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_uri", "redirect_url", "return",
    "returnUrl", "return_url", "dest", "destination", "continue", "r", "u",
    "goto", "target", "to", "out", "link",
]


def check_open_redirect(client: HttpClient, url: str) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    existing = parse_qs(parsed.query)
    canary_host = "evil-bugbounty-test.example"
    payload = f"https://{canary_host}/"

    params_to_test = list(existing.keys()) or REDIRECT_PARAMS
    seen = set()
    for param in params_to_test:
        if param in seen:
            continue
        seen.add(param)
        # N'attaque que les paramètres à consonance "redirection" pour rester ciblé.
        if not existing and param not in REDIRECT_PARAMS:
            continue
        new_query = dict(existing)
        new_query[param] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(new_query, doseq=True)))
        resp = client.get(test_url, allow_redirects=False)
        if resp is None:
            continue
        location = resp.headers.get("location", "")
        if resp.status_code in (301, 302, 303, 307, 308) and _points_to(location, canary_host):
            findings.append(
                Finding(
                    title="Open redirect potentiel",
                    severity=Severity.MEDIUM,
                    target=test_url,
                    module="vulns",
                    description=f"Le paramètre '{param}' contrôle la redirection vers un domaine externe.",
                    evidence=f"HTTP {resp.status_code} → Location: {location}",
                    remediation="Valider les URLs de redirection contre une liste blanche ou n'autoriser que des chemins relatifs.",
                    references=["https://cwe.mitre.org/data/definitions/601.html"],
                )
            )
    return findings


def _points_to(location: str, host: str) -> bool:
    if not location:
        return False
    loc = location.strip()
    if loc.startswith("//" + host) or loc.startswith("https://" + host) or loc.startswith("http://" + host):
        return True
    parsed = urlparse(loc)
    return parsed.hostname == host


# --------------------------------------------------------------------------- #
# Reflet de paramètre (indicateur XSS)
# --------------------------------------------------------------------------- #
def check_reflection(client: HttpClient, url: str) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(url)
    existing = parse_qs(parsed.query)
    if not existing:
        return findings

    marker = f"bbx{uuid.uuid4().hex[:8]}"
    # Sonde inoffensive contenant des caractères spéciaux HTML.
    probe = f'{marker}"<x>'
    for param in existing:
        new_query = dict(existing)
        new_query[param] = [probe]
        test_url = urlunparse(parsed._replace(query=urlencode(new_query, doseq=True)))
        resp = client.get(test_url)
        if resp is None or not resp.text:
            continue
        body = resp.text
        if probe in body:
            findings.append(
                Finding(
                    title="Reflet non échappé (XSS possible)",
                    severity=Severity.MEDIUM,
                    target=test_url,
                    module="vulns",
                    description=f"Le paramètre '{param}' est reflété sans échappement des caractères < > \".",
                    evidence=f"Sonde '{probe}' retrouvée telle quelle dans la réponse.",
                    remediation="Encoder les sorties selon le contexte (HTML/JS/attribut) et valider les entrées.",
                    references=["https://owasp.org/www-community/attacks/xss/"],
                )
            )
        elif marker in body:
            findings.append(
                Finding(
                    title="Reflet de paramètre (échappé)",
                    severity=Severity.INFO,
                    target=test_url,
                    module="vulns",
                    description=f"Le paramètre '{param}' est reflété mais les caractères spéciaux semblent échappés.",
                    evidence=f"Marqueur '{marker}' présent, caractères spéciaux filtrés.",
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Méthodes HTTP dangereuses
# --------------------------------------------------------------------------- #
def check_http_methods(client: HttpClient, url: str) -> List[Finding]:
    findings: List[Finding] = []
    resp = client.options(url)
    if resp is None:
        return findings
    allow = resp.headers.get("allow", "")
    risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH") if m in allow.upper()]
    if risky:
        findings.append(
            Finding(
                title="Méthodes HTTP potentiellement dangereuses activées",
                severity=Severity.LOW,
                target=url,
                module="vulns",
                description="Le serveur annonce des méthodes HTTP à risque.",
                evidence=f"Allow: {allow}",
                remediation="Désactiver les méthodes non nécessaires (TRACE, PUT, DELETE...).",
            )
        )
    return findings


def run(client: HttpClient, url: str, ctx: dict | None = None) -> List[Finding]:
    findings: List[Finding] = []
    findings += check_cors(client, url)
    findings += check_open_redirect(client, url)
    findings += check_reflection(client, url)
    findings += check_http_methods(client, url)
    return findings
