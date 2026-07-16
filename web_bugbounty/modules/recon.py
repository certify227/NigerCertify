"""Reconnaissance : fingerprint techno, en-têtes, robots.txt, sitemap."""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urljoin, urlparse

from ..core.findings import Finding, Severity
from ..core.http_client import HttpClient

# Signatures simples de technologies via en-têtes / corps.
TECH_HEADER_SIGNS = {
    "server": "Serveur",
    "x-powered-by": "Powered-By",
    "x-aspnet-version": "ASP.NET",
    "x-aspnetmvc-version": "ASP.NET MVC",
    "x-generator": "Générateur",
    "via": "Proxy/CDN",
    "x-drupal-cache": "Drupal",
    "x-varnish": "Varnish",
}

TECH_BODY_SIGNS = [
    (re.compile(r"wp-content|wp-includes", re.I), "WordPress"),
    (re.compile(r"/sites/default/files|Drupal.settings", re.I), "Drupal"),
    (re.compile(r"Joomla!|/media/jui/", re.I), "Joomla"),
    (re.compile(r"csrf-token|Laravel", re.I), "Laravel"),
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"ng-version=", re.I), "Angular"),
    (re.compile(r"data-reactroot|react-dom", re.I), "React"),
    (re.compile(r"__NUXT__", re.I), "Nuxt.js"),
    (re.compile(r"Shopify\.", re.I), "Shopify"),
]


def fingerprint(client: HttpClient, url: str) -> List[Finding]:
    findings: List[Finding] = []
    resp = client.get(url)
    if resp is None:
        return [
            Finding(
                title="Cible injoignable",
                severity=Severity.INFO,
                target=url,
                module="recon",
                description="Aucune réponse HTTP obtenue.",
            )
        ]

    detected = []
    for header, label in TECH_HEADER_SIGNS.items():
        if header in resp.headers:
            value = resp.headers[header]
            detected.append(f"{label}: {value}")

    body = resp.text[:200000] if resp.text else ""
    for pattern, label in TECH_BODY_SIGNS:
        if pattern.search(body):
            detected.append(f"Techno détectée: {label}")

    if detected:
        findings.append(
            Finding(
                title="Empreinte technologique",
                severity=Severity.INFO,
                target=url,
                module="recon",
                description="Technologies / composants identifiés via en-têtes et contenu.",
                evidence=" | ".join(sorted(set(detected))),
                remediation="Masquer les bannières de version (Server, X-Powered-By) pour limiter la reconnaissance.",
            )
        )

    findings.append(
        Finding(
            title="Réponse HTTP de base",
            severity=Severity.INFO,
            target=url,
            module="recon",
            description="Code de statut et titre de la page d'accueil.",
            evidence=f"HTTP {resp.status_code} · titre={_extract_title(body)!r} · {len(body)} octets",
        )
    )
    return findings


def _extract_title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return m.group(1).strip()[:120] if m else ""


def robots_and_sitemap(client: HttpClient, url: str) -> List[Finding]:
    findings: List[Finding] = []
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    robots_url = urljoin(base + "/", "robots.txt")
    resp = client.get(robots_url)
    if resp is not None and resp.status_code == 200 and resp.text.strip():
        disallowed = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", resp.text)
        sitemaps = re.findall(r"(?im)^\s*Sitemap:\s*(\S+)", resp.text)
        evidence = f"{len(disallowed)} règles Disallow"
        if disallowed:
            evidence += f" (ex: {', '.join(disallowed[:8])})"
        findings.append(
            Finding(
                title="robots.txt exposé",
                severity=Severity.INFO,
                target=robots_url,
                module="recon",
                description="Le fichier robots.txt peut révéler des chemins sensibles.",
                evidence=evidence,
                extra={"disallowed": disallowed, "sitemaps": sitemaps},
            )
        )

    for sm in ("sitemap.xml", "sitemap_index.xml"):
        sm_url = urljoin(base + "/", sm)
        r = client.get(sm_url)
        if r is not None and r.status_code == 200 and "<urlset" in r.text.lower() or (
            r is not None and "<sitemapindex" in (r.text.lower() if r.text else "")
        ):
            locs = re.findall(r"<loc>(.*?)</loc>", r.text, re.I)
            findings.append(
                Finding(
                    title="sitemap.xml exposé",
                    severity=Severity.INFO,
                    target=sm_url,
                    module="recon",
                    description="Le sitemap fournit une cartographie des URLs.",
                    evidence=f"{len(locs)} URLs listées",
                    extra={"urls": locs[:200]},
                )
            )
            break
    return findings


def run(client: HttpClient, url: str, ctx: dict | None = None) -> List[Finding]:
    findings = fingerprint(client, url)
    findings += robots_and_sitemap(client, url)
    return findings
