"""Module de reconnaissance passive et active légère.

Collecte des informations utiles sur la cible sans effectuer d'action
intrusive : résolution DNS, en-têtes HTTP, empreinte technologique,
robots.txt, sitemap.xml, security.txt et détection de fichiers sensibles
exposés par erreur.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from .findings import Finding, Severity
from .http_client import HttpClient

# Signatures d'empreinte technologique basées sur les en-têtes/cookies/corps.
_TECH_SIGNATURES = [
    ("header", "server", re.compile(r"nginx", re.I), "Nginx"),
    ("header", "server", re.compile(r"apache", re.I), "Apache"),
    ("header", "server", re.compile(r"microsoft-iis", re.I), "IIS"),
    ("header", "server", re.compile(r"cloudflare", re.I), "Cloudflare"),
    ("header", "x-powered-by", re.compile(r"php", re.I), "PHP"),
    ("header", "x-powered-by", re.compile(r"express", re.I), "Express.js"),
    ("header", "x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET"),
    ("header", "x-generator", re.compile(r"drupal", re.I), "Drupal"),
    ("header", "x-drupal-cache", re.compile(r".+"), "Drupal"),
    ("cookie", "", re.compile(r"wordpress_|wp-settings", re.I), "WordPress"),
    ("cookie", "", re.compile(r"laravel_session", re.I), "Laravel"),
    ("cookie", "", re.compile(r"csrftoken", re.I), "Django"),
    ("cookie", "", re.compile(r"jsessionid", re.I), "Java (Servlet)"),
    ("body", "", re.compile(r"/wp-content/|wp-includes", re.I), "WordPress"),
    ("body", "", re.compile(r"content=\"Joomla", re.I), "Joomla"),
    ("body", "", re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    ("body", "", re.compile(r"ng-version=", re.I), "Angular"),
    ("body", "", re.compile(r"data-reactroot|react", re.I), "React"),
]

# Fichiers/chemins fréquemment exposés par erreur (recon non destructive).
_SENSITIVE_PATHS = [
    (".git/config", Severity.HIGH, "Dépôt Git exposé"),
    (".git/HEAD", Severity.HIGH, "Dépôt Git exposé"),
    (".env", Severity.CRITICAL, "Fichier d'environnement exposé"),
    (".env.local", Severity.CRITICAL, "Fichier d'environnement exposé"),
    ("config.php.bak", Severity.HIGH, "Sauvegarde de configuration exposée"),
    ("backup.zip", Severity.HIGH, "Archive de sauvegarde exposée"),
    ("backup.sql", Severity.HIGH, "Dump SQL exposé"),
    ("db.sql", Severity.HIGH, "Dump SQL exposé"),
    ("phpinfo.php", Severity.MEDIUM, "phpinfo() exposé"),
    (".DS_Store", Severity.LOW, "Fichier .DS_Store exposé"),
    ("server-status", Severity.MEDIUM, "Apache server-status exposé"),
    (".svn/entries", Severity.MEDIUM, "Métadonnées SVN exposées"),
    ("wp-config.php.bak", Severity.CRITICAL, "Sauvegarde wp-config exposée"),
    ("composer.lock", Severity.LOW, "composer.lock exposé"),
    ("package.json", Severity.INFO, "package.json exposé"),
]


@dataclass
class ReconResult:
    base_url: str
    ip_addresses: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    technologies: Set[str] = field(default_factory=set)
    robots_paths: List[str] = field(default_factory=list)
    sitemap_urls: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def as_dict(self) -> Dict:
        return {
            "base_url": self.base_url,
            "ip_addresses": self.ip_addresses,
            "headers": self.headers,
            "technologies": sorted(self.technologies),
            "robots_paths": self.robots_paths,
            "sitemap_urls": self.sitemap_urls,
        }


class Recon:
    def __init__(self, client: HttpClient) -> None:
        self.client = client

    def run(self, base_url: str) -> ReconResult:
        result = ReconResult(base_url=base_url)
        self._resolve_dns(base_url, result)

        resp = self.client.get(base_url)
        if resp is not None:
            result.headers = dict(resp.headers)
            self._fingerprint(resp, result)

        self._robots(base_url, result)
        self._sitemap(base_url, result)
        self._security_txt(base_url, result)
        self._sensitive_files(base_url, result)
        return result

    def _resolve_dns(self, base_url: str, result: ReconResult) -> None:
        host = urlparse(base_url).hostname or ""
        try:
            infos = socket.getaddrinfo(host, None)
            ips = sorted({i[4][0] for i in infos})
            result.ip_addresses = ips
        except socket.gaierror:
            result.findings.append(
                Finding(
                    check="recon.dns",
                    title="Résolution DNS impossible",
                    severity=Severity.INFO,
                    url=base_url,
                    description=f"L'hôte {host} n'a pas pu être résolu.",
                )
            )

    def _fingerprint(self, resp, result: ReconResult) -> None:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = "; ".join(f"{c.name}={c.value}" for c in resp.cookies)
        set_cookie = headers.get("set-cookie", "")
        body = resp.text[:200_000] if resp.text else ""

        for kind, key, pattern, tech in _TECH_SIGNATURES:
            if kind == "header":
                val = headers.get(key, "")
                if val and pattern.search(val):
                    result.technologies.add(tech)
            elif kind == "cookie":
                if pattern.search(cookies) or pattern.search(set_cookie):
                    result.technologies.add(tech)
            elif kind == "body" and body:
                if pattern.search(body):
                    result.technologies.add(tech)

        # Divulgation de version logicielle via en-têtes.
        for h in ("server", "x-powered-by", "x-aspnet-version"):
            val = headers.get(h)
            if val and re.search(r"\d", val):
                result.findings.append(
                    Finding(
                        check="recon.version-disclosure",
                        title=f"Divulgation de version via l'en-tête {h}",
                        severity=Severity.LOW,
                        url=result.base_url,
                        description=(
                            "Le serveur révèle des informations de version "
                            "qui facilitent la recherche d'exploits ciblés."
                        ),
                        evidence=f"{h}: {val}",
                        remediation=(
                            f"Masquer ou banaliser l'en-tête '{h}'."
                        ),
                    )
                )

    def _robots(self, base_url: str, result: ReconResult) -> None:
        url = urljoin(base_url, "/robots.txt")
        resp = self.client.get(url)
        if resp is None or resp.status_code != 200:
            return
        paths = re.findall(r"(?im)^\s*(?:dis)?allow:\s*(\S+)", resp.text)
        result.robots_paths = sorted(set(paths))
        if result.robots_paths:
            result.findings.append(
                Finding(
                    check="recon.robots",
                    title="robots.txt révèle des chemins",
                    severity=Severity.INFO,
                    url=url,
                    description=(
                        "robots.txt liste des chemins potentiellement "
                        "intéressants à explorer."
                    ),
                    evidence=", ".join(result.robots_paths[:20]),
                )
            )

    def _sitemap(self, base_url: str, result: ReconResult) -> None:
        url = urljoin(base_url, "/sitemap.xml")
        resp = self.client.get(url)
        if resp is None or resp.status_code != 200:
            return
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", resp.text, re.I)
        result.sitemap_urls = locs[:500]

    def _security_txt(self, base_url: str, result: ReconResult) -> None:
        for path in ("/.well-known/security.txt", "/security.txt"):
            url = urljoin(base_url, path)
            resp = self.client.get(url)
            if resp is not None and resp.status_code == 200 and "contact" in resp.text.lower():
                result.findings.append(
                    Finding(
                        check="recon.security-txt",
                        title="security.txt présent",
                        severity=Severity.INFO,
                        url=url,
                        description="Un point de contact sécurité est publié.",
                        evidence=resp.text.strip()[:300],
                    )
                )
                return

    def _sensitive_files(self, base_url: str, result: ReconResult) -> None:
        for path, severity, title in _SENSITIVE_PATHS:
            url = urljoin(base_url.rstrip("/") + "/", path)
            resp = self.client.get(url, allow_redirects=False)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if not body.strip():
                continue
            # Filtre les faux positifs (pages 200 « soft 404 »).
            if self._looks_like_html_error(body):
                continue
            result.findings.append(
                Finding(
                    check="recon.sensitive-file",
                    title=title,
                    severity=severity,
                    url=url,
                    description=(
                        "Un fichier sensible est accessible publiquement "
                        "et peut divulguer des secrets ou du code source."
                    ),
                    evidence=body.strip()[:200],
                    remediation=(
                        "Retirer le fichier de la racine web ou en bloquer "
                        "l'accès via la configuration du serveur."
                    ),
                )
            )

    @staticmethod
    def _looks_like_html_error(body: str) -> bool:
        head = body[:500].lower()
        return "<html" in head and ("not found" in head or "404" in head)
