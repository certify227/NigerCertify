"""Module de reconnaissance pour WebBounty."""

from __future__ import annotations

import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

from .utils import (
    Finding,
    create_session,
    extract_links,
    get_base_url,
    get_domain,
    get_ssl_info,
    normalize_url,
    resolve_host,
    safe_request,
)


TECH_SIGNATURES: dict[str, list[str]] = {
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Drupal": ["drupal.js", "sites/default", "Drupal.settings"],
    "Joomla": ["joomla", "/components/com_"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Django": ["csrfmiddlewaretoken", "__admin_media_prefix__"],
    "React": ["react-dom", "_next/static", "__NEXT_DATA__"],
    "Angular": ["ng-version", "angular.js", "angular.min.js"],
    "Vue.js": ["vue.js", "vue.min.js", "__vue__"],
    "jQuery": ["jquery.min.js", "jquery.js"],
    "Bootstrap": ["bootstrap.min.css", "bootstrap.css"],
    "PHP": ["PHPSESSID", ".php"],
    "ASP.NET": ["__VIEWSTATE", "aspnet"],
    "Nginx": ["nginx"],
    "Apache": ["Apache"],
    "Cloudflare": ["cf-ray", "cloudflare"],
    "AWS": ["amazonaws.com", "x-amz-"],
    "GitHub Pages": ["github.io"],
}


class ReconModule:
    """Reconnaissance passive et active d'une cible web."""

    def __init__(
        self,
        target: str,
        session: requests.Session | None = None,
        threads: int = 10,
        wordlist_dir: Path | None = None,
    ):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.domain = get_domain(self.target)
        self.session = session or create_session()
        self.threads = threads
        self.wordlist_dir = wordlist_dir or Path(__file__).parent.parent / "wordlists"
        self.findings: list[Finding] = []
        self.info: dict[str, Any] = {}

    def run_full_recon(self) -> dict[str, Any]:
        """Lance toutes les étapes de reconnaissance."""
        self.info["target"] = self.target
        self.info["domain"] = self.domain
        self.info["ips"] = resolve_host(self.domain)
        self.info["ssl"] = get_ssl_info(self.domain)
        self.info["dns_records"] = self._get_dns_records()
        self.info["technologies"] = self.detect_technologies()
        self.info["headers"] = self._get_response_headers()
        self.info["robots_txt"] = self.check_robots_txt()
        self.info["sitemap"] = self.check_sitemap()
        self.info["subdomains"] = self.enumerate_subdomains()
        self.info["links"] = self.crawl_links(max_pages=15)
        self.info["emails"] = self.extract_emails()
        self.info["findings"] = [f.to_dict() for f in self.findings]
        return self.info

    def _get_dns_records(self) -> dict[str, list[str]]:
        """Récupère les enregistrements DNS basiques."""
        records: dict[str, list[str]] = {}
        try:
            import dns.resolver

            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
                try:
                    answers = dns.resolver.resolve(self.domain, rtype)
                    records[rtype] = [str(r) for r in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    continue
        except ImportError:
            records["note"] = ["dnspython non installé — pip install dnspython"]
        return records

    def _get_response_headers(self) -> dict[str, str]:
        """Récupère les en-têtes de réponse."""
        resp = safe_request(self.session, "GET", self.target)
        if resp:
            return dict(resp.headers)
        return {}

    def detect_technologies(self) -> list[str]:
        """Détecte les technologies utilisées."""
        detected: list[str] = []
        resp = safe_request(self.session, "GET", self.target)
        if not resp:
            return detected

        content = resp.text.lower()
        headers_str = str(resp.headers).lower()

        for tech, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in content or sig.lower() in headers_str:
                    detected.append(tech)
                    break

        server = resp.headers.get("Server", "")
        if server and server not in detected:
            detected.append(f"Server: {server}")

        x_powered = resp.headers.get("X-Powered-By", "")
        if x_powered:
            detected.append(f"X-Powered-By: {x_powered}")

        self.info["technologies"] = list(set(detected))
        return self.info["technologies"]

    def check_robots_txt(self) -> dict[str, Any]:
        """Analyse robots.txt pour découvrir des chemins sensibles."""
        result: dict[str, Any] = {"found": False, "paths": [], "disallow": []}
        url = f"{self.base_url}/robots.txt"
        resp = safe_request(self.session, "GET", url)
        if not resp or resp.status_code != 200:
            return result

        result["found"] = True
        result["content"] = resp.text[:2000]
        disallow_paths = re.findall(r"Disallow:\s*(.+)", resp.text, re.IGNORECASE)
        allow_paths = re.findall(r"Allow:\s*(.+)", resp.text, re.IGNORECASE)
        sitemaps = re.findall(r"Sitemap:\s*(.+)", resp.text, re.IGNORECASE)

        result["disallow"] = [p.strip() for p in disallow_paths]
        result["allow"] = [p.strip() for p in allow_paths]
        result["sitemaps"] = [s.strip() for s in sitemaps]

        sensitive_keywords = [
            "admin", "backup", "config", "api", "private", "secret",
            "internal", "staging", "dev", "test", "upload", "database",
        ]
        for path in result["disallow"]:
            for kw in sensitive_keywords:
                if kw in path.lower():
                    finding = Finding(
                        title=f"Chemin sensible dans robots.txt: {path}",
                        severity="info",
                        category="Information Disclosure",
                        url=url,
                        description=f"robots.txt révèle un chemin potentiellement sensible: {path}",
                        evidence=path,
                        remediation="Vérifier si ce chemin est accessible et correctement protégé.",
                    )
                    self.findings.append(finding)
                    break

        return result

    def check_sitemap(self) -> dict[str, Any]:
        """Récupère et analyse le sitemap."""
        result: dict[str, Any] = {"found": False, "urls": []}
        for path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"):
            url = f"{self.base_url}{path}"
            resp = safe_request(self.session, "GET", url)
            if resp and resp.status_code == 200 and "<url" in resp.text.lower():
                result["found"] = True
                urls = re.findall(r"<loc>([^<]+)</loc>", resp.text, re.IGNORECASE)
                result["urls"].extend(urls)
                result["source"] = url
        result["urls"] = list(set(result["urls"]))[:100]
        return result

    def enumerate_subdomains(self) -> list[str]:
        """Énumération de sous-domaines via wordlist."""
        wordlist_path = self.wordlist_dir / "subdomains.txt"
        if not wordlist_path.exists():
            return []

        subdomains: list[str] = []
        words = wordlist_path.read_text(encoding="utf-8").strip().splitlines()

        def check_sub(word: str) -> str | None:
            subdomain = f"{word.strip()}.{self.domain}"
            ips = resolve_host(subdomain)
            if ips:
                return subdomain
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_sub, w): w for w in words if w.strip()}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.append(result)
                    finding = Finding(
                        title=f"Sous-domaine découvert: {result}",
                        severity="info",
                        category="Reconnaissance",
                        url=f"https://{result}",
                        description=f"Sous-domaine actif résolu: {result}",
                        evidence=", ".join(resolve_host(result)),
                    )
                    self.findings.append(finding)

        return sorted(subdomains)

    def crawl_links(self, max_pages: int = 20) -> list[str]:
        """Crawl léger pour découvrir des liens internes."""
        visited: set[str] = set()
        to_visit: list[str] = [self.target]
        all_links: set[str] = set()

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            resp = safe_request(self.session, "GET", url)
            if not resp or resp.status_code != 200:
                continue

            links = extract_links(resp.text, url)
            for link in links:
                all_links.add(link)
                parsed = urllib.parse.urlparse(link)
                if parsed.netloc == urllib.parse.urlparse(self.base_url).netloc:
                    if link not in visited and len(to_visit) < max_pages:
                        to_visit.append(link)

        return sorted(all_links)

    def extract_emails(self) -> list[str]:
        """Extrait les adresses email de la page principale."""
        resp = safe_request(self.session, "GET", self.target)
        if not resp:
            return []
        emails = set(
            re.findall(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                resp.text,
            )
        )
        return sorted(emails)
