"""Détection de subdomain takeover pour BountyStrike."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

from .utils import Finding, create_session, get_domain, normalize_url, safe_request

# Services vulnérables au takeover et leurs signatures
TAKEOVER_FINGERPRINTS: list[dict[str, Any]] = [
    {
        "service": "GitHub Pages",
        "cname_patterns": ["github.io", "githubusercontent.com"],
        "indicators": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html"],
        "severity": "high",
    },
    {
        "service": "Heroku",
        "cname_patterns": ["herokudns.com", "herokuapp.com"],
        "indicators": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        "severity": "high",
    },
    {
        "service": "AWS S3",
        "cname_patterns": ["s3.amazonaws.com", "s3-website"],
        "indicators": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "critical",
    },
    {
        "service": "Shopify",
        "cname_patterns": ["myshopify.com"],
        "indicators": ["Sorry, this shop is currently unavailable", "Only one step left!"],
        "severity": "high",
    },
    {
        "service": "Tumblr",
        "cname_patterns": ["domains.tumblr.com"],
        "indicators": ["There's nothing here.", "Whatever you were looking for doesn't currently exist"],
        "severity": "medium",
    },
    {
        "service": "WordPress.com",
        "cname_patterns": ["wordpress.com"],
        "indicators": ["Do you want to register"],
        "severity": "medium",
    },
    {
        "service": "Ghost",
        "cname_patterns": ["ghost.io"],
        "indicators": ["The thing you were looking for is no longer here"],
        "severity": "medium",
    },
    {
        "service": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "indicators": ["project not found"],
        "severity": "medium",
    },
    {
        "service": "Bitbucket",
        "cname_patterns": ["bitbucket.io"],
        "indicators": ["Repository not found"],
        "severity": "medium",
    },
    {
        "service": "Azure",
        "cname_patterns": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com"],
        "indicators": ["404 Web Site not found", "Error 404"],
        "severity": "high",
    },
    {
        "service": "Fastly",
        "cname_patterns": ["fastly.net"],
        "indicators": ["Fastly error: unknown domain"],
        "severity": "high",
    },
    {
        "service": "Pantheon",
        "cname_patterns": ["pantheonsite.io"],
        "indicators": ["The gods are wise", "404 error unknown site!"],
        "severity": "medium",
    },
    {
        "service": "Zendesk",
        "cname_patterns": ["zendesk.com"],
        "indicators": ["Help Center Closed", "this help center no longer exists"],
        "severity": "medium",
    },
    {
        "service": "Cargo",
        "cname_patterns": ["cargocollective.com"],
        "indicators": ["404 Not Found"],
        "severity": "low",
    },
    {
        "service": "Statuspage",
        "cname_patterns": ["statuspage.io"],
        "indicators": ["You are being redirected", "Status page not found"],
        "severity": "medium",
    },
    {
        "service": "Unbounce",
        "cname_patterns": ["unbouncepages.com"],
        "indicators": ["The requested URL was not found on this server"],
        "severity": "medium",
    },
    {
        "service": "Intercom",
        "cname_patterns": ["custom.intercom.help"],
        "indicators": ["This page is reserved for artistic dogs"],
        "severity": "medium",
    },
    {
        "service": "Webflow",
        "cname_patterns": ["proxy.webflow.com", "proxy-ssl.webflow.com"],
        "indicators": ["The page you are looking for doesn't exist"],
        "severity": "medium",
    },
    {
        "service": "Vercel",
        "cname_patterns": ["vercel.app", "now.sh"],
        "indicators": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        "severity": "high",
    },
    {
        "service": "Netlify",
        "cname_patterns": ["netlify.app", "netlify.com"],
        "indicators": ["Not Found - Request ID"],
        "severity": "high",
    },
    {
        "service": "Fly.io",
        "cname_patterns": ["fly.dev"],
        "indicators": ["404 Not Found"],
        "severity": "medium",
    },
    {
        "service": "Readthedocs",
        "cname_patterns": ["readthedocs.io"],
        "indicators": ["unknown to Read the Docs"],
        "severity": "low",
    },
]


class TakeoverScanner:
    """Détecte les sous-domaines vulnérables au takeover."""

    def __init__(
        self,
        target: str,
        session: requests.Session | None = None,
        subdomains: list[str] | None = None,
        threads: int = 10,
        wordlist_dir: Path | None = None,
    ):
        self.target = normalize_url(target)
        self.domain = get_domain(self.target)
        self.session = session or create_session()
        self.subdomains = subdomains or []
        self.threads = threads
        self.wordlist_dir = wordlist_dir or Path(__file__).parent.parent / "wordlists"
        self.findings: list[Finding] = []

    def run_full_scan(self) -> list[Finding]:
        """Scanne les sous-domaines pour takeover."""
        targets = self._get_targets()
        if not targets:
            self.findings.append(
                Finding(
                    title="Aucun sous-domaine à analyser pour takeover",
                    severity="info",
                    category="Subdomain Takeover",
                    url=self.target,
                    description="Lancez --recon d'abord ou fournissez des sous-domaines",
                )
            )
            return self.findings

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_subdomain, sd): sd for sd in targets}
            for future in as_completed(futures):
                future.result()

        return self.findings

    def _get_targets(self) -> list[str]:
        """Construit la liste des sous-domaines à tester."""
        targets = set(self.subdomains)
        targets.add(self.domain)

        wordlist_path = self.wordlist_dir / "subdomains.txt"
        if wordlist_path.exists():
            for word in wordlist_path.read_text(encoding="utf-8").splitlines()[:50]:
                word = word.strip()
                if word and not word.startswith("#"):
                    targets.add(f"{word}.{self.domain}")

        return sorted(targets)

    def _get_cname(self, subdomain: str) -> list[str]:
        """Récupère les enregistrements CNAME."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(subdomain, "CNAME")
            return [str(r.target).rstrip(".") for r in answers]
        except Exception:
            return []

    def _check_subdomain(self, subdomain: str) -> None:
        """Vérifie un sous-domaine pour takeover."""
        cnames = self._get_cname(subdomain)

        for cname in cnames:
            for fp in TAKEOVER_FINGERPRINTS:
                if any(pattern in cname.lower() for pattern in fp["cname_patterns"]):
                    self._verify_takeover(subdomain, cname, fp)
                    return

        # Vérifier aussi via HTTP même sans CNAME (dangling DNS)
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            resp = safe_request(self.session, "GET", url, allow_redirects=True)
            if not resp:
                continue
            for fp in TAKEOVER_FINGERPRINTS:
                for indicator in fp["indicators"]:
                    if indicator.lower() in resp.text.lower():
                        self.findings.append(
                            Finding(
                                title=f"Subdomain Takeover potentiel: {subdomain}",
                                severity=fp["severity"],
                                category="Subdomain Takeover",
                                url=url,
                                description=f"Service {fp['service']} — sous-domaine potentiellement récupérable",
                                evidence=f"CNAME: {cname or 'N/A'}, Indicator: {indicator}",
                                remediation=f"Supprimer l'enregistrement DNS ou réclamer le service {fp['service']}",
                            )
                        )
                        return

    def _verify_takeover(self, subdomain: str, cname: str, fp: dict[str, Any]) -> None:
        """Vérifie le takeover via requête HTTP."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            resp = safe_request(self.session, "GET", url, allow_redirects=True)
            if not resp:
                continue

            for indicator in fp["indicators"]:
                if indicator.lower() in resp.text.lower():
                    self.findings.append(
                        Finding(
                            title=f"Subdomain Takeover: {subdomain} → {fp['service']}",
                            severity=fp["severity"],
                            category="Subdomain Takeover",
                            url=url,
                            description=(
                                f"Le sous-domaine pointe vers {fp['service']} ({cname}) "
                                f"mais le service n'est pas réclamé — takeover possible"
                            ),
                            evidence=f"CNAME: {cname}, HTTP indicator: {indicator}",
                            remediation=f"Réclamer le service {fp['service']} ou supprimer le CNAME",
                        )
                    )
                    return

            # CNAME vers service externe mais pas d'indicateur clair
            self.findings.append(
                Finding(
                    title=f"CNAME externe détecté: {subdomain}",
                    severity="info",
                    category="Subdomain Takeover",
                    url=url,
                    description=f"CNAME vers {fp['service']}: {cname} — vérifier manuellement",
                    evidence=f"CNAME: {cname}",
                )
            )
