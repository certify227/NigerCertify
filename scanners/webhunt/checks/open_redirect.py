"""Détection de redirections ouvertes (open redirect).

Check actif et non destructif : réécrit les paramètres candidats vers une
URL témoin hors périmètre et observe si le serveur redirige vers elle.
La requête de suivi éventuelle n'est PAS exécutée (allow_redirects=False).
"""

from __future__ import annotations

from typing import List
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..findings import Finding, Severity
from .base import BaseCheck, CheckContext

# Noms de paramètres fréquemment vulnérables aux redirections ouvertes.
_CANDIDATE_PARAMS = {
    "url", "next", "redirect", "redirect_uri", "redir", "return",
    "returnurl", "return_url", "dest", "destination", "continue",
    "goto", "target", "rurl", "u", "link", "out",
}

_MARKER_HOST = "webhunt-redirect-probe.example"
_PAYLOAD = f"https://{_MARKER_HOST}/"


class OpenRedirectCheck(BaseCheck):
    name = "open-redirect"
    description = "Teste les paramètres de redirection avec une URL témoin."
    active = True

    def run(self, ctx: CheckContext) -> List[Finding]:
        findings: List[Finding] = []
        if not ctx.active or not ctx.crawl:
            return findings

        tested = set()
        for url, params in ctx.crawl.parameterized_urls():
            for param in params:
                if param.lower() not in _CANDIDATE_PARAMS:
                    continue
                key = (urlparse(url).path, param)
                if key in tested:
                    continue
                tested.add(key)
                finding = self._probe(ctx, url, param)
                if finding:
                    findings.append(finding)
        return findings

    def _probe(self, ctx: CheckContext, url: str, param: str):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [_PAYLOAD]
        new_query = urlencode(query, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        resp = ctx.client.get(test_url, allow_redirects=False)
        if resp is None:
            return None
        if resp.status_code not in (301, 302, 303, 307, 308):
            return None
        location = resp.headers.get("Location", "")
        if _MARKER_HOST in location:
            return Finding(
                check=self.name,
                title=f"Redirection ouverte via le paramètre '{param}'",
                severity=Severity.MEDIUM,
                url=test_url,
                description=(
                    "Le paramètre contrôle la destination de redirection "
                    "et permet d'envoyer les victimes vers un site externe."
                ),
                evidence=f"HTTP {resp.status_code} -> Location: {location}",
                remediation=(
                    "Valider la destination contre une liste blanche ou "
                    "n'autoriser que des chemins relatifs internes."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"
                ],
            )
        return None
