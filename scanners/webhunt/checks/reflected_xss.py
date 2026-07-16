"""Détection heuristique de XSS réfléchi (actif, non destructif).

Injecte un marqueur unique contenant des caractères significatifs pour le
HTML dans les paramètres GET et vérifie s'il est renvoyé sans encodage
dans un contexte exploitable. Aucune charge utile ne s'exécute côté
scanner : on cherche seulement la réflexion non échappée.
"""

from __future__ import annotations

import html
import re
import secrets
from typing import List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..findings import Finding, Severity
from .base import BaseCheck, CheckContext


class ReflectedXssCheck(BaseCheck):
    name = "reflected-xss"
    description = "Teste la réflexion non échappée de paramètres (XSS réfléchi)."
    active = True

    def run(self, ctx: CheckContext) -> List[Finding]:
        findings: List[Finding] = []
        if not ctx.active or not ctx.crawl:
            return findings

        tested = set()
        for url, params in ctx.crawl.parameterized_urls():
            for param in params:
                key = (urlparse(url).path, param)
                if key in tested:
                    continue
                tested.add(key)
                finding = self._probe(ctx, url, param)
                if finding:
                    findings.append(finding)
        return findings

    def _probe(self, ctx: CheckContext, url: str, param: str) -> Optional[Finding]:
        token = "wh" + secrets.token_hex(4)
        # Marqueur portant des caractères clés pour le contexte HTML.
        marker = f"{token}<x>\"'"
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [marker]
        test_url = urlunparse(
            parsed._replace(query=urlencode(query, doseq=True))
        )

        resp = ctx.client.get(test_url)
        if resp is None or not resp.text:
            return None
        body = resp.text

        if token not in body:
            return None  # non réfléchi

        # Réfléchi mais correctement encodé -> non exploitable.
        encoded = html.escape(marker)
        raw_reflections = body.count(marker)
        if raw_reflections == 0 and encoded in body:
            return None

        # Recherche des caractères dangereux réfléchis bruts autour du token.
        window = self._context(body, token)
        dangerous = any(c in window for c in ("<x>", '"', "'"))
        if "<x>" in body:
            severity = Severity.HIGH
            note = "Les chevrons '<>' sont réfléchis sans encodage."
        elif dangerous:
            severity = Severity.MEDIUM
            note = "Des caractères spéciaux sont réfléchis sans encodage."
        else:
            return None

        return Finding(
            check=self.name,
            title=f"Réflexion non échappée via le paramètre '{param}' (XSS possible)",
            severity=severity,
            url=test_url,
            description=(
                "La valeur du paramètre est renvoyée dans la réponse sans "
                "encodage suffisant. " + note + " À confirmer manuellement."
            ),
            evidence=self._context(body, token, span=80),
            remediation=(
                "Encoder toute donnée utilisateur selon le contexte de sortie "
                "(HTML, attribut, JS) et appliquer une CSP."
            ),
            references=[
                "https://owasp.org/www-community/attacks/xss/"
            ],
        )

    @staticmethod
    def _context(body: str, token: str, span: int = 40) -> str:
        idx = body.find(token)
        if idx < 0:
            return ""
        start = max(0, idx - span)
        end = min(len(body), idx + len(token) + span)
        snippet = body[start:end]
        return re.sub(r"\s+", " ", snippet).strip()
