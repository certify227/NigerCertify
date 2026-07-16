"""Détection de fuites d'informations dans les réponses (passif).

Analyse les pages déjà découvertes par le crawler à la recherche de
messages d'erreur détaillés, de traces de pile et de secrets exposés.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from ..findings import Finding, Severity
from .base import BaseCheck, CheckContext

# (regex, titre, gravité)
_PATTERNS: List[Tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "Clé privée exposée", Severity.CRITICAL),
    (re.compile(r"AKIA[0-9A-Z]{16}"),
     "Clé d'accès AWS exposée", Severity.CRITICAL),
    (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+"),
     "Secret AWS exposé", Severity.CRITICAL),
    (re.compile(r"(?i)(api[_-]?key|secret|passwd|password)\s*[=:]\s*['\"][^'\"]{6,}"),
     "Secret potentiel dans la réponse", Severity.HIGH),
    (re.compile(r"(?i)Fatal error:|Warning:.*on line \d+|Notice:.*on line \d+"),
     "Message d'erreur PHP détaillé", Severity.LOW),
    (re.compile(r"Traceback \(most recent call last\):"),
     "Trace de pile Python exposée", Severity.MEDIUM),
    (re.compile(r"(?i)java\.lang\.[A-Za-z.]+Exception"),
     "Trace de pile Java exposée", Severity.MEDIUM),
    (re.compile(r"(?i)You have an error in your SQL syntax"),
     "Message d'erreur SQL exposé", Severity.MEDIUM),
    (re.compile(r"(?i)ORA-\d{5}|SQLSTATE\[|PG::"),
     "Message d'erreur base de données exposé", Severity.MEDIUM),
    (re.compile(r"(?i)DEBUG\s*=\s*True"),
     "Mode debug activé", Severity.MEDIUM),
]


class InfoDisclosureCheck(BaseCheck):
    name = "info-disclosure"
    description = "Recherche des fuites d'informations dans les pages crawlées."
    active = False

    def run(self, ctx: CheckContext) -> List[Finding]:
        findings: List[Finding] = []
        seen = set()

        urls = [ctx.base_url]
        if ctx.crawl:
            urls = list(dict.fromkeys([ctx.base_url] + ctx.crawl.pages))

        for url in urls[:200]:
            resp = ctx.client.get(url)
            if resp is None or not resp.text:
                continue
            body = resp.text
            for pattern, title, sev in _PATTERNS:
                m = pattern.search(body)
                if not m:
                    continue
                key = (title, url)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        check=self.name,
                        title=title,
                        severity=sev,
                        url=url,
                        description="Une information sensible a été détectée dans la réponse.",
                        evidence=m.group(0)[:160],
                        remediation=(
                            "Désactiver les messages d'erreur détaillés en "
                            "production et retirer tout secret des réponses."
                        ),
                    )
                )
        return findings
