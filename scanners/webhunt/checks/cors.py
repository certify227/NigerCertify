"""Détection de configurations CORS dangereuses."""

from __future__ import annotations

from typing import List

from ..findings import Finding, Severity
from .base import BaseCheck, CheckContext


class CorsCheck(BaseCheck):
    name = "cors"
    description = "Teste la réflexion d'origine et les CORS trop permissifs."
    active = True  # envoie un en-tête Origin forgé (non destructif)

    _EVIL_ORIGIN = "https://webhunt-cors-probe.example"

    def run(self, ctx: CheckContext) -> List[Finding]:
        findings: List[Finding] = []
        resp = ctx.client.get(
            ctx.base_url, headers={"Origin": self._EVIL_ORIGIN}
        )
        if resp is None:
            return findings

        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").lower()
        if not acao:
            return findings

        if acao == self._EVIL_ORIGIN:
            sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
            findings.append(
                Finding(
                    check=self.name,
                    title="CORS reflète une origine arbitraire",
                    severity=sev,
                    url=ctx.base_url,
                    description=(
                        "Le serveur renvoie l'origine fournie par le client "
                        "dans Access-Control-Allow-Origin"
                        + (", avec les credentials autorisés." if acac == "true" else ".")
                    ),
                    evidence=f"Origin: {self._EVIL_ORIGIN} -> ACAO: {acao}; ACAC: {acac}",
                    remediation=(
                        "Valider l'origine contre une liste blanche stricte et "
                        "ne jamais combiner ACAO générique avec les credentials."
                    ),
                    references=[
                        "https://portswigger.net/web-security/cors"
                    ],
                )
            )
        elif acao == "*" and acac == "true":
            findings.append(
                Finding(
                    check=self.name,
                    title="CORS: wildcard + credentials",
                    severity=Severity.MEDIUM,
                    url=ctx.base_url,
                    description="ACAO=* combiné avec ACAC=true est une mauvaise config.",
                    evidence=f"ACAO: {acao}; ACAC: {acac}",
                    remediation="Restreindre l'origine autorisée.",
                )
            )
        elif acao == "*":
            findings.append(
                Finding(
                    check=self.name,
                    title="CORS: Access-Control-Allow-Origin: *",
                    severity=Severity.INFO,
                    url=ctx.base_url,
                    description="Toutes les origines sont autorisées (données publiques ?).",
                    evidence=f"ACAO: {acao}",
                    remediation="Confirmer que l'endpoint n'expose pas de données sensibles.",
                )
            )
        return findings
