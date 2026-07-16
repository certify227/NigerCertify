"""Détection de méthodes HTTP dangereuses activées."""

from __future__ import annotations

from typing import List

from ..findings import Finding, Severity
from .base import BaseCheck, CheckContext

_RISKY = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


class HttpMethodsCheck(BaseCheck):
    name = "http-methods"
    description = "Interroge OPTIONS pour repérer des méthodes HTTP risquées."
    active = False

    def run(self, ctx: CheckContext) -> List[Finding]:
        findings: List[Finding] = []
        resp = ctx.client.options(ctx.base_url)
        if resp is None:
            return findings
        allow = resp.headers.get("Allow") or resp.headers.get("Access-Control-Allow-Methods")
        if not allow:
            return findings
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = sorted(methods & _RISKY)
        if risky:
            sev = Severity.MEDIUM if {"PUT", "DELETE"} & set(risky) else Severity.LOW
            findings.append(
                Finding(
                    check=self.name,
                    title="Méthodes HTTP risquées autorisées",
                    severity=sev,
                    url=ctx.base_url,
                    description="Le serveur annonce des méthodes potentiellement dangereuses.",
                    evidence=f"Allow: {allow}",
                    remediation="Désactiver les méthodes non nécessaires (PUT, DELETE, TRACE...).",
                )
            )
        return findings
