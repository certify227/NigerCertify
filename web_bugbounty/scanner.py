"""Orchestrateur : exécute les modules sélectionnés sur une cible."""
from __future__ import annotations

import time
from typing import Callable, Dict, List

from .core.findings import Finding, Severity
from .core.http_client import HttpClient
from .core.scope import Scope, normalize_url
from .modules import (
    content_discovery,
    recon,
    security_headers,
    subdomains,
    tls_scan,
    vulns,
)

# Registre des modules disponibles.
MODULES: Dict[str, Callable] = {
    "recon": recon.run,
    "headers": security_headers.run,
    "tls": tls_scan.run,
    "vulns": vulns.run,
    "content": content_discovery.run,
    "subdomains": subdomains.run,
}

# Modules exécutés par défaut (subdomains/content peuvent être bruyants).
DEFAULT_MODULES = ["recon", "headers", "tls", "vulns", "content"]


class Scanner:
    def __init__(
        self,
        client: HttpClient,
        scope: Scope,
        modules: List[str] | None = None,
        ctx: dict | None = None,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.client = client
        self.scope = scope
        self.modules = modules or DEFAULT_MODULES
        self.ctx = ctx or {}
        self.log = logger or (lambda msg: None)

    def scan(self, target: str) -> List[Finding]:
        url = normalize_url(target)
        if not self.scope.in_scope(url):
            self.log(f"[!] Hors périmètre, ignoré : {url}")
            return [
                Finding(
                    title="Cible hors périmètre",
                    severity=Severity.INFO,
                    target=url,
                    module="scope",
                    description="La cible n'est pas dans le périmètre autorisé (--scope).",
                )
            ]

        findings: List[Finding] = []
        for name in self.modules:
            fn = MODULES.get(name)
            if fn is None:
                self.log(f"[!] Module inconnu : {name}")
                continue
            self.log(f"[*] Module '{name}' en cours…")
            started = time.monotonic()
            try:
                results = fn(self.client, url, self.ctx)
            except Exception as exc:  # robustesse : un module ne doit pas tout casser
                self.log(f"[!] Erreur dans le module '{name}': {exc}")
                results = [
                    Finding(
                        title=f"Erreur module {name}",
                        severity=Severity.INFO,
                        target=url,
                        module=name,
                        description="Le module a levé une exception.",
                        evidence=str(exc)[:300],
                    )
                ]
            elapsed = time.monotonic() - started
            self.log(f"    → {len(results)} finding(s) en {elapsed:.1f}s")
            findings.extend(results)
        return findings
