"""Interface commune aux modules de détection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..crawler import CrawlResult
from ..findings import Finding
from ..http_client import HttpClient
from ..recon import ReconResult
from ..scope import Scope


@dataclass
class CheckContext:
    """Contexte partagé fourni à chaque check."""

    base_url: str
    client: HttpClient
    scope: Scope
    recon: Optional[ReconResult] = None
    crawl: Optional[CrawlResult] = None
    active: bool = False
    findings: List[Finding] = field(default_factory=list)


class BaseCheck:
    """Classe de base pour un module de détection."""

    #: Nom court unique du check.
    name: str = "base"
    #: Description lisible.
    description: str = ""
    #: True si le check envoie des payloads actifs (nécessite autorisation).
    active: bool = False

    def run(self, ctx: CheckContext) -> List[Finding]:  # pragma: no cover
        raise NotImplementedError
