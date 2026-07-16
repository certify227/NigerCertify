"""Modèle de données pour les découvertes (findings) de l'audit."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


class Severity(enum.IntEnum):
    """Niveau de gravité d'une découverte, ordonné pour le tri."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]


# Codes couleur ANSI utilisés pour l'affichage console.
SEVERITY_COLORS: Dict[Severity, str] = {
    Severity.INFO: "\033[36m",      # cyan
    Severity.LOW: "\033[34m",       # bleu
    Severity.MEDIUM: "\033[33m",    # jaune
    Severity.HIGH: "\033[31m",      # rouge
    Severity.CRITICAL: "\033[1;35m",  # magenta gras
}


@dataclass
class Finding:
    """Une découverte unitaire produite par un module d'audit."""

    check: str
    title: str
    severity: Severity
    url: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data

    def dedup_key(self) -> str:
        """Clé de déduplication pour éviter les doublons identiques."""
        return f"{self.check}|{self.title}|{self.url}|{self.evidence}"


@dataclass
class Target:
    """Cible normalisée de l'audit."""

    raw: str
    scheme: str
    host: str
    port: Optional[int]
    base_url: str
