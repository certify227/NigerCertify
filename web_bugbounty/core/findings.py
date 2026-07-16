"""Modèle de données pour les résultats d'audit (findings)."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


class Severity(enum.IntEnum):
    """Niveaux de sévérité, ordonnés pour permettre le tri."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]

    @property
    def label(self) -> str:
        return self.name.capitalize()


# Codes couleur ANSI par sévérité (désactivables).
SEVERITY_COLORS = {
    Severity.INFO: "\033[94m",      # bleu
    Severity.LOW: "\033[96m",       # cyan
    Severity.MEDIUM: "\033[93m",    # jaune
    Severity.HIGH: "\033[91m",      # rouge
    Severity.CRITICAL: "\033[95m",  # magenta
}
RESET = "\033[0m"
BOLD = "\033[1m"


@dataclass
class Finding:
    """Un résultat d'audit unique et structuré."""

    title: str
    severity: Severity
    target: str
    module: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data

    def colored_line(self, use_color: bool = True) -> str:
        tag = f"[{self.severity.label.upper()}]"
        if use_color:
            color = SEVERITY_COLORS.get(self.severity, "")
            tag = f"{color}{BOLD}{tag}{RESET}"
        line = f"{tag} {self.title} — {self.target}"
        if self.evidence:
            line += f"\n        ↳ {self.evidence}"
        return line


def sort_findings(findings, descending: bool = True):
    """Trie les findings par sévérité (les plus critiques en premier par défaut)."""
    return sorted(findings, key=lambda f: f.severity, reverse=descending)
