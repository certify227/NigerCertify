"""
web_bugbounty - Boîte à outils de reconnaissance et d'audit de sécurité web
pour le bug bounty (usage autorisé et pédagogique uniquement).

Voir README.md et --help pour l'utilisation.
"""

__version__ = "1.0.0"
__author__ = "Niger Certify Offensive Lab"

from .core.findings import Finding, Severity  # noqa: F401
