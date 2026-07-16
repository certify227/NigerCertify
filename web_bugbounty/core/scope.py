"""Gestion du périmètre (scope) pour rester dans les cibles autorisées."""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List
from urllib.parse import urlparse


def normalize_url(url: str, default_scheme: str = "https") -> str:
    """Ajoute un schéma si absent et retire le slash final superflu."""
    url = url.strip()
    if not url:
        return url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"{default_scheme}://{url}"
    parsed = urlparse(url)
    path = parsed.path or "/"
    netloc = parsed.netloc
    rebuilt = f"{parsed.scheme}://{netloc}{path}"
    if parsed.query:
        rebuilt += f"?{parsed.query}"
    return rebuilt.rstrip("/") if path == "/" and not parsed.query else rebuilt


def host_of(url: str) -> str:
    return urlparse(normalize_url(url)).hostname or ""


def registrable_root(host: str) -> str:
    """Approximation naïve du domaine racine (les 2 derniers labels).

    Suffisant pour du bug bounty basique ; pour une précision totale sur les
    suffixes composés (ex: .co.uk) une liste PSL serait nécessaire.
    """
    host = host.strip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


class Scope:
    """Détermine si un hôte est dans le périmètre autorisé.

    - `include` : domaines autorisés (le sous-domaine est autorisé par défaut).
    - `exclude` : domaines/hôtes explicitement interdits (prioritaire).
    """

    def __init__(
        self,
        include: Iterable[str],
        exclude: Iterable[str] | None = None,
        allow_subdomains: bool = True,
    ) -> None:
        self.include: List[str] = [h.lower().strip(".") for h in include if h]
        self.exclude: List[str] = [h.lower().strip(".") for h in (exclude or []) if h]
        self.allow_subdomains = allow_subdomains

    @staticmethod
    def _matches(host: str, pattern: str, allow_subdomains: bool) -> bool:
        host = host.lower().strip(".")
        pattern = pattern.lower().strip(".")
        if host == pattern:
            return True
        if allow_subdomains and host.endswith("." + pattern):
            return True
        return False

    def in_scope(self, url_or_host: str) -> bool:
        host = url_or_host if "://" not in url_or_host else host_of(url_or_host)
        if not host:
            return False
        for pattern in self.exclude:
            if self._matches(host, pattern, True):
                return False
        for pattern in self.include:
            if self._matches(host, pattern, self.allow_subdomains):
                return True
        return False

    @staticmethod
    def is_private_target(host: str) -> bool:
        """Renvoie True si l'hôte pointe explicitement vers une IP privée/loopback."""
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return host in ("localhost",)
