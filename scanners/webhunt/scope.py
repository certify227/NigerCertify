"""Gestion du périmètre (scope) et de l'autorisation.

Ce module est le garde-fou de l'outil : il garantit que WebHunt ne
communique JAMAIS avec un hôte hors du périmètre explicitement autorisé.
"""

from __future__ import annotations

import fnmatch
from typing import Iterable, List
from urllib.parse import urlparse


class Scope:
    """Définit les hôtes dans le périmètre autorisé.

    Un hôte est dans le périmètre s'il correspond exactement à un hôte
    autorisé, ou s'il en est un sous-domaine lorsque les jokers sont activés.
    """

    def __init__(
        self,
        allowed_hosts: Iterable[str],
        include_subdomains: bool = True,
    ) -> None:
        self._patterns: List[str] = []
        self.include_subdomains = include_subdomains
        for host in allowed_hosts:
            host = self._clean(host)
            if host:
                self._patterns.append(host)

    @staticmethod
    def _clean(host: str) -> str:
        host = host.strip().lower()
        if "://" in host:
            host = urlparse(host).hostname or ""
        # Retire un éventuel port.
        if host and ":" in host and not host.startswith("["):
            host = host.split(":", 1)[0]
        return host

    def host_of(self, url: str) -> str:
        return self._clean(url)

    def is_allowed(self, url: str) -> bool:
        host = self._clean(url)
        if not host:
            return False
        for pattern in self._patterns:
            if host == pattern:
                return True
            if "*" in pattern and fnmatch.fnmatch(host, pattern):
                return True
            if self.include_subdomains and host.endswith("." + pattern):
                return True
        return False

    @property
    def hosts(self) -> List[str]:
        return list(self._patterns)

    def __repr__(self) -> str:  # pragma: no cover - debug
        return f"Scope(hosts={self._patterns}, subdomains={self.include_subdomains})"
