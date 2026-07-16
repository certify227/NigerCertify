"""Gestion du scope bug bounty."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse


class ScopeManager:
    """Gère les domaines in-scope et out-of-scope."""

    def __init__(self, scope_file: Path | None = None, root_domain: str | None = None):
        self.in_scope: list[str] = []
        self.out_scope: list[str] = []
        self.root_domain = root_domain or ""

        if scope_file and scope_file.exists():
            self._load(scope_file)
        elif root_domain:
            domain = root_domain
            if "://" in domain:
                from urllib.parse import urlparse
                domain = urlparse(domain).netloc.split(":")[0]
            self.in_scope.append(domain)

    def _load(self, path: Path) -> None:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-"):
                self.out_scope.append(line[1:].strip())
            else:
                self.in_scope.append(line)

    def is_in_scope(self, url: str) -> bool:
        """Vérifie si une URL est dans le scope."""
        host = urlparse(url).netloc.split(":")[0].lower()
        for pattern in self.out_scope:
            if self._match(host, pattern):
                return False
        if not self.in_scope:
            return True
        return any(self._match(host, p) for p in self.in_scope)

    @staticmethod
    def _match(host: str, pattern: str) -> bool:
        pattern = pattern.lower().replace("*.", "")
        return host == pattern or host.endswith(f".{pattern}")
