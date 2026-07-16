"""Crawler léger respectant le périmètre.

Explore l'application en largeur (BFS), collecte les URLs, les paramètres
de requête et les formulaires HTML. Reste strictement dans le périmètre
et limite la profondeur et le nombre de pages.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse

from .http_client import HttpClient
from .scope import Scope


@dataclass
class Form:
    action: str
    method: str
    inputs: Dict[str, str] = field(default_factory=dict)


@dataclass
class CrawlResult:
    pages: List[str] = field(default_factory=list)
    # URL -> ensemble de noms de paramètres GET observés.
    params: Dict[str, Set[str]] = field(default_factory=dict)
    forms: List[Form] = field(default_factory=list)

    def parameterized_urls(self) -> List[Tuple[str, List[str]]]:
        return [(u, sorted(p)) for u, p in self.params.items() if p]


class _LinkParser(HTMLParser):
    """Extrait liens, formulaires et champs d'un document HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.forms: List[Form] = []
        self._current: Optional[Form] = None

    def handle_starttag(self, tag: str, attrs) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("script", "link", "iframe"):
            src = a.get("src") or a.get("href")
            if src:
                self.links.append(src)
        elif tag == "form":
            self._current = Form(
                action=a.get("action", ""),
                method=(a.get("method") or "get").lower(),
            )
        elif tag in ("input", "textarea", "select") and self._current is not None:
            name = a.get("name")
            if name:
                self._current.inputs[name] = a.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


class Crawler:
    def __init__(
        self,
        client: HttpClient,
        scope: Scope,
        max_pages: int = 150,
        max_depth: int = 3,
    ) -> None:
        self.client = client
        self.scope = scope
        self.max_pages = max_pages
        self.max_depth = max_depth

    def crawl(self, start_urls: List[str]) -> CrawlResult:
        result = CrawlResult()
        seen: Set[str] = set()
        queue: deque = deque()
        for u in start_urls:
            queue.append((self._normalize(u), 0))

        while queue and len(result.pages) < self.max_pages:
            url, depth = queue.popleft()
            if not url or url in seen:
                continue
            seen.add(url)
            if not self.scope.is_allowed(url):
                continue

            self._record_params(url, result)

            resp = self.client.get(url)
            if resp is None:
                continue
            result.pages.append(url)

            ctype = resp.headers.get("Content-Type", "")
            if "html" not in ctype.lower():
                continue

            parser = _LinkParser()
            try:
                parser.feed(resp.text or "")
            except Exception:
                continue

            for form in parser.forms:
                action = self._normalize(urljoin(url, form.action or url))
                if self.scope.is_allowed(action):
                    result.forms.append(
                        Form(action=action, method=form.method, inputs=form.inputs)
                    )

            if depth >= self.max_depth:
                continue

            for link in parser.links:
                nxt = self._normalize(urljoin(url, link))
                if nxt and nxt not in seen and self.scope.is_allowed(nxt):
                    queue.append((nxt, depth + 1))

        return result

    def _record_params(self, url: str, result: CrawlResult) -> None:
        q = urlparse(url).query
        if not q:
            return
        names = set(parse_qs(q).keys())
        if names:
            result.params.setdefault(url, set()).update(names)

    @staticmethod
    def _normalize(url: str) -> str:
        if not url:
            return ""
        url, _ = urldefrag(url)
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return ""
        # Ignore les schémas/extensions binaires non pertinents.
        if re.search(
            r"\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|pdf|zip|mp4|mp3)($|\?)",
            parsed.path,
            re.I,
        ):
            return ""
        return url
