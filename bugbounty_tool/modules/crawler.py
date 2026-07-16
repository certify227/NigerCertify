"""
Crawler HTML léger et concurrent.

- Respecte le domaine (par défaut) et une profondeur maximale
- Extrait liens (<a>, <link>, <script src>, <form action>, <iframe src>)
- Collecte formulaires (méthode, action, champs) pour tester des injections
- Détecte les paramètres GET pour alimenter le scanner de vulnérabilités
"""

from __future__ import annotations

import concurrent.futures as cf
import re
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse

from ..core import HttpClient, log_info, log_ok, log_debug, same_domain


LINK_REGEX = re.compile(
    r"""(?:href|src|action)\s*=\s*['"]([^'"#\s]+)['"]""", re.IGNORECASE
)

FORM_REGEX = re.compile(
    r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL
)
FORM_ATTR_REGEX = re.compile(r"""(\w+)\s*=\s*['"]([^'"]*)['"]""")
INPUT_REGEX = re.compile(
    r"<(?:input|textarea|select)\b([^>]*)>", re.IGNORECASE
)


@dataclass
class Form:
    action: str
    method: str = "GET"
    inputs: Dict[str, str] = field(default_factory=dict)


@dataclass
class CrawlResult:
    urls: Set[str] = field(default_factory=set)
    parameterized: Set[str] = field(default_factory=set)  # URLs avec query-string
    forms: List[Form] = field(default_factory=list)


class Crawler:
    def __init__(
        self,
        base_url: str,
        http: HttpClient,
        max_depth: int = 2,
        max_urls: int = 300,
        threads: int = 10,
        same_domain_only: bool = True,
        verbose: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.http = http
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.threads = threads
        self.same_domain_only = same_domain_only
        self.verbose = verbose
        self._lock = threading.Lock()
        self._visited: Set[str] = set()
        self._result = CrawlResult()

    # ------------------------------------------------------------------
    def _extract(self, html: str, page_url: str) -> Tuple[Set[str], List[Form]]:
        links: Set[str] = set()
        for m in LINK_REGEX.finditer(html):
            raw = m.group(1).strip()
            if raw.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            absolute = urldefrag(urljoin(page_url, raw))[0]
            links.add(absolute)

        forms: List[Form] = []
        for m in FORM_REGEX.finditer(html):
            open_tag_match = re.search(r"<form\b([^>]*)>", m.group(0), re.IGNORECASE)
            attrs = dict(FORM_ATTR_REGEX.findall(open_tag_match.group(1))) if open_tag_match else {}
            action = urljoin(page_url, attrs.get("action", page_url))
            method = attrs.get("method", "GET").upper()
            inputs: Dict[str, str] = {}
            for i in INPUT_REGEX.finditer(m.group(1)):
                iattrs = dict(FORM_ATTR_REGEX.findall(i.group(1)))
                name = iattrs.get("name")
                if not name:
                    continue
                inputs[name] = iattrs.get("value", "test")
            forms.append(Form(action=action, method=method, inputs=inputs))
        return links, forms

    def _fetch_and_parse(self, url: str) -> Set[str]:
        """Télécharge une page et met à jour l'état ; renvoie les nouveaux liens."""
        r = self.http.get(url)
        if not r or "text/html" not in r.headers.get("Content-Type", ""):
            return set()

        with self._lock:
            self._result.urls.add(url)
            if urlparse(url).query:
                self._result.parameterized.add(url)

        links, forms = self._extract(r.text, url)

        with self._lock:
            for f in forms:
                if not any(
                    ff.action == f.action and ff.method == f.method and ff.inputs == f.inputs
                    for ff in self._result.forms
                ):
                    self._result.forms.append(f)

        new_links: Set[str] = set()
        for link in links:
            if self.same_domain_only and not same_domain(link, self.base_url):
                continue
            with self._lock:
                if link in self._visited or len(self._visited) >= self.max_urls:
                    continue
                self._visited.add(link)
            new_links.add(link)
        return new_links

    # ------------------------------------------------------------------
    def crawl(self, extra_seeds: Optional[List[str]] = None) -> CrawlResult:
        log_info(
            f"Crawl de {self.base_url} (profondeur ≤ {self.max_depth}, "
            f"max URLs = {self.max_urls}, threads = {self.threads})"
        )
        frontier: Set[str] = {self.base_url}
        if extra_seeds:
            frontier |= {urljoin(self.base_url + "/", s) for s in extra_seeds}
        with self._lock:
            self._visited |= frontier

        depth = 0
        while frontier and depth <= self.max_depth:
            log_debug(f"Profondeur {depth} : {len(frontier)} URL(s) à explorer", self.verbose)
            next_frontier: Set[str] = set()
            with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
                for links in ex.map(self._fetch_and_parse, list(frontier)):
                    next_frontier |= links
            frontier = next_frontier
            depth += 1
            if len(self._result.urls) >= self.max_urls:
                break

        # Analyse des paramètres découverts
        params_seen: Set[str] = set()
        for u in self._result.parameterized:
            for p in parse_qs(urlparse(u).query).keys():
                params_seen.add(p)

        log_ok(f"Crawl terminé : {len(self._result.urls)} URLs, "
               f"{len(self._result.parameterized)} avec paramètres, "
               f"{len(self._result.forms)} formulaire(s), "
               f"{len(params_seen)} paramètre(s) unique(s)")
        return self._result
