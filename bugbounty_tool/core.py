"""
Utilitaires partagés pour NCScan.

Gère la session HTTP mutualisée, la rotation de User-Agent, le rate-limiting,
la journalisation colorée et la structure des résultats (findings).
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Couleurs ANSI (aucune dépendance externe requise)
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BG_RED = "\033[41m"


SEVERITY_COLORS = {
    "info": C.BLUE,
    "low": C.CYAN,
    "medium": C.YELLOW,
    "high": C.RED,
    "critical": C.BG_RED + C.WHITE + C.BOLD,
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
def get_logger(name: str = "ncscan", verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        return logger
    handler = logging.StreamHandler()
    fmt = logging.Formatter("%(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    return logger


def log_info(msg: str) -> None:
    print(f"{C.BLUE}[i]{C.RESET} {msg}")


def log_ok(msg: str) -> None:
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def log_warn(msg: str) -> None:
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def log_err(msg: str) -> None:
    print(f"{C.RED}[-]{C.RESET} {msg}")


def log_debug(msg: str, verbose: bool = False) -> None:
    if verbose:
        print(f"{C.DIM}[d] {msg}{C.RESET}")


def log_finding(f: "Finding") -> None:
    color = SEVERITY_COLORS.get(f.severity, C.WHITE)
    tag = f"{color}[{f.severity.upper()}]{C.RESET}"
    print(f"{tag} {C.BOLD}{f.title}{C.RESET} — {f.url}")
    if f.evidence:
        print(f"    {C.DIM}↳ {f.evidence}{C.RESET}")


# ---------------------------------------------------------------------------
# Structures de données
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """Représente une découverte de vulnérabilité ou d'information."""

    module: str
    title: str
    severity: str  # info | low | medium | high | critical
    url: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe: Optional[str] = None
    payload: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Session HTTP mutualisée + rate limiting
# ---------------------------------------------------------------------------
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]


class HttpClient:
    """
    Client HTTP mutualisé avec :
      - pool de connexions (adapters urllib3)
      - retries automatiques (5xx / 429)
      - rate-limiting basique (req/s)
      - rotation optionnelle du User-Agent
      - support proxy (ex: Burp / mitmproxy)
    """

    def __init__(
        self,
        timeout: int = 12,
        rate_limit: float = 20.0,
        proxy: Optional[str] = None,
        insecure: bool = False,
        rotate_ua: bool = True,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        self.timeout = timeout
        self.rate_limit = max(0.1, rate_limit)
        self._min_interval = 1.0 / self.rate_limit
        self._last_ts = 0.0
        self._lock = threading.Lock()
        self.rotate_ua = rotate_ua
        self.insecure = insecure

        self.session = requests.Session()
        retry = Retry(
            total=2,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST", "HEAD", "OPTIONS"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(pool_connections=50, pool_maxsize=100, max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        base_headers = {
            "User-Agent": random.choice(DEFAULT_USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if headers:
            base_headers.update(headers)
        self.session.headers.update(base_headers)

        if cookies:
            self.session.cookies.update(cookies)

        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})

        if insecure:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _throttle(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_ts)
            if wait > 0:
                time.sleep(wait)
            self._last_ts = time.monotonic()

    def request(
        self,
        method: str,
        url: str,
        allow_redirects: bool = True,
        **kwargs: Any,
    ) -> Optional[requests.Response]:
        self._throttle()
        if self.rotate_ua:
            self.session.headers["User-Agent"] = random.choice(DEFAULT_USER_AGENTS)
        try:
            return self.session.request(
                method,
                url,
                timeout=self.timeout,
                verify=not self.insecure,
                allow_redirects=allow_redirects,
                **kwargs,
            )
        except requests.RequestException:
            return None

    def get(self, url: str, **kwargs: Any) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Optional[requests.Response]:
        return self.request("HEAD", url, **kwargs)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def normalize_target(target: str) -> str:
    """Ajoute https:// si nécessaire, retire le trailing slash."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def same_domain(url: str, root: str) -> bool:
    try:
        return urlparse(url).netloc.split(":")[0].endswith(
            urlparse(root).netloc.split(":")[0]
        )
    except Exception:
        return False


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, -1), f.module, f.title),
    )
