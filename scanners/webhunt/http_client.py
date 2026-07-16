"""Client HTTP avec périmètre, limitation de débit et robustesse.

Toutes les requêtes réseau de WebHunt passent par ce client afin de
centraliser l'application du périmètre (scope), la limitation de débit,
les tentatives de reprise et la collecte de statistiques.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

import requests
from requests.adapters import HTTPAdapter

try:  # urllib3 est fourni par requests
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    Retry = None  # type: ignore

from .scope import Scope

DEFAULT_UA = (
    "WebHunt/1.0 (+bug-bounty-recon; usage autorisé uniquement)"
)


class OutOfScopeError(Exception):
    """Levée quand une requête viserait un hôte hors périmètre."""


class RateLimiter:
    """Limiteur de débit simple, thread-safe (requêtes par seconde)."""

    def __init__(self, rate_per_sec: float) -> None:
        self.min_interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0.0
        self._lock = threading.Lock()
        self._next_time = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_time:
                sleep_for = self._next_time - now
            else:
                sleep_for = 0.0
            self._next_time = max(now, self._next_time) + self.min_interval
        if sleep_for > 0:
            time.sleep(sleep_for)


@dataclass
class HttpStats:
    requests_sent: int = 0
    bytes_received: int = 0
    errors: int = 0
    by_status: Dict[int, int] = field(default_factory=dict)


class HttpClient:
    """Wrapper autour de requests.Session respectant le périmètre."""

    def __init__(
        self,
        scope: Scope,
        rate_per_sec: float = 5.0,
        timeout: float = 12.0,
        user_agent: str = DEFAULT_UA,
        verify_tls: bool = True,
        max_retries: int = 2,
        proxy: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.scope = scope
        self.timeout = timeout
        self.limiter = RateLimiter(rate_per_sec)
        self.verify_tls = verify_tls
        self.stats = HttpStats()
        self._lock = threading.Lock()

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        if extra_headers:
            self.session.headers.update(extra_headers)
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})

        if Retry is not None and max_retries > 0:
            retry = Retry(
                total=max_retries,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=frozenset(
                    ["GET", "HEAD", "OPTIONS", "POST"]
                ),
            )
            adapter = HTTPAdapter(max_retries=retry, pool_maxsize=32)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)

    def _record(self, resp: Optional[requests.Response], error: bool = False) -> None:
        with self._lock:
            self.stats.requests_sent += 1
            if error or resp is None:
                self.stats.errors += 1
                return
            self.stats.by_status[resp.status_code] = (
                self.stats.by_status.get(resp.status_code, 0) + 1
            )
            try:
                self.stats.bytes_received += len(resp.content or b"")
            except Exception:
                pass

    def request(
        self,
        method: str,
        url: str,
        allow_redirects: bool = True,
        enforce_scope: bool = True,
        **kwargs,
    ) -> Optional[requests.Response]:
        """Effectue une requête HTTP en respectant le périmètre.

        Retourne None en cas d'erreur réseau (loggée dans les stats).
        """
        if enforce_scope and not self.scope.is_allowed(url):
            raise OutOfScopeError(f"Hôte hors périmètre : {url}")

        self.limiter.wait()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_tls)
        try:
            resp = self.session.request(
                method, url, allow_redirects=allow_redirects, **kwargs
            )
            self._record(resp)
            return resp
        except requests.RequestException:
            self._record(None, error=True)
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("OPTIONS", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def close(self) -> None:
        self.session.close()
