"""Client HTTP mutualisé : rate limiting, retries, en-têtes personnalisés."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

import requests
from requests.adapters import HTTPAdapter

try:  # urllib3 est fourni avec requests
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    Retry = None  # type: ignore

DEFAULT_UA = (
    "web_bugbounty/1.0 (+authorized security testing; "
    "https://github.com/Niger-Certify)"
)


@dataclass
class HttpConfig:
    timeout: float = 10.0
    max_retries: int = 2
    rate_limit: float = 0.0  # secondes minimum entre 2 requêtes (0 = illimité)
    verify_tls: bool = True
    follow_redirects: bool = True
    proxy: Optional[str] = None
    user_agent: str = DEFAULT_UA
    extra_headers: Optional[Dict[str, str]] = None


class RateLimiter:
    """Limiteur de débit simple et thread-safe."""

    def __init__(self, min_interval: float) -> None:
        self.min_interval = max(0.0, min_interval)
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                time.sleep(self._next_allowed - now)
                now = time.monotonic()
            self._next_allowed = now + self.min_interval


class HttpClient:
    """Enveloppe autour de requests.Session, réutilisable et thread-safe."""

    def __init__(self, config: HttpConfig | None = None) -> None:
        self.config = config or HttpConfig()
        self._limiter = RateLimiter(self.config.rate_limit)
        self._local = threading.local()
        self.stats_lock = threading.Lock()
        self.requests_sent = 0

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            headers = {
                "User-Agent": self.config.user_agent,
                "Accept": "*/*",
                "Connection": "close",
            }
            if self.config.extra_headers:
                headers.update(self.config.extra_headers)
            session.headers.update(headers)
            if self.config.proxy:
                session.proxies = {
                    "http": self.config.proxy,
                    "https": self.config.proxy,
                }
            if Retry is not None and self.config.max_retries > 0:
                retry = Retry(
                    total=self.config.max_retries,
                    backoff_factor=0.4,
                    status_forcelist=(429, 500, 502, 503, 504),
                    allowed_methods=frozenset(
                        ["GET", "HEAD", "OPTIONS", "POST"]
                    ),
                    raise_on_status=False,
                )
                adapter = HTTPAdapter(max_retries=retry)
                session.mount("http://", adapter)
                session.mount("https://", adapter)
            self._local.session = session
        return session

    def request(
        self,
        method: str,
        url: str,
        *,
        allow_redirects: Optional[bool] = None,
        **kwargs,
    ) -> Optional[requests.Response]:
        self._limiter.wait()
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("verify", self.config.verify_tls)
        if allow_redirects is None:
            allow_redirects = self.config.follow_redirects
        try:
            resp = self._session().request(
                method.upper(), url, allow_redirects=allow_redirects, **kwargs
            )
        except requests.RequestException:
            return None
        with self.stats_lock:
            self.requests_sent += 1
        return resp

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)
