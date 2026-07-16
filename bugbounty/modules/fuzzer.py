"""Module de fuzzing (répertoires, paramètres) pour WebBounty."""

from __future__ import annotations

import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

from .utils import (
    Finding,
    build_url_with_params,
    create_session,
    extract_links,
    get_base_url,
    normalize_url,
    safe_request,
)


class FuzzerModule:
    """Fuzzing de répertoires et de paramètres cachés."""

    def __init__(
        self,
        target: str,
        session: requests.Session | None = None,
        threads: int = 15,
        wordlist_dir: Path | None = None,
    ):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session or create_session()
        self.threads = threads
        self.wordlist_dir = wordlist_dir or Path(__file__).parent.parent / "wordlists"
        self.findings: list[Finding] = []
        self.discovered: dict[str, list[str]] = {
            "directories": [],
            "parameters": [],
            "endpoints": [],
        }

    def fuzz_directories(self, custom_wordlist: Path | None = None) -> list[str]:
        """Brute-force de répertoires et fichiers."""
        wordlist_path = custom_wordlist or (self.wordlist_dir / "directories.txt")
        if not wordlist_path.exists():
            return []

        words = [
            w.strip()
            for w in wordlist_path.read_text(encoding="utf-8").splitlines()
            if w.strip() and not w.startswith("#")
        ]

        found: list[str] = []
        baseline = self._get_baseline_response()

        def check_path(word: str) -> tuple[str, int, int] | None:
            url = f"{self.base_url}/{word}"
            resp = safe_request(self.session, "GET", url, allow_redirects=False)
            if not resp:
                return None
            if resp.status_code in (200, 301, 302, 403):
                # Filtrer les faux positifs par taille de contenu
                if baseline and resp.status_code == 200:
                    if abs(len(resp.content) - baseline["size"]) < 50:
                        return None
                return (word, resp.status_code, len(resp.content))
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_path, w): w for w in words}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    path, status, size = result
                    found.append(path)
                    severity = "high" if status == 403 else "info"
                    self.findings.append(
                        Finding(
                            title=f"Chemin découvert: /{path} [{status}]",
                            severity=severity,
                            category="Directory Fuzzing",
                            url=f"{self.base_url}/{path}",
                            description=f"Répertoire/fichier trouvé ({size} bytes)",
                            evidence=f"HTTP {status}",
                        )
                    )

        self.discovered["directories"] = sorted(found)
        return self.discovered["directories"]

    def fuzz_parameters(self, url: str | None = None) -> list[str]:
        """Découverte de paramètres cachés via wordlist."""
        target_url = url or self.target
        wordlist_path = self.wordlist_dir / "parameters.txt"
        if not wordlist_path.exists():
            return []

        words = [
            w.strip()
            for w in wordlist_path.read_text(encoding="utf-8").splitlines()
            if w.strip() and not w.startswith("#")
        ]

        base = target_url.split("?")[0]
        baseline_resp = safe_request(self.session, "GET", base)
        baseline_size = len(baseline_resp.content) if baseline_resp else 0
        baseline_status = baseline_resp.status_code if baseline_resp else 0

        found: list[str] = []

        def check_param(param: str) -> str | None:
            test_url = build_url_with_params(base, {param: "bountystrike_probe"})
            resp = safe_request(self.session, "GET", test_url)
            if not resp:
                return None
            # Paramètre actif si la réponse diffère
            if (
                resp.status_code != baseline_status
                or abs(len(resp.content) - baseline_size) > 100
                or "bountystrike_probe" in resp.text
            ):
                return param
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_param, w): w for w in words}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    self.findings.append(
                        Finding(
                            title=f"Paramètre caché découvert: {result}",
                            severity="info",
                            category="Parameter Discovery",
                            url=build_url_with_params(base, {result: "test"}),
                            description=f"Le paramètre '{result}' modifie la réponse",
                        )
                    )

        self.discovered["parameters"] = sorted(found)
        return self.discovered["parameters"]

    def discover_endpoints_from_js(self) -> list[str]:
        """Extrait des endpoints depuis les fichiers JavaScript."""
        endpoints: set[str] = set()
        resp = safe_request(self.session, "GET", self.target)
        if not resp:
            return []

        # Trouver les scripts JS
        import re

        js_urls = re.findall(
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            resp.text,
            re.IGNORECASE,
        )

        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'endpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        pages_to_scan = [self.target] + [
            urllib.parse.urljoin(self.base_url, js) for js in js_urls[:5]
        ]

        for page_url in pages_to_scan:
            page_resp = safe_request(self.session, "GET", page_url)
            if not page_resp:
                continue
            for pattern in api_patterns:
                matches = re.findall(pattern, page_resp.text, re.IGNORECASE)
                for match in matches:
                    if match.startswith(("/", "http")):
                        full = urllib.parse.urljoin(self.base_url, match)
                        endpoints.add(full)

        self.discovered["endpoints"] = sorted(endpoints)
        for ep in self.discovered["endpoints"][:20]:
            self.findings.append(
                Finding(
                    title=f"Endpoint API découvert",
                    severity="info",
                    category="API Discovery",
                    url=ep,
                    description="Endpoint extrait du code JavaScript",
                )
            )

        return self.discovered["endpoints"]

    def _get_baseline_response(self) -> dict[str, Any] | None:
        """Obtient une réponse baseline pour filtrer les faux positifs."""
        fake_url = f"{self.base_url}/bountystrike_probe_{hash(self.target) % 99999}"
        resp = safe_request(self.session, "GET", fake_url)
        if resp:
            return {"size": len(resp.content), "status": resp.status_code}
        return None
