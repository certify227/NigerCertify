"""Business logic — race conditions, manipulation."""

from __future__ import annotations

import concurrent.futures

import requests

from .utils import Finding, get_base_url, normalize_url, safe_request


class BusinessLogicScanner:
    """Teste les failles de logique métier."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.findings: list[Finding] = []

    def run_full_scan(self) -> list[Finding]:
        self._test_race_condition()
        self._test_negative_values()
        self._test_price_manipulation()
        return self.findings

    def _test_race_condition(self) -> None:
        endpoints = [
            (f"{self.base_url}/api/coupon", {"code": "TEST"}),
            (f"{self.base_url}/api/redeem", {"code": "PROMO"}),
            (f"{self.base_url}/api/transfer", {"amount": "1"}),
        ]
        for url, data in endpoints:
            def fire():
                return safe_request(self.session, "POST", url, json=data)

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                futures = [ex.submit(fire) for _ in range(10)]
                results = [f.result() for f in futures if f.result()]

            successes = [r for r in results if r.status_code in (200, 201)]
            if len(successes) > 1:
                self.findings.append(
                    Finding(
                        title=f"Race condition possible: {url}",
                        severity="high",
                        category="Race Condition",
                        url=url,
                        description=f"{len(successes)}/10 requêtes parallèles réussies",
                        evidence=str(data),
                        remediation="Implémenter des verrous/idempotency keys",
                    )
                )

    def _test_negative_values(self) -> None:
        endpoints = [
            (f"{self.base_url}/api/cart", {"quantity": -1}),
            (f"{self.base_url}/api/order", {"amount": -100}),
            (f"{self.base_url}/api/transfer", {"amount": -1}),
        ]
        for url, data in endpoints:
            resp = safe_request(self.session, "POST", url, json=data)
            if resp and resp.status_code in (200, 201):
                self.findings.append(
                    Finding(
                        title=f"Valeur négative acceptée: {url}",
                        severity="high",
                        category="Business Logic",
                        url=url,
                        description="Valeurs négatives non rejetées",
                        evidence=str(data),
                    )
                )

    def _test_price_manipulation(self) -> None:
        endpoints = [
            (f"{self.base_url}/api/checkout", {"price": 0}),
            (f"{self.base_url}/api/checkout", {"price": 0.01}),
            (f"{self.base_url}/api/cart", {"total": 0}),
        ]
        for url, data in endpoints:
            resp = safe_request(self.session, "POST", url, json=data)
            if resp and resp.status_code in (200, 201) and "error" not in resp.text.lower():
                self.findings.append(
                    Finding(
                        title=f"Manipulation de prix: {url}",
                        severity="critical",
                        category="Business Logic",
                        url=url,
                        description="Prix manipulable côté client",
                        evidence=str(data),
                        remediation="Recalculer le prix côté serveur",
                    )
                )
