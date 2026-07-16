"""OpenAPI/Swagger automated testing."""

from __future__ import annotations

import json
import re

import requests

from .utils import Finding, get_base_url, normalize_url, safe_request

SPEC_PATHS = [
    "/swagger.json", "/openapi.json", "/api/swagger.json", "/v1/swagger.json",
    "/api-docs", "/swagger/v1/swagger.json", "/v2/api-docs", "/api/openapi.json",
]


class APIScanner:
    """Teste automatiquement les APIs depuis OpenAPI/Swagger."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.findings: list[Finding] = []
        self.spec: dict | None = None

    def run_full_scan(self) -> list[Finding]:
        self._fetch_spec()
        if self.spec:
            self._test_endpoints()
            self._test_auth_bypass()
        return self.findings

    def _fetch_spec(self) -> None:
        for path in SPEC_PATHS:
            url = f"{self.base_url}{path}"
            resp = safe_request(self.session, "GET", url)
            if resp and resp.status_code == 200:
                try:
                    self.spec = resp.json()
                    self.findings.append(
                        Finding(
                            title=f"OpenAPI spec exposée: {path}",
                            severity="medium",
                            category="API",
                            url=url,
                            description="Spécification API publiquement accessible",
                        )
                    )
                    return
                except json.JSONDecodeError:
                    pass

    def _test_endpoints(self) -> None:
        if not self.spec:
            return
        paths = self.spec.get("paths", {})
        for path, methods in list(paths.items())[:30]:
            for method, details in methods.items():
                if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                    continue
                url = f"{self.base_url}{path}"
                security = details.get("security", self.spec.get("security", []))
                resp = safe_request(self.session, method.upper(), url)
                if resp and resp.status_code == 200 and security:
                    self.findings.append(
                        Finding(
                            title=f"API endpoint sans auth: {method.upper()} {path}",
                            severity="high",
                            category="API",
                            url=url,
                            description="Endpoint marqué sécurisé mais accessible",
                            evidence=f"Status: {resp.status_code}",
                        )
                    )

    def _test_auth_bypass(self) -> None:
        if not self.spec:
            return
        for path in list(self.spec.get("paths", {}).keys())[:10]:
            url = f"{self.base_url}{path}"
            for header in ({"X-Original-URL": path}, {"X-Rewrite-URL": path}, {"X-Custom-IP-Authorization": "127.0.0.1"}):
                resp = safe_request(self.session, "GET", self.base_url, headers=header)
                if resp and resp.status_code == 200:
                    self.findings.append(
                        Finding(
                            title="API auth bypass via header",
                            severity="high",
                            category="API",
                            url=url,
                            description=f"Bypass via {list(header.keys())[0]}",
                            evidence=str(header),
                        )
                    )
