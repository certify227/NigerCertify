"""Scanner GraphQL offensif pour WebBounty."""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

import requests

from .utils import Finding, get_base_url, normalize_url, safe_request

GRAPHQL_PATHS = [
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
    "/playground",
    "/altair",
    "/api/gql",
    "/graphql/console",
    "/graphql.php",
    "/___graphql",
]

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args { name type { name kind } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

BATCH_QUERY = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]

DEPTH_QUERY = """
query DeepQuery {
  a1: __typename
  a2: __typename
  a3: __typename
  a4: __typename
  a5: __typename
  a6: __typename
  a7: __typename
  a8: __typename
  a9: __typename
  a10: __typename
}
"""


class GraphQLScanner:
    """Scanner GraphQL — découverte, introspection et attaques."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.findings: list[Finding] = []
        self.endpoints: list[str] = []

    def run_full_scan(self) -> list[Finding]:
        """Lance tous les tests GraphQL."""
        self._discover_endpoints()
        for endpoint in self.endpoints:
            self._test_introspection(endpoint)
            self._test_field_suggestions(endpoint)
            self._test_batching(endpoint)
            self._test_depth_limit(endpoint)
            self._test_mutations_unauth(endpoint)
            self._test_dos_aliases(endpoint)
        return self.findings

    def _discover_endpoints(self) -> None:
        """Découvre les endpoints GraphQL."""
        # Depuis la page principale
        resp = safe_request(self.session, "GET", self.target)
        if resp:
            for match in re.findall(r'["\']([^"\']*graphql[^"\']*)["\']', resp.text, re.I):
                url = urllib.parse.urljoin(self.base_url, match)
                if url not in self.endpoints:
                    self.endpoints.append(url)

        for path in GRAPHQL_PATHS:
            url = f"{self.base_url}{path}"
            resp = safe_request(
                self.session,
                "POST",
                url,
                json={"query": "{ __typename }"},
                headers={"Content-Type": "application/json"},
            )
            if resp and resp.status_code in (200, 400) and (
                "graphql" in resp.text.lower()
                or "__typename" in resp.text
                or "errors" in resp.text
            ):
                if url not in self.endpoints:
                    self.endpoints.append(url)
                    self.findings.append(
                        Finding(
                            title=f"Endpoint GraphQL découvert: {path}",
                            severity="info",
                            category="GraphQL",
                            url=url,
                            description="Endpoint GraphQL actif",
                            evidence=resp.text[:200],
                        )
                    )

    def _graphql_request(self, endpoint: str, query: str | list, variables: dict | None = None) -> requests.Response | None:
        """Envoie une requête GraphQL."""
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        return safe_request(
            self.session,
            "POST",
            endpoint,
            json=payload,
            headers={"Content-Type": "application/json"},
        )

    def _test_introspection(self, endpoint: str) -> None:
        """Teste si l'introspection est activée."""
        resp = self._graphql_request(endpoint, INTROSPECTION_QUERY)
        if not resp:
            return

        try:
            data = resp.json()
            if data.get("data", {}).get("__schema"):
                types = data["data"]["__schema"].get("types", [])
                type_names = [t["name"] for t in types if not t["name"].startswith("__")][:20]
                self.findings.append(
                    Finding(
                        title="Introspection GraphQL activée",
                        severity="high",
                        category="GraphQL",
                        url=endpoint,
                        description=f"Introspection complète disponible — {len(types)} types exposés",
                        evidence=f"Types: {', '.join(type_names)}",
                        remediation="Désactiver l'introspection en production",
                    )
                )

                # Chercher des types/mutations sensibles
                sensitive = ["admin", "user", "password", "secret", "token", "delete", "internal"]
                for t in types:
                    name_lower = t.get("name", "").lower()
                    if any(s in name_lower for s in sensitive):
                        self.findings.append(
                            Finding(
                                title=f"Type GraphQL sensible: {t['name']}",
                                severity="medium",
                                category="GraphQL",
                                url=endpoint,
                                description=f"Type '{t['name']}' exposé via introspection",
                                evidence=json.dumps(t)[:300],
                            )
                        )
        except (json.JSONDecodeError, KeyError):
            pass

    def _test_field_suggestions(self, endpoint: str) -> None:
        """Teste les suggestions de champs (information disclosure)."""
        resp = self._graphql_request(endpoint, "{ __schema { nonExistentField12345 } }")
        if not resp:
            return

        body = resp.text.lower()
        if "did you mean" in body or "suggestion" in body or "cannot query field" in body:
            self.findings.append(
                Finding(
                    title="Suggestions de champs GraphQL activées",
                    severity="medium",
                    category="GraphQL",
                    url=endpoint,
                    description="Le serveur révèle des noms de champs via les erreurs",
                    evidence=resp.text[:300],
                    remediation="Désactiver les suggestions de champs en production",
                )
            )

    def _test_batching(self, endpoint: str) -> None:
        """Teste le batching de requêtes (bypass rate limit / brute-force)."""
        resp = safe_request(
            self.session,
            "POST",
            endpoint,
            json=BATCH_QUERY,
            headers={"Content-Type": "application/json"},
        )
        if not resp:
            return

        try:
            data = resp.json()
            if isinstance(data, list) and len(data) >= 3:
                self.findings.append(
                    Finding(
                        title="Batching GraphQL autorisé",
                        severity="medium",
                        category="GraphQL",
                        url=endpoint,
                        description=f"Le serveur accepte {len(data)} requêtes batchées — bypass rate limit possible",
                        evidence=f"Batch size: {len(data)}",
                        remediation="Limiter ou désactiver le batching de requêtes",
                    )
                )
        except json.JSONDecodeError:
            pass

    def _test_depth_limit(self, endpoint: str) -> None:
        """Teste les limites de profondeur de requête."""
        resp = self._graphql_request(endpoint, DEPTH_QUERY)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if "data" in data and not data.get("errors"):
                    self.findings.append(
                        Finding(
                            title="Pas de limite de profondeur GraphQL",
                            severity="medium",
                            category="GraphQL",
                            url=endpoint,
                            description="Requêtes profondes acceptées — risque de DoS",
                            remediation="Implémenter une limite de profondeur (max depth)",
                        )
                    )
            except json.JSONDecodeError:
                pass

    def _test_mutations_unauth(self, endpoint: str) -> None:
        """Teste l'accès aux mutations sans authentification."""
        resp = self._graphql_request(endpoint, INTROSPECTION_QUERY)
        if not resp:
            return

        try:
            data = resp.json()
            mutation_type = data.get("data", {}).get("__schema", {}).get("mutationType")
            if not mutation_type:
                return

            types = data["data"]["__schema"].get("types", [])
            mutations = []
            for t in types:
                if t.get("name") == mutation_type.get("name"):
                    mutations = [f["name"] for f in t.get("fields", [])]

            dangerous = ["delete", "create", "update", "admin", "register", "reset", "grant"]
            for mutation in mutations[:10]:
                if any(d in mutation.lower() for d in dangerous):
                    test_resp = self._graphql_request(endpoint, f"mutation {{ {mutation} }}")
                    if test_resp and test_resp.status_code == 200:
                        body = test_resp.text.lower()
                        if "unauthorized" not in body and "forbidden" not in body and "error" not in body:
                            self.findings.append(
                                Finding(
                                    title=f"Mutation '{mutation}' accessible sans auth",
                                    severity="high",
                                    category="GraphQL",
                                    url=endpoint,
                                    description=f"Mutation potentiellement accessible: {mutation}",
                                    evidence=test_resp.text[:200],
                                    remediation="Protéger toutes les mutations par authentification",
                                )
                            )
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    def _test_dos_aliases(self, endpoint: str) -> None:
        """Teste les attaques par alias (DoS)."""
        aliases = " ".join(f"a{i}: __typename" for i in range(50))
        query = f"query {{ {aliases} }}"
        resp = self._graphql_request(endpoint, query)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if data.get("data") and len(data["data"]) >= 40:
                    self.findings.append(
                        Finding(
                            title="Pas de limite d'alias GraphQL",
                            severity="medium",
                            category="GraphQL",
                            url=endpoint,
                            description="50 alias acceptés — risque de DoS par requêtes complexes",
                            remediation="Limiter le nombre d'alias par requête",
                        )
                    )
            except (json.JSONDecodeError, TypeError):
                pass
