"""Module de scan de vulnérabilités pour WebBounty."""

from __future__ import annotations

import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

from .utils import (
    Finding,
    build_url_with_params,
    create_session,
    extract_forms,
    extract_params_from_url,
    get_base_url,
    normalize_url,
    safe_request,
)


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HSTS manquant — risque de downgrade HTTPS",
        "remediation": "Ajouter: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "CSP manquant — protection XSS réduite",
        "remediation": "Implémenter une Content-Security-Policy stricte",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options manquant — risque de clickjacking",
        "remediation": "Ajouter: X-Frame-Options: DENY ou SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options manquant — risque de MIME sniffing",
        "remediation": "Ajouter: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy manquant — fuite d'informations via Referer",
        "remediation": "Ajouter: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy manquant",
        "remediation": "Restreindre les fonctionnalités du navigateur via Permissions-Policy",
    },
}

SENSITIVE_PATHS = [
    (".git/HEAD", "critical", "Exposition du dépôt Git"),
    (".git/config", "critical", "Exposition de la config Git"),
    (".env", "critical", "Fichier .env exposé"),
    (".env.local", "critical", "Fichier .env.local exposé"),
    ("config.php.bak", "high", "Backup de configuration PHP"),
    ("wp-config.php.bak", "high", "Backup WordPress config"),
    ("backup.sql", "critical", "Dump SQL exposé"),
    ("database.sql", "critical", "Dump base de données"),
    ("phpinfo.php", "high", "phpinfo() exposé"),
    ("server-status", "medium", "Apache server-status"),
    ("server-info", "medium", "Apache server-info"),
    (".htaccess", "medium", "Fichier .htaccess exposé"),
    ("web.config", "medium", "Configuration IIS exposée"),
    ("crossdomain.xml", "low", "Politique cross-domain Flash"),
    ("clientaccesspolicy.xml", "low", "Politique Silverlight"),
    ("swagger.json", "info", "Documentation API Swagger"),
    ("api/swagger.json", "info", "Documentation API Swagger"),
    ("openapi.json", "info", "Documentation OpenAPI"),
    (".DS_Store", "low", "Fichier macOS .DS_Store"),
    ("debug", "medium", "Endpoint de debug"),
    ("trace", "medium", "Endpoint trace"),
    ("actuator", "high", "Spring Boot Actuator"),
    ("actuator/env", "critical", "Spring Boot Actuator /env"),
    ("actuator/heapdump", "critical", "Spring Boot heapdump"),
    (".svn/entries", "high", "Dépôt SVN exposé"),
    ("admin", "info", "Panneau admin"),
    ("administrator", "info", "Panneau administrateur"),
    ("login", "info", "Page de connexion"),
    ("api", "info", "Endpoint API"),
    ("graphql", "info", "Endpoint GraphQL"),
    (".well-known/security.txt", "info", "security.txt"),
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    "<svg/onload=alert(1)>",
    "{{7*7}}",
    "${7*7}",
]

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "'; WAITFOR DELAY '0:0:3'--",
]

SQLI_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "sqlite3",
    "postgresql",
    "ora-",
    "unclosed quotation",
    "quoted string not properly terminated",
    "syntax error",
    "odbc",
    "jdbc",
    "warning: pg_",
    "valid mysql result",
    "mssql",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    "////evil.com",
]


class VulnScanner:
    """Scanner de vulnérabilités web pour bug bounty."""

    def __init__(
        self,
        target: str,
        session: requests.Session | None = None,
        threads: int = 10,
        aggressive: bool = False,
    ):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session or create_session()
        self.threads = threads
        self.aggressive = aggressive
        self.findings: list[Finding] = []

    def run_full_scan(self, urls: list[str] | None = None) -> list[Finding]:
        """Lance tous les tests de vulnérabilité."""
        self.check_security_headers()
        self.check_cors()
        self.check_cookie_security()
        self.scan_sensitive_files()
        self.check_http_methods()

        scan_urls = urls or [self.target]
        for url in scan_urls[:10]:
            self.test_open_redirect(url)
            self.test_xss_reflected(url)
            if self.aggressive:
                self.test_sqli(url)
                self.test_ssrf_params(url)

        forms_resp = safe_request(self.session, "GET", self.target)
        if forms_resp:
            for form in extract_forms(forms_resp.text):
                self._analyze_form(form)

        return self.findings

    def check_security_headers(self) -> None:
        """Vérifie les en-têtes de sécurité HTTP."""
        resp = safe_request(self.session, "GET", self.target)
        if not resp:
            return

        for header, info in SECURITY_HEADERS.items():
            if header.lower() not in {h.lower() for h in resp.headers}:
                self.findings.append(
                    Finding(
                        title=f"En-tête de sécurité manquant: {header}",
                        severity=info["severity"],
                        category="Security Headers",
                        url=self.target,
                        description=info["description"],
                        remediation=info["remediation"],
                    )
                )

        # Vérifications supplémentaires sur les en-têtes présents
        csp = resp.headers.get("Content-Security-Policy", "")
        if csp and "unsafe-inline" in csp:
            self.findings.append(
                Finding(
                    title="CSP contient unsafe-inline",
                    severity="low",
                    category="Security Headers",
                    url=self.target,
                    description="La CSP autorise unsafe-inline, réduisant la protection XSS",
                    evidence=csp[:200],
                    remediation="Retirer unsafe-inline et utiliser des nonces ou hashes",
                )
            )

        server = resp.headers.get("Server", "")
        if server:
            self.findings.append(
                Finding(
                    title=f"Fuite de version serveur: {server}",
                    severity="info",
                    category="Information Disclosure",
                    url=self.target,
                    description="L'en-tête Server révèle des informations sur le serveur",
                    evidence=server,
                    remediation="Masquer ou généraliser l'en-tête Server",
                )
            )

    def check_cors(self) -> None:
        """Teste les mauvaises configurations CORS."""
        test_origins = [
            "https://evil.com",
            f"https://{urllib.parse.urlparse(self.target).netloc}.evil.com",
            "null",
        ]
        for origin in test_origins:
            resp = safe_request(
                self.session,
                "GET",
                self.target,
                headers={"Origin": origin},
            )
            if not resp:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*" and acac.lower() == "true":
                self.findings.append(
                    Finding(
                        title="CORS critique: wildcard + credentials",
                        severity="critical",
                        category="CORS Misconfiguration",
                        url=self.target,
                        description="ACAO=* avec Allow-Credentials=true permet le vol de données",
                        evidence=f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                        remediation="Ne jamais combiner * et credentials",
                    )
                )
            elif acao == origin:
                self.findings.append(
                    Finding(
                        title="CORS reflète l'origine arbitraire",
                        severity="high",
                        category="CORS Misconfiguration",
                        url=self.target,
                        description=f"Le serveur reflète l'origine: {origin}",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        remediation="Valider strictement les origines autorisées",
                    )
                )
            elif acao == "*":
                self.findings.append(
                    Finding(
                        title="CORS wildcard (ACAO: *)",
                        severity="medium",
                        category="CORS Misconfiguration",
                        url=self.target,
                        description="Toute origine peut lire les réponses",
                        evidence=f"ACAO: {acao}",
                        remediation="Restreindre aux origines de confiance",
                    )
                )

    def check_cookie_security(self) -> None:
        """Analyse la sécurité des cookies."""
        resp = safe_request(self.session, "GET", self.target)
        if not resp:
            return

        cookies = resp.headers.get("Set-Cookie", "")
        if not cookies:
            return

        for cookie_part in cookies.split(","):
            cookie_lower = cookie_part.lower()
            cookie_name = cookie_part.split("=")[0].strip()

            if "secure" not in cookie_lower and self.target.startswith("https"):
                self.findings.append(
                    Finding(
                        title=f"Cookie sans flag Secure: {cookie_name}",
                        severity="medium",
                        category="Cookie Security",
                        url=self.target,
                        description="Cookie transmis potentiellement en HTTP clair",
                        evidence=cookie_part[:150],
                        remediation="Ajouter le flag Secure à tous les cookies sensibles",
                    )
                )
            if "httponly" not in cookie_lower:
                self.findings.append(
                    Finding(
                        title=f"Cookie sans flag HttpOnly: {cookie_name}",
                        severity="medium",
                        category="Cookie Security",
                        url=self.target,
                        description="Cookie accessible via JavaScript (risque XSS)",
                        evidence=cookie_part[:150],
                        remediation="Ajouter le flag HttpOnly",
                    )
                )
            if "samesite" not in cookie_lower:
                self.findings.append(
                    Finding(
                        title=f"Cookie sans SameSite: {cookie_name}",
                        severity="low",
                        category="Cookie Security",
                        url=self.target,
                        description="Cookie vulnérable au CSRF",
                        evidence=cookie_part[:150],
                        remediation="Ajouter SameSite=Strict ou Lax",
                    )
                )

    def scan_sensitive_files(self) -> None:
        """Recherche de fichiers et chemins sensibles."""
        def check_path(path_info: tuple) -> Finding | None:
            path, severity, desc = path_info
            url = f"{self.base_url}/{path.lstrip('/')}"
            resp = safe_request(self.session, "GET", url, allow_redirects=False)
            if not resp:
                return None

            if resp.status_code == 200 and len(resp.content) > 0:
                # Éviter les faux positifs sur les pages 404 custom
                if resp.status_code == 200:
                    content_lower = resp.text[:500].lower()
                    if "not found" in content_lower and "404" in content_lower:
                        return None
                    if path.endswith(".git/HEAD") and "[core]" not in resp.text and "ref:" not in resp.text:
                        return None
                    return Finding(
                        title=f"Fichier sensible accessible: /{path}",
                        severity=severity,
                        category="Sensitive File Exposure",
                        url=url,
                        description=desc,
                        evidence=resp.text[:200],
                        remediation="Restreindre l'accès ou supprimer le fichier",
                    )
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_path, p): p for p in SENSITIVE_PATHS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.findings.append(result)

    def check_http_methods(self) -> None:
        """Teste les méthodes HTTP dangereuses."""
        dangerous = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
        for method in dangerous:
            resp = safe_request(self.session, method, self.target)
            if resp and resp.status_code not in (405, 501, 403, 404):
                severity = "high" if method == "TRACE" else "medium"
                self.findings.append(
                    Finding(
                        title=f"Méthode HTTP {method} autorisée",
                        severity=severity,
                        category="HTTP Methods",
                        url=self.target,
                        description=f"Le serveur accepte la méthode {method} (status: {resp.status_code})",
                        evidence=f"Status: {resp.status_code}",
                        remediation=f"Désactiver la méthode {method} si non nécessaire",
                    )
                )

    def test_xss_reflected(self, url: str) -> None:
        """Teste les XSS réfléchis sur les paramètres GET."""
        params = extract_params_from_url(url)
        if not params:
            # Tester avec un paramètre commun
            params = {"q": "test", "search": "test", "id": "1"}

        for param_name in list(params.keys())[:5]:
            for payload in XSS_PAYLOADS[:3]:
                test_params = params.copy()
                test_params[param_name] = payload
                test_url = build_url_with_params(
                    urllib.parse.urlparse(url)._replace(query="").geturl()
                    if "?" in url
                    else url.split("?")[0],
                    test_params,
                )
                resp = safe_request(self.session, "GET", test_url)
                if not resp:
                    continue

                if payload in resp.text or "alert(1)" in resp.text or "alert(\"XSS\")" in resp.text:
                    self.findings.append(
                        Finding(
                            title=f"XSS réfléchi potentiel — paramètre '{param_name}'",
                            severity="high",
                            category="Cross-Site Scripting (XSS)",
                            url=test_url,
                            description=f"Le payload XSS est réfléchi sans encodage dans la réponse",
                            evidence=f"Payload: {payload}",
                            remediation="Encoder toutes les sorties HTML (OWASP XSS Prevention)",
                        )
                    )
                    return

    def test_sqli(self, url: str) -> None:
        """Teste les injections SQL basiques."""
        params = extract_params_from_url(url)
        if not params:
            return

        for param_name in list(params.keys())[:3]:
            for payload in SQLI_PAYLOADS[:4]:
                test_params = params.copy()
                test_params[param_name] = payload
                base = url.split("?")[0]
                test_url = build_url_with_params(base, test_params)
                resp = safe_request(self.session, "GET", test_url)
                if not resp:
                    continue

                body_lower = resp.text.lower()
                for error in SQLI_ERRORS:
                    if error in body_lower:
                        self.findings.append(
                            Finding(
                                title=f"SQL Injection potentielle — paramètre '{param_name}'",
                                severity="critical",
                                category="SQL Injection",
                                url=test_url,
                                description="Message d'erreur SQL détecté dans la réponse",
                                evidence=f"Erreur: {error}, Payload: {payload}",
                                remediation="Utiliser des requêtes préparées (prepared statements)",
                            )
                        )
                        return

    def test_open_redirect(self, url: str) -> None:
        """Teste les redirections ouvertes."""
        redirect_params = ["url", "redirect", "next", "return", "returnUrl", "goto", "dest", "destination", "redir", "redirect_uri"]
        base = url.split("?")[0]

        for param in redirect_params:
            for payload in OPEN_REDIRECT_PAYLOADS[:2]:
                test_url = build_url_with_params(base, {param: payload})
                resp = safe_request(self.session, "GET", test_url, allow_redirects=False)
                if not resp:
                    continue

                location = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308):
                    if "evil.com" in location:
                        self.findings.append(
                            Finding(
                                title=f"Open Redirect — paramètre '{param}'",
                                severity="medium",
                                category="Open Redirect",
                                url=test_url,
                                description="Redirection vers un domaine externe non validé",
                                evidence=f"Location: {location}",
                                remediation="Valider les URLs de redirection contre une whitelist",
                            )
                        )
                        return

    def test_ssrf_params(self, url: str) -> None:
        """Détecte les paramètres potentiellement vulnérables au SSRF."""
        ssrf_params = ["url", "uri", "path", "dest", "redirect", "proxy", "feed", "host", "site", "html", "callback"]
        params = extract_params_from_url(url)
        base = url.split("?")[0]

        for param in ssrf_params:
            test_url = build_url_with_params(base, {param: "http://169.254.169.254/"})
            resp = safe_request(self.session, "GET", test_url)
            if resp and any(
                indicator in resp.text.lower()
                for indicator in ("ami-id", "instance-id", "meta-data", "169.254.169.254")
            ):
                self.findings.append(
                    Finding(
                        title=f"SSRF potentiel — paramètre '{param}'",
                        severity="critical",
                        category="Server-Side Request Forgery (SSRF)",
                        url=test_url,
                        description="Réponse suggérant un accès aux métadonnées cloud",
                        evidence=resp.text[:200],
                        remediation="Valider et restreindre les URLs côté serveur",
                    )
                )

    def _analyze_form(self, form: dict[str, Any]) -> None:
        """Analyse un formulaire HTML pour des problèmes de sécurité."""
        if form["method"] == "GET" and any(
            f["type"] in ("password", "hidden") for f in form["fields"]
        ):
            action = urllib.parse.urljoin(self.target, form.get("action", ""))
            self.findings.append(
                Finding(
                    title="Formulaire sensible en méthode GET",
                    severity="medium",
                    category="Insecure Form",
                    url=action or self.target,
                    description="Des champs sensibles sont envoyés via GET (visible dans l'URL/logs)",
                    evidence=str(form["fields"]),
                    remediation="Utiliser POST pour les formulaires contenant des données sensibles",
                )
            )

        if not any(f["type"] == "hidden" and "csrf" in f["name"].lower() for f in form["fields"]):
            if form["method"] == "POST" and len(form["fields"]) > 0:
                action = urllib.parse.urljoin(self.target, form.get("action", ""))
                self.findings.append(
                    Finding(
                        title="Formulaire POST sans token CSRF visible",
                        severity="low",
                        category="CSRF",
                        url=action or self.target,
                        description="Aucun token CSRF détecté dans le formulaire",
                        evidence=str(form["fields"][:5]),
                        remediation="Implémenter des tokens CSRF synchronisés",
                    )
                )
