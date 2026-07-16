#!/usr/bin/env python3
"""
WebSentinel - scanner bug bounty non destructif pour applications web.

Usage autorise uniquement: lancez cet outil sur vos propres applications, vos
labs ou des cibles explicitement incluses dans un programme bug bounty.
"""

from __future__ import annotations

import argparse
import html.parser
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.message import Message
from http.cookies import SimpleCookie
from typing import Iterable, Optional


DEFAULT_HEADERS = {
    "User-Agent": "WebSentinel/1.0 authorized-security-research",
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
}

SECURITY_HEADERS = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
}

EXPOSURE_PATHS = (
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/.env",
    "/backup.zip",
)

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    title: str
    url: str
    evidence: str
    recommendation: str


@dataclass
class HttpResponse:
    url: str
    status: int
    reason: str
    headers: Message
    body: bytes

    @property
    def text(self) -> str:
        content_type = self.headers.get("Content-Type", "")
        charset = "utf-8"
        if "charset=" in content_type:
            charset = content_type.rsplit("charset=", 1)[-1].split(";")[0].strip()
        return self.body.decode(charset or "utf-8", errors="replace")


class LinkAndFormParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.assets: list[str] = []
        self.forms: list[dict[str, object]] = []
        self.meta_generator: Optional[str] = None
        self._current_form: Optional[dict[str, object]] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attributes = {name.lower(): value or "" for name, value in attrs}
        if tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        if tag in {"script", "img", "iframe", "link"}:
            value = attributes.get("src") or attributes.get("href")
            if value:
                self.assets.append(value)
        if tag == "meta" and attributes.get("name", "").lower() == "generator":
            self.meta_generator = attributes.get("content") or ""
        if tag == "form":
            self._current_form = {
                "method": attributes.get("method", "get").lower(),
                "action": attributes.get("action", ""),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        if tag in {"input", "textarea", "select"} and self._current_form is not None:
            inputs = self._current_form["inputs"]
            assert isinstance(inputs, list)
            inputs.append(
                {
                    "name": attributes.get("name", ""),
                    "type": attributes.get("type", "text").lower(),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


class WebSentinelScanner:
    def __init__(
        self,
        target: str,
        *,
        timeout: float = 8.0,
        rate_limit: float = 0.4,
        max_pages: int = 20,
        max_depth: int = 2,
        origin_probe: str = "https://attacker.invalid",
    ) -> None:
        self.target = normalize_url(target)
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.origin_probe = origin_probe
        self.findings: list[Finding] = []
        self.visited: set[str] = set()
        self.responses: list[HttpResponse] = []
        self._last_request_at = 0.0
        self._base = urllib.parse.urlsplit(self.target)
        self._opener = urllib.request.build_opener(NoRedirectHandler)

    def run(self) -> dict[str, object]:
        start = datetime.now(timezone.utc)
        self._add_info("scope", "Scan autorise declare", self.target, "Flag --i-am-authorized fourni.", "Conserver une preuve d'autorisation pour la cible.")
        self._crawl()
        self._check_exposure_paths()
        self._check_cors()
        self._check_http_methods()
        self._check_tls_certificate()
        return {
            "tool": "WebSentinel",
            "target": self.target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round((datetime.now(timezone.utc) - start).total_seconds(), 3),
            "pages_scanned": len(self.visited),
            "requests_sent": len(self.responses),
            "findings": [asdict(finding) for finding in sorted(self.findings, key=finding_sort_key, reverse=True)],
            "summary": self._summary(),
        }

    def _crawl(self) -> None:
        queue: deque[tuple[str, int]] = deque([(self.target, 0)])
        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.popleft()
            url = strip_fragment(url)
            if url in self.visited or not self._same_origin(url):
                continue
            self.visited.add(url)
            response = self._request(url)
            if response is None:
                continue
            self._analyze_response(response)
            if depth >= self.max_depth or "text/html" not in response.headers.get("Content-Type", ""):
                continue
            parser = parse_html(response.text)
            for link in parser.links:
                absolute = urllib.parse.urljoin(response.url, link)
                if self._same_origin(absolute) and strip_fragment(absolute) not in self.visited:
                    queue.append((absolute, depth + 1))

    def _analyze_response(self, response: HttpResponse) -> None:
        self._check_security_headers(response)
        self._check_cookie_flags(response)
        self._check_server_disclosure(response)
        if "text/html" in response.headers.get("Content-Type", ""):
            parser = parse_html(response.text)
            self._check_forms(response, parser)
            self._check_mixed_content(response, parser)
            self._check_generator(response, parser)

    def _check_security_headers(self, response: HttpResponse) -> None:
        present = {header.lower() for header in response.headers.keys()}
        for lowered, display in SECURITY_HEADERS.items():
            if lowered not in present:
                severity = "medium" if display in {"Content-Security-Policy", "Strict-Transport-Security"} else "low"
                if display == "Strict-Transport-Security" and urllib.parse.urlsplit(response.url).scheme != "https":
                    severity = "info"
                self.findings.append(
                    Finding(
                        severity=severity,
                        category="headers",
                        title=f"En-tete manquant: {display}",
                        url=response.url,
                        evidence=f"{display} absent sur la reponse HTTP {response.status}.",
                        recommendation=f"Ajouter {display} avec une valeur adaptee a l'application.",
                    )
                )
        csp = response.headers.get("Content-Security-Policy", "")
        if csp and ("unsafe-inline" in csp or "*" in csp):
            self.findings.append(
                Finding(
                    severity="medium",
                    category="headers",
                    title="Content-Security-Policy permissive",
                    url=response.url,
                    evidence=csp,
                    recommendation="Limiter les sources CSP et supprimer unsafe-inline lorsque possible.",
                )
            )

    def _check_cookie_flags(self, response: HttpResponse) -> None:
        for raw_cookie in response.headers.get_all("Set-Cookie", []):
            cookie = SimpleCookie()
            try:
                cookie.load(raw_cookie)
            except Exception:
                continue
            for morsel in cookie.values():
                missing = []
                if not morsel["httponly"]:
                    missing.append("HttpOnly")
                if not morsel["secure"]:
                    missing.append("Secure")
                if not morsel["samesite"]:
                    missing.append("SameSite")
                if missing:
                    self.findings.append(
                        Finding(
                            severity="medium",
                            category="cookies",
                            title=f"Cookie sans attributs defensifs: {morsel.key}",
                            url=response.url,
                            evidence=f"Attributs manquants: {', '.join(missing)}.",
                            recommendation="Ajouter Secure, HttpOnly et SameSite=Lax/Strict aux cookies sensibles.",
                        )
                    )

    def _check_server_disclosure(self, response: HttpResponse) -> None:
        server = response.headers.get("Server", "")
        powered_by = response.headers.get("X-Powered-By", "")
        if server:
            self._add_info("fingerprint", "Banniere Server exposee", response.url, server, "Reduire les bannieres serveur en production.")
        if powered_by:
            self.findings.append(
                Finding(
                    severity="low",
                    category="fingerprint",
                    title="Technologie exposee via X-Powered-By",
                    url=response.url,
                    evidence=powered_by,
                    recommendation="Supprimer ou neutraliser l'en-tete X-Powered-By.",
                )
            )

    def _check_forms(self, response: HttpResponse, parser: LinkAndFormParser) -> None:
        page_scheme = urllib.parse.urlsplit(response.url).scheme
        for form in parser.forms:
            inputs = form.get("inputs", [])
            assert isinstance(inputs, list)
            input_names = {str(item.get("name", "")).lower() for item in inputs if isinstance(item, dict)}
            input_types = {str(item.get("type", "")).lower() for item in inputs if isinstance(item, dict)}
            action = urllib.parse.urljoin(response.url, str(form.get("action") or ""))
            method = str(form.get("method") or "get").lower()
            if "password" in input_types and page_scheme != "https":
                self.findings.append(
                    Finding(
                        severity="high",
                        category="forms",
                        title="Formulaire de mot de passe servi sans HTTPS",
                        url=response.url,
                        evidence=f"Form action={action}",
                        recommendation="Servir les pages d'authentification exclusivement en HTTPS.",
                    )
                )
            if method == "post" and not any(token in name for name in input_names for token in ("csrf", "token", "nonce")):
                self.findings.append(
                    Finding(
                        severity="medium",
                        category="forms",
                        title="Formulaire POST sans jeton CSRF visible",
                        url=response.url,
                        evidence=f"Form action={action}",
                        recommendation="Ajouter un jeton CSRF unique et verifie cote serveur.",
                    )
                )

    def _check_mixed_content(self, response: HttpResponse, parser: LinkAndFormParser) -> None:
        if urllib.parse.urlsplit(response.url).scheme != "https":
            return
        insecure_assets = [asset for asset in parser.assets if urllib.parse.urlsplit(urllib.parse.urljoin(response.url, asset)).scheme == "http"]
        if insecure_assets:
            self.findings.append(
                Finding(
                    severity="medium",
                    category="transport",
                    title="Contenu mixte detecte",
                    url=response.url,
                    evidence=", ".join(insecure_assets[:5]),
                    recommendation="Charger toutes les ressources via HTTPS.",
                )
            )

    def _check_generator(self, response: HttpResponse, parser: LinkAndFormParser) -> None:
        if parser.meta_generator:
            self._add_info(
                "fingerprint",
                "Meta generator expose",
                response.url,
                parser.meta_generator,
                "Masquer les versions detaillees lorsque cela n'apporte rien aux utilisateurs.",
            )

    def _check_exposure_paths(self) -> None:
        for path in EXPOSURE_PATHS:
            url = urllib.parse.urlunsplit((self._base.scheme, self._base.netloc, path, "", ""))
            response = self._request(url)
            if response is None or response.status in {401, 403, 404, 405}:
                continue
            if response.status < 400:
                severity = "high" if path in {"/.git/HEAD", "/.env"} else "info"
                self.findings.append(
                    Finding(
                        severity=severity,
                        category="exposure",
                        title=f"Chemin sensible accessible: {path}",
                        url=response.url,
                        evidence=f"HTTP {response.status}, {len(response.body)} octets.",
                        recommendation="Verifier que ce fichier est volontairement public ou le bloquer au niveau serveur.",
                    )
                )

    def _check_cors(self) -> None:
        response = self._request(self.target, headers={"Origin": self.origin_probe})
        if response is None:
            return
        allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "")
        if allow_origin == "*" and allow_credentials.lower() == "true":
            self.findings.append(
                Finding(
                    severity="high",
                    category="cors",
                    title="CORS invalide: wildcard avec credentials",
                    url=response.url,
                    evidence="Access-Control-Allow-Origin=* et Access-Control-Allow-Credentials=true.",
                    recommendation="Restreindre Access-Control-Allow-Origin a une liste stricte et eviter credentials si inutile.",
                )
            )
        elif allow_origin == "*" or allow_origin == self.origin_probe:
            self.findings.append(
                Finding(
                    severity="medium",
                    category="cors",
                    title="CORS trop permissif",
                    url=response.url,
                    evidence=f"Access-Control-Allow-Origin={allow_origin}",
                    recommendation="Autoriser uniquement les origins necessaires.",
                )
            )

    def _check_http_methods(self) -> None:
        request = urllib.request.Request(self.target, headers=DEFAULT_HEADERS, method="OPTIONS")
        response = self._open(request)
        if response is None:
            return
        allow = response.headers.get("Allow", "") or response.headers.get("Access-Control-Allow-Methods", "")
        risky = sorted({method for method in ("PUT", "DELETE", "TRACE", "CONNECT") if method in allow.upper()})
        if risky:
            self.findings.append(
                Finding(
                    severity="medium",
                    category="methods",
                    title="Methodes HTTP sensibles annoncees",
                    url=response.url,
                    evidence=f"Allow={allow}",
                    recommendation="Desactiver les methodes non necessaires et verifier l'autorisation cote serveur.",
                )
            )

    def _check_tls_certificate(self) -> None:
        if self._base.scheme != "https":
            self.findings.append(
                Finding(
                    severity="medium",
                    category="transport",
                    title="Cible servie sans HTTPS",
                    url=self.target,
                    evidence=f"Schema detecte: {self._base.scheme}",
                    recommendation="Forcer HTTPS et rediriger HTTP vers HTTPS.",
                )
            )
            return
        try:
            context = ssl.create_default_context()
            port = self._base.port or 443
            with socket.create_connection((self._base.hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self._base.hostname) as wrapped:
                    cert = wrapped.getpeercert()
        except Exception as exc:
            self.findings.append(
                Finding(
                    severity="medium",
                    category="transport",
                    title="Certificat TLS non verifiable",
                    url=self.target,
                    evidence=str(exc),
                    recommendation="Verifier la chaine TLS, le nom du certificat et la date d'expiration.",
                )
            )
            return
        expires_raw = cert.get("notAfter")
        if not expires_raw:
            return
        expires = datetime.strptime(expires_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 30:
            self.findings.append(
                Finding(
                    severity="medium" if days_left >= 0 else "high",
                    category="transport",
                    title="Certificat TLS proche de l'expiration",
                    url=self.target,
                    evidence=f"Expiration dans {days_left} jours ({expires.isoformat()}).",
                    recommendation="Renouveler le certificat TLS avant expiration.",
                )
            )

    def _request(self, url: str, headers: Optional[dict[str, str]] = None) -> Optional[HttpResponse]:
        request_headers = dict(DEFAULT_HEADERS)
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(url, headers=request_headers, method="GET")
        return self._open(request)

    def _open(self, request: urllib.request.Request) -> Optional[HttpResponse]:
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request_at = time.monotonic()
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read(1024 * 1024)
                result = HttpResponse(response.geturl(), response.status, response.reason, response.headers, body)
        except urllib.error.HTTPError as exc:
            body = exc.read(1024 * 1024)
            result = HttpResponse(exc.geturl(), exc.code, exc.reason, exc.headers, body)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.findings.append(
                Finding(
                    severity="low",
                    category="availability",
                    title="Requete echouee",
                    url=request.full_url,
                    evidence=str(exc),
                    recommendation="Verifier la connectivite, le pare-feu ou reduire la cadence.",
                )
            )
            return None
        self.responses.append(result)
        return result

    def _same_origin(self, url: str) -> bool:
        parsed = urllib.parse.urlsplit(url)
        return parsed.scheme in {"http", "https"} and parsed.scheme == self._base.scheme and parsed.netloc == self._base.netloc

    def _summary(self) -> dict[str, int]:
        summary = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            summary[finding.severity] += 1
        return summary

    def _add_info(self, category: str, title: str, url: str, evidence: str, recommendation: str) -> None:
        self.findings.append(Finding("info", category, title, url, evidence, recommendation))


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def parse_html(text: str) -> LinkAndFormParser:
    parser = LinkAndFormParser()
    parser.feed(text)
    return parser


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("La cible ne peut pas etre vide.")
    if "://" not in value:
        value = "https://" + value
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL cible invalide. Exemple attendu: https://example.com")
    path = parsed.path or "/"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))


def strip_fragment(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def finding_sort_key(finding: Finding) -> tuple[int, str, str]:
    return (SEVERITY_ORDER.get(finding.severity, 0), finding.category, finding.title)


def render_text(report: dict[str, object]) -> str:
    findings = report["findings"]
    assert isinstance(findings, list)
    lines = [
        "WebSentinel - rapport bug bounty non destructif",
        f"Cible: {report['target']}",
        f"Pages scannees: {report['pages_scanned']} | Requetes: {report['requests_sent']}",
        f"Resume: {json.dumps(report['summary'], ensure_ascii=False, sort_keys=True)}",
        "",
    ]
    if not findings:
        lines.append("Aucun finding detecte.")
        return "\n".join(lines)
    for index, finding in enumerate(findings, 1):
        item = dict(finding)
        lines.extend(
            [
                f"{index}. [{item['severity'].upper()}] {item['title']}",
                f"   Categorie: {item['category']}",
                f"   URL: {item['url']}",
                f"   Preuve: {item['evidence']}",
                f"   Recommandation: {item['recommendation']}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scanner bug bounty web non destructif avec crawling limite au meme origin.",
    )
    parser.add_argument("target", help="URL cible autorisee, ex: https://example.com")
    parser.add_argument("--i-am-authorized", action="store_true", help="Confirme que vous avez l'autorisation de tester la cible.")
    parser.add_argument("--max-pages", type=int, default=20, help="Nombre maximum de pages a crawler (defaut: 20).")
    parser.add_argument("--max-depth", type=int, default=2, help="Profondeur maximum du crawl (defaut: 2).")
    parser.add_argument("--timeout", type=float, default=8.0, help="Timeout par requete en secondes.")
    parser.add_argument("--rate-limit", type=float, default=0.4, help="Pause minimum entre requetes en secondes.")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Format de sortie.")
    parser.add_argument("--output", help="Chemin du fichier de rapport.")
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.i_am_authorized:
        parser.error("--i-am-authorized est obligatoire pour confirmer le perimetre legal.")
    try:
        scanner = WebSentinelScanner(
            args.target,
            timeout=args.timeout,
            rate_limit=max(0.0, args.rate_limit),
            max_pages=max(1, args.max_pages),
            max_depth=max(0, args.max_depth),
        )
        report = scanner.run()
    except ValueError as exc:
        parser.error(str(exc))
    output = json.dumps(report, indent=2, ensure_ascii=False) if args.format == "json" else render_text(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
