#!/usr/bin/env python3
"""Scanner CLI de reconnaissance web pour bug bounty.

Ce module privilégie des vérifications sûres :
- crawl limité au même hôte,
- collecte des liens, formulaires, scripts et paramètres,
- vérification des en-têtes/cookies,
- détection heuristique de signaux fréquents (CSRF absent, endpoints sensibles).
"""

from __future__ import annotations

import argparse
import json
import ssl
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urljoin, urlparse
from urllib.request import Request, urlopen

USER_AGENT = "SafeBountyScanner/1.0 (+local security assessment)"
DEFAULT_WORDLIST = [
    "/robots.txt",
    "/sitemap.xml",
    "/admin",
    "/login",
    "/logout",
    "/register",
    "/api",
    "/api/docs",
    "/swagger",
    "/graphql",
    "/debug",
    "/.env",
    "/.git/HEAD",
    "/backup.zip",
    "/server-status",
]
SECURITY_HEADERS = {
    "content-security-policy": "Définir une CSP restrictive pour limiter XSS et chargements non désirés.",
    "strict-transport-security": "Activer HSTS sur HTTPS pour forcer les connexions sécurisées.",
    "x-frame-options": "Définir DENY ou SAMEORIGIN pour limiter le clickjacking.",
    "x-content-type-options": "Définir nosniff pour éviter l'interprétation MIME.",
    "referrer-policy": "Limiter les fuites de referrer avec strict-origin-when-cross-origin ou plus strict.",
    "permissions-policy": "Restreindre explicitement l'accès aux APIs navigateur sensibles.",
}
SENSITIVE_PATH_KEYWORDS = {
    "/.git/": "Exposition potentielle de dépôt Git.",
    ".env": "Fichier d'environnement potentiellement exposé.",
    "backup": "Artefact de sauvegarde potentiellement téléchargeable.",
    "swagger": "Documentation API intéressante pour l'énumération.",
    "graphql": "Endpoint GraphQL détecté.",
    "debug": "Endpoint de debug accessible.",
    "server-status": "Page de statut serveur accessible.",
}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    url: str
    evidence: str
    recommendation: str


@dataclass
class FormRecord:
    action: str
    method: str
    inputs: list[str] = field(default_factory=list)
    hidden_inputs: list[str] = field(default_factory=list)


@dataclass
class PageRecord:
    url: str
    status: int
    content_type: str
    title: str = ""
    query_params: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[FormRecord] = field(default_factory=list)


class ReconHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.forms: list[FormRecord] = []
        self._current_form: FormRecord | None = None
        self._in_title = False
        self.title = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {key.lower(): value or "" for key, value in attrs}
        if tag == "a" and attrs_map.get("href"):
            self.links.add(attrs_map["href"])
        elif tag == "script" and attrs_map.get("src"):
            self.scripts.add(attrs_map["src"])
        elif tag == "form":
            self._current_form = FormRecord(
                action=attrs_map.get("action", ""),
                method=(attrs_map.get("method", "get") or "get").lower(),
            )
        elif tag == "input" and self._current_form is not None:
            input_name = attrs_map.get("name", "").strip()
            input_type = (attrs_map.get("type", "text") or "text").lower()
            if input_name:
                self._current_form.inputs.append(input_name)
                if input_type == "hidden":
                    self._current_form.hidden_inputs.append(input_name)
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


def _normalize_url(base_url: str, candidate: str) -> str | None:
    if not candidate or candidate.startswith(("javascript:", "mailto:", "tel:", "#")):
        return None
    normalized = urljoin(base_url, candidate)
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"}:
        return None
    clean_path = parsed.path or "/"
    clean_url = parsed._replace(fragment="", path=clean_path).geturl()
    return clean_url


def _same_host(base_url: str, candidate: str) -> bool:
    return urlparse(base_url).netloc == urlparse(candidate).netloc


def _extract_query_params(url: str) -> list[str]:
    return sorted(parse_qs(urlparse(url).query).keys())


def _load_wordlist(path: str | None) -> list[str]:
    if not path:
        return DEFAULT_WORDLIST
    lines = []
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line if line.startswith("/") else f"/{line}")
    return lines or DEFAULT_WORDLIST


def _request(url: str, timeout: int, method: str = "GET") -> dict:
    request = Request(url, headers={"User-Agent": USER_AGENT}, method=method)
    context = ssl.create_default_context()
    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            body_bytes = response.read()
            headers = {key.lower(): value for key, value in response.headers.items()}
            return {
                "url": response.geturl(),
                "status": response.status,
                "headers": headers,
                "body": body_bytes,
            }
    except HTTPError as exc:
        body = exc.read() if exc.fp else b""
        return {
            "url": exc.geturl(),
            "status": exc.code,
            "headers": {key.lower(): value for key, value in exc.headers.items()},
            "body": body,
        }
    except URLError as exc:
        return {
            "url": url,
            "status": 0,
            "headers": {},
            "body": str(exc).encode("utf-8", errors="ignore"),
            "error": str(exc),
        }


def _decode_body(raw: bytes, headers: dict[str, str]) -> str:
    charset = "utf-8"
    content_type = headers.get("content-type", "")
    if "charset=" in content_type:
        charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip()
    return raw.decode(charset, errors="replace")


def _parse_set_cookie(header_value: str) -> list[dict[str, str]]:
    cookies: list[dict[str, str]] = []
    simple_cookie = SimpleCookie()
    simple_cookie.load(header_value)
    for morsel in simple_cookie.values():
        cookies.append(
            {
                "name": morsel.key,
                "secure": "secure" if morsel["secure"] else "",
                "httponly": "httponly" if morsel["httponly"] else "",
                "samesite": morsel["samesite"],
            }
        )
    return cookies


def _analyze_headers(url: str, headers: dict[str, str], findings: list[Finding]) -> None:
    for header, recommendation in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(
                Finding(
                    severity="medium",
                    category="headers",
                    title=f"En-tête de sécurité manquant : {header}",
                    url=url,
                    evidence=f"L'en-tête HTTP `{header}` est absent.",
                    recommendation=recommendation,
                )
            )

    set_cookie = headers.get("set-cookie")
    if not set_cookie:
        return

    for cookie in _parse_set_cookie(set_cookie):
        missing_flags = []
        if not cookie["secure"]:
            missing_flags.append("Secure")
        if not cookie["httponly"]:
            missing_flags.append("HttpOnly")
        if not cookie["samesite"]:
            missing_flags.append("SameSite")
        if missing_flags:
            findings.append(
                Finding(
                    severity="medium",
                    category="cookies",
                    title=f"Cookie `{cookie['name']}` sans protections complètes",
                    url=url,
                    evidence=f"Flags manquants : {', '.join(missing_flags)}.",
                    recommendation="Ajouter Secure, HttpOnly et SameSite sur les cookies sensibles.",
                )
            )


def _analyze_page(page: PageRecord, findings: list[Finding]) -> None:
    for query_param in page.query_params:
        lowered = query_param.lower()
        if lowered in {"next", "url", "redirect", "return", "returnto"}:
            findings.append(
                Finding(
                    severity="medium",
                    category="parameters",
                    title=f"Paramètre de redirection intéressant : {query_param}",
                    url=page.url,
                    evidence=f"Le paramètre `{query_param}` apparaît dans l'URL.",
                    recommendation="Vérifier les protections contre l'open redirect et la validation côté serveur.",
                )
            )
        elif lowered in {"file", "path", "template", "view"}:
            findings.append(
                Finding(
                    severity="medium",
                    category="parameters",
                    title=f"Paramètre de fichier/chemin intéressant : {query_param}",
                    url=page.url,
                    evidence=f"Le paramètre `{query_param}` apparaît dans l'URL.",
                    recommendation="Tester les validations de chemin et l'isolation des fichiers côté serveur.",
                )
            )

    for form in page.forms:
        hidden_lower = {value.lower() for value in form.hidden_inputs}
        if form.method == "post" and not any(
            token in name for name in hidden_lower for token in ("csrf", "token", "authenticity", "nonce")
        ):
            findings.append(
                Finding(
                    severity="high",
                    category="forms",
                    title="Formulaire POST sans jeton CSRF détecté",
                    url=page.url,
                    evidence=f"Action `{form.action or page.url}` avec champs cachés {form.hidden_inputs or 'aucun'}.",
                    recommendation="Ajouter un jeton CSRF robuste et une validation côté serveur.",
                )
            )


def _probe_common_paths(base_url: str, timeout: int, paths: Iterable[str], delay: float) -> list[dict]:
    results = []
    origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    interesting_statuses = {401, 403, 405}
    for path in paths:
        candidate = urljoin(origin, path)
        response = _request(candidate, timeout=timeout, method="GET")
        if (200 <= response["status"] < 400) or response["status"] in interesting_statuses:
            results.append({"url": candidate, "status": response["status"]})
        time.sleep(delay)
    return results


def scan_target(
    base_url: str,
    *,
    max_depth: int = 2,
    max_pages: int = 20,
    timeout: int = 10,
    delay: float = 0.0,
    wordlist_path: str | None = None,
    enable_probing: bool = True,
) -> dict:
    normalized_base = _normalize_url(base_url, base_url)
    if not normalized_base:
        raise ValueError("URL de base invalide.")

    queue: deque[tuple[str, int]] = deque([(normalized_base, 0)])
    visited: set[str] = set()
    pages: list[PageRecord] = []
    findings: list[Finding] = []

    while queue and len(visited) < max_pages:
        current_url, depth = queue.popleft()
        if current_url in visited or depth > max_depth:
            continue
        visited.add(current_url)

        response = _request(current_url, timeout=timeout)
        headers = response["headers"]
        content_type = headers.get("content-type", "")
        page = PageRecord(
            url=response["url"],
            status=response["status"],
            content_type=content_type,
            query_params=_extract_query_params(response["url"]),
        )
        _analyze_headers(response["url"], headers, findings)

        if response["status"] == 0:
            findings.append(
                Finding(
                    severity="low",
                    category="availability",
                    title="URL non joignable",
                    url=current_url,
                    evidence=response.get("error", "Erreur réseau inconnue."),
                    recommendation="Vérifier la connectivité, le DNS et la disponibilité de l'application.",
                )
            )
            pages.append(page)
            continue

        if "text/html" in content_type or "application/xhtml+xml" in content_type:
            parser = ReconHTMLParser()
            decoded = _decode_body(response["body"], headers)
            parser.feed(decoded)
            page.title = parser.title
            page.links = sorted(
                link
                for raw_link in parser.links
                if (link := _normalize_url(response["url"], raw_link)) and _same_host(normalized_base, link)
            )
            page.scripts = sorted(
                script
                for raw_script in parser.scripts
                if (script := _normalize_url(response["url"], raw_script))
            )
            page.forms = parser.forms

            for discovered_url in page.links:
                if discovered_url not in visited and depth + 1 <= max_depth:
                    queue.append((discovered_url, depth + 1))

        pages.append(page)
        _analyze_page(page, findings)
        time.sleep(delay)

    interesting_endpoints = []
    if enable_probing:
        wordlist = _load_wordlist(wordlist_path)
        interesting_endpoints = _probe_common_paths(normalized_base, timeout, wordlist, delay)
        for endpoint in interesting_endpoints:
            matched_reason = next(
                (reason for keyword, reason in SENSITIVE_PATH_KEYWORDS.items() if keyword in endpoint["url"]),
                "",
            )
            if matched_reason:
                findings.append(
                    Finding(
                        severity="high" if "/.git/" in endpoint["url"] or ".env" in endpoint["url"] else "medium",
                        category="surface",
                        title=f"Endpoint intéressant détecté : {endpoint['url']}",
                        url=endpoint["url"],
                        evidence=f"Le chemin a répondu avec le statut HTTP {endpoint['status']}.",
                        recommendation=matched_reason,
                    )
                )

    report = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "target": normalized_base,
        "summary": {
            "pages_visited": len(pages),
            "forms_found": sum(len(page.forms) for page in pages),
            "scripts_found": sum(len(page.scripts) for page in pages),
            "findings_count": len(findings),
            "interesting_endpoints": len(interesting_endpoints),
        },
        "pages": [
            {
                **asdict(page),
                "forms": [asdict(form) for form in page.forms],
            }
            for page in pages
        ],
        "interesting_endpoints": interesting_endpoints,
        "findings": [asdict(finding) for finding in findings],
    }
    return report


def write_json_report(report: dict, output_path: str) -> None:
    Path(output_path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def write_markdown_report(report: dict, output_path: str) -> None:
    lines = [
        f"# Rapport SafeBountyScanner",
        "",
        f"- Cible : `{report['target']}`",
        f"- Horodatage : `{report['scanned_at']}`",
        f"- Pages visitées : `{report['summary']['pages_visited']}`",
        f"- Formulaires trouvés : `{report['summary']['forms_found']}`",
        f"- Scripts trouvés : `{report['summary']['scripts_found']}`",
        f"- Findings : `{report['summary']['findings_count']}`",
        "",
        "## Findings",
        "",
    ]

    if not report["findings"]:
        lines.append("- Aucun finding heuristique détecté.")
    else:
        for finding in report["findings"]:
            lines.extend(
                [
                    f"### [{finding['severity'].upper()}] {finding['title']}",
                    f"- URL : `{finding['url']}`",
                    f"- Catégorie : `{finding['category']}`",
                    f"- Preuve : {finding['evidence']}",
                    f"- Recommandation : {finding['recommendation']}",
                    "",
                ]
            )

    lines.extend(["## Endpoints intéressants", ""])
    if not report["interesting_endpoints"]:
        lines.append("- Aucun endpoint intéressant dans la wordlist.")
    else:
        for endpoint in report["interesting_endpoints"]:
            lines.append(f"- `{endpoint['url']}` -> HTTP {endpoint['status']}")

    Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scanner web safe-by-design pour bug bounty.")
    parser.add_argument("url", help="URL de base à scanner, ex: https://example.com")
    parser.add_argument("--depth", type=int, default=2, help="Profondeur maximale de crawl (défaut: 2)")
    parser.add_argument("--max-pages", type=int, default=20, help="Nombre maximal de pages à visiter")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout HTTP par requête en secondes")
    parser.add_argument("--delay", type=float, default=0.0, help="Délai entre requêtes en secondes")
    parser.add_argument("--wordlist", help="Fichier de wordlist pour les endpoints à sonder")
    parser.add_argument("--json", dest="json_output", help="Chemin du rapport JSON à écrire")
    parser.add_argument("--markdown", dest="markdown_output", help="Chemin du rapport Markdown à écrire")
    parser.add_argument("--no-probe", action="store_true", help="Désactive le sondage des endpoints communs")
    return parser


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()

    report = scan_target(
        args.url,
        max_depth=args.depth,
        max_pages=args.max_pages,
        timeout=args.timeout,
        delay=args.delay,
        wordlist_path=args.wordlist,
        enable_probing=not args.no_probe,
    )

    if args.json_output:
        write_json_report(report, args.json_output)
    if args.markdown_output:
        write_markdown_report(report, args.markdown_output)

    print(
        json.dumps(
            {
                "target": report["target"],
                "summary": report["summary"],
                "top_findings": report["findings"][:5],
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
