#!/usr/bin/env python3
"""
Assistant de reconnaissance bug bounty pour applications web.

L'outil reste volontairement non destructif: il ne brute-force pas, n'exploite
pas les failles et limite le crawl au scope autorise.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import html
import json
import re
import ssl
import sys
import time
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from http import HTTPStatus
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib import error, parse, request


DEFAULT_USER_AGENT = "NigerCertify-BugBountyScanner/1.0 (+authorized-security-testing)"
SECURITY_HEADER_CHECKS = {
    "content-security-policy": ("medium", "Definit une politique CSP contre XSS et injection de contenu."),
    "x-content-type-options": ("low", "Reduit le risque de MIME sniffing."),
    "referrer-policy": ("low", "Controle la fuite de donnees via l'en-tete Referer."),
    "permissions-policy": ("low", "Restreint l'acces navigateur aux API sensibles."),
}
SENSITIVE_PROBES = (
    "/.env",
    "/.git/HEAD",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/phpinfo.php",
    "/server-status",
)
PUBLIC_PROBES = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
)
CSRF_HINTS = ("csrf", "token", "nonce", "authenticity")


@dataclasses.dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    url: str
    evidence: str
    recommendation: str

    def key(self) -> Tuple[str, str, str, str]:
        return (self.severity, self.title, self.url, self.evidence)


@dataclasses.dataclass
class PageResult:
    url: str
    status: Optional[int]
    content_type: str
    title: str
    links: List[str]
    forms: List[Dict[str, object]]
    response_headers: Dict[str, str]
    error: Optional[str] = None


class PageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: List[str] = []
        self.resources: List[str] = []
        self.forms: List[Dict[str, object]] = []
        self._current_form: Optional[Dict[str, object]] = None
        self._in_title = False
        self._title_parts: List[str] = []

    @property
    def title(self) -> str:
        return " ".join("".join(self._title_parts).split())

    def handle_starttag(self, tag: str, attrs: Sequence[Tuple[str, Optional[str]]]) -> None:
        attr_map = {name.lower(): value or "" for name, value in attrs}
        if tag == "title":
            self._in_title = True
        if tag == "a" and attr_map.get("href"):
            self.links.append(parse.urljoin(self.base_url, attr_map["href"]))
        if tag in {"script", "img", "iframe", "link"}:
            ref = attr_map.get("src") or attr_map.get("href")
            if ref:
                self.resources.append(parse.urljoin(self.base_url, ref))
        if tag == "form":
            self._current_form = {
                "method": attr_map.get("method", "get").lower(),
                "action": parse.urljoin(self.base_url, attr_map.get("action", self.base_url)),
                "inputs": [],
            }
        if tag in {"input", "textarea", "select"} and self._current_form is not None:
            inputs = self._current_form["inputs"]
            assert isinstance(inputs, list)
            inputs.append(
                {
                    "tag": tag,
                    "type": attr_map.get("type", "text").lower(),
                    "name": attr_map.get("name", ""),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)


class WebBugBountyScanner:
    def __init__(
        self,
        target: str,
        scope_domains: Sequence[str],
        max_pages: int,
        timeout: float,
        delay: float,
        user_agent: str,
        active_probes: bool,
    ) -> None:
        self.target = normalize_url(target)
        self.max_pages = max_pages
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent
        self.active_probes = active_probes
        target_host = parse.urlparse(self.target).hostname or ""
        self.scope_domains = {target_host, *[domain.lower() for domain in scope_domains]}
        self.pages: List[PageResult] = []
        self.findings: List[Finding] = []
        self._seen_findings: Set[Tuple[str, str, str, str]] = set()

    def scan(self) -> Dict[str, object]:
        started = datetime.now(timezone.utc)
        self._crawl()
        self._run_public_probes()
        if self.active_probes:
            self._run_sensitive_exposure_probes()
            self._run_reflection_probes()
        finished = datetime.now(timezone.utc)
        return {
            "tool": "web_bugbounty_scanner",
            "target": self.target,
            "scope_domains": sorted(self.scope_domains),
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "active_probes": self.active_probes,
            "summary": self._summary(),
            "pages": [dataclasses.asdict(page) for page in self.pages],
            "findings": [dataclasses.asdict(finding) for finding in self._sorted_findings()],
        }

    def _crawl(self) -> None:
        queue: deque[str] = deque([self.target])
        visited: Set[str] = set()
        while queue and len(visited) < self.max_pages:
            url = canonicalize_url(queue.popleft())
            if url in visited or not self._in_scope(url):
                continue
            visited.add(url)
            page = self._fetch_page(url)
            self.pages.append(page)
            if page.error:
                self._add_finding(
                    "info",
                    "Page inaccessible pendant le scan",
                    url,
                    page.error,
                    "Verifier manuellement si cette erreur est attendue ou liee a un filtrage.",
                )
                continue
            self._analyze_response(page)
            for link in page.links:
                clean_link = canonicalize_url(link)
                if self._in_scope(clean_link) and clean_link not in visited:
                    queue.append(clean_link)
            if self.delay:
                time.sleep(self.delay)

    def _fetch_page(self, url: str) -> PageResult:
        try:
            response = self._request(url)
            body = response.read(512_000)
            headers = normalize_headers(response.headers.items())
            content_type = headers.get("content-type", "")
            text = decode_body(body, content_type)
            parser = PageParser(response.geturl())
            if "html" in content_type.lower() or looks_like_html(text):
                parser.feed(text)
            return PageResult(
                url=response.geturl(),
                status=response.status,
                content_type=content_type,
                title=parser.title,
                links=dedupe(parser.links + parser.resources),
                forms=parser.forms,
                response_headers=headers,
            )
        except Exception as exc:  # urllib expose plusieurs sous-types selon l'erreur reseau.
            return PageResult(
                url=url,
                status=None,
                content_type="",
                title="",
                links=[],
                forms=[],
                response_headers={},
                error=str(exc),
            )

    def _request(self, url: str) -> request.addinfourl:
        req = request.Request(url, headers={"User-Agent": self.user_agent})
        return request.urlopen(req, timeout=self.timeout, context=ssl.create_default_context())

    def _analyze_response(self, page: PageResult) -> None:
        parsed = parse.urlparse(page.url)
        if parsed.scheme != "https":
            self._add_finding(
                "medium",
                "HTTP sans TLS",
                page.url,
                "La page est servie en HTTP.",
                "Forcer HTTPS avec redirection permanente et HSTS.",
            )
        self._check_security_headers(page)
        self._check_information_disclosure(page)
        self._check_cookies(page)
        self._check_forms(page)
        self._check_mixed_content(page)

    def _check_security_headers(self, page: PageResult) -> None:
        headers = page.response_headers
        for header, (severity, reason) in SECURITY_HEADER_CHECKS.items():
            if header not in headers:
                self._add_finding(
                    severity,
                    f"En-tete de securite manquant: {header}",
                    page.url,
                    reason,
                    f"Configurer l'en-tete HTTP `{header}` avec une politique adaptee.",
                )
        if parse.urlparse(page.url).scheme == "https" and "strict-transport-security" not in headers:
            self._add_finding(
                "medium",
                "HSTS manquant",
                page.url,
                "La reponse HTTPS ne declare pas Strict-Transport-Security.",
                "Ajouter HSTS apres validation du support HTTPS sur tous les sous-domaines concernes.",
            )
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            self._add_finding(
                "medium",
                "Protection anti-clickjacking absente",
                page.url,
                "Aucun X-Frame-Options ni CSP frame-ancestors detecte.",
                "Definir `frame-ancestors` dans CSP ou ajouter X-Frame-Options.",
            )

    def _check_information_disclosure(self, page: PageResult) -> None:
        for header in ("server", "x-powered-by"):
            value = page.response_headers.get(header)
            if value:
                self._add_finding(
                    "info",
                    f"Banniere technique exposee: {header}",
                    page.url,
                    f"{header}: {value}",
                    "Reduire les bannieres de version lorsque c'est possible.",
                )

    def _check_cookies(self, page: PageResult) -> None:
        cookie_headers = get_header_values(page.response_headers, "set-cookie")
        for cookie in cookie_headers:
            cookie_name = cookie.split("=", 1)[0].strip()
            lower_cookie = cookie.lower()
            if "httponly" not in lower_cookie:
                self._add_finding(
                    "medium",
                    "Cookie sans HttpOnly",
                    page.url,
                    cookie_name,
                    "Ajouter HttpOnly aux cookies de session non lus par JavaScript.",
                )
            if parse.urlparse(page.url).scheme == "https" and "secure" not in lower_cookie:
                self._add_finding(
                    "medium",
                    "Cookie HTTPS sans Secure",
                    page.url,
                    cookie_name,
                    "Ajouter Secure pour eviter l'envoi du cookie en clair.",
                )
            if "samesite" not in lower_cookie:
                self._add_finding(
                    "low",
                    "Cookie sans SameSite",
                    page.url,
                    cookie_name,
                    "Declarer SameSite=Lax ou Strict selon le besoin fonctionnel.",
                )

    def _check_forms(self, page: PageResult) -> None:
        for form in page.forms:
            inputs = form.get("inputs", [])
            action = str(form.get("action", page.url))
            method = str(form.get("method", "get")).upper()
            input_names = [
                str(item.get("name", "")).lower()
                for item in inputs
                if isinstance(item, dict)
            ]
            input_types = [
                str(item.get("type", "")).lower()
                for item in inputs
                if isinstance(item, dict)
            ]
            if "password" in input_types and parse.urlparse(action).scheme != "https":
                self._add_finding(
                    "high",
                    "Formulaire mot de passe sans HTTPS",
                    action,
                    f"Methode {method}",
                    "Servir les formulaires d'authentification exclusivement en HTTPS.",
                )
            if method == "POST" and not any(any(hint in name for hint in CSRF_HINTS) for name in input_names):
                self._add_finding(
                    "medium",
                    "Formulaire POST sans jeton CSRF visible",
                    action,
                    f"Champs: {', '.join(filter(None, input_names)) or 'aucun champ nomme'}",
                    "Verifier la presence d'une protection CSRF cote serveur et exposer un jeton anti-CSRF si necessaire.",
                )

    def _check_mixed_content(self, page: PageResult) -> None:
        if parse.urlparse(page.url).scheme != "https":
            return
        insecure_resources = [link for link in page.links if parse.urlparse(link).scheme == "http"]
        for resource in insecure_resources[:10]:
            self._add_finding(
                "medium",
                "Ressource HTTP chargee depuis une page HTTPS",
                page.url,
                resource,
                "Charger les ressources externes en HTTPS ou les heberger localement.",
            )

    def _run_public_probes(self) -> None:
        base = origin(self.target)
        for path in PUBLIC_PROBES:
            url = parse.urljoin(base, path)
            if not self._in_scope(url):
                continue
            status, headers, body = self._probe(url)
            if status is None:
                continue
            if path.endswith("security.txt") and status == HTTPStatus.OK:
                self._add_finding(
                    "info",
                    "security.txt publie",
                    url,
                    snippet(body),
                    "Conserver un canal de divulgation responsable clair et a jour.",
                )
            elif path.endswith("robots.txt") and status == HTTPStatus.OK:
                interesting = find_interesting_robots_entries(body)
                if interesting:
                    self._add_finding(
                        "info",
                        "robots.txt contient des chemins sensibles potentiels",
                        url,
                        ", ".join(interesting[:10]),
                        "Verifier que robots.txt ne revele pas d'administration ou de sauvegardes sensibles.",
                    )
            elif path.endswith("sitemap.xml") and status == HTTPStatus.OK:
                self._add_finding(
                    "info",
                    "sitemap.xml detecte",
                    url,
                    headers.get("content-type", "type inconnu"),
                    "Utiliser le sitemap pour completer la cartographie du scope autorise.",
                )

    def _run_sensitive_exposure_probes(self) -> None:
        base = origin(self.target)
        for path in SENSITIVE_PROBES:
            url = parse.urljoin(base, path)
            if not self._in_scope(url):
                continue
            status, headers, body = self._probe(url)
            if status is None:
                continue
            if status in {HTTPStatus.OK, HTTPStatus.PARTIAL_CONTENT} and not is_soft_404(body):
                self._add_finding(
                    "high",
                    "Fichier ou endpoint sensible accessible",
                    url,
                    f"HTTP {status}; {snippet(body)}",
                    "Restreindre l'acces, supprimer le fichier expose et verifier les journaux d'acces.",
                )
            if self.delay:
                time.sleep(self.delay)

    def _run_reflection_probes(self) -> None:
        candidates = collect_urls_with_params([page.url for page in self.pages] + [link for page in self.pages for link in page.links])
        canary = "bbscan-" + hashlib.sha1(self.target.encode("utf-8")).hexdigest()[:10]
        for url in candidates[:20]:
            reflected_url = inject_canary(url, canary)
            if not self._in_scope(reflected_url):
                continue
            status, _, body = self._probe(reflected_url)
            if status == HTTPStatus.OK and canary in body:
                self._add_finding(
                    "medium",
                    "Parametre reflechi avec canari inerte",
                    reflected_url,
                    canary,
                    "Valider l'encodage de sortie et tester manuellement le contexte avant tout rapport XSS.",
                )
            if self.delay:
                time.sleep(self.delay)

    def _probe(self, url: str) -> Tuple[Optional[int], Dict[str, str], str]:
        try:
            response = self._request(url)
            body = response.read(128_000)
            headers = normalize_headers(response.headers.items())
            return response.status, headers, decode_body(body, headers.get("content-type", ""))
        except error.HTTPError as exc:
            body = exc.read(64_000)
            headers = normalize_headers(exc.headers.items())
            return exc.code, headers, decode_body(body, headers.get("content-type", ""))
        except Exception:
            return None, {}, ""

    def _in_scope(self, url: str) -> bool:
        parsed = parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        return parsed.scheme in {"http", "https"} and any(
            host == domain or host.endswith("." + domain) for domain in self.scope_domains
        )

    def _add_finding(self, severity: str, title: str, url: str, evidence: str, recommendation: str) -> None:
        finding = Finding(severity, title, url, evidence[:500], recommendation)
        if finding.key() not in self._seen_findings:
            self._seen_findings.add(finding.key())
            self.findings.append(finding)

    def _sorted_findings(self) -> List[Finding]:
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(self.findings, key=lambda item: (rank.get(item.severity, 9), item.title, item.url))

    def _summary(self) -> Dict[str, int]:
        summary = {"pages_scanned": len(self.pages), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            summary[finding.severity] = summary.get(finding.severity, 0) + 1
        return summary


def normalize_url(value: str) -> str:
    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = "https://" + value
    parsed = parse.urlparse(value)
    if not parsed.hostname:
        raise ValueError("URL cible invalide")
    return parsed.geturl()


def canonicalize_url(url: str) -> str:
    parsed = parse.urlparse(url)
    path = parsed.path or "/"
    return parse.urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", parsed.query, ""))


def origin(url: str) -> str:
    parsed = parse.urlparse(url)
    return parse.urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def normalize_headers(items: Iterable[Tuple[str, str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for name, value in items:
        key = name.lower()
        if key in headers:
            headers[key] = headers[key] + "\n" + value
        else:
            headers[key] = value
    return headers


def get_header_values(headers: Dict[str, str], name: str) -> List[str]:
    value = headers.get(name.lower(), "")
    return [part.strip() for part in value.split("\n") if part.strip()]


def decode_body(body: bytes, content_type: str) -> str:
    charset_match = re.search(r"charset=([\w.-]+)", content_type, flags=re.IGNORECASE)
    charset = charset_match.group(1) if charset_match else "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def looks_like_html(text: str) -> bool:
    prefix = text[:500].lower()
    return "<html" in prefix or "<!doctype html" in prefix


def dedupe(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for value in values:
        clean = value.strip()
        if clean and clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result


def snippet(text: str, limit: int = 160) -> str:
    clean = " ".join(html.unescape(text).split())
    return clean[:limit]


def find_interesting_robots_entries(body: str) -> List[str]:
    interesting_words = ("admin", "backup", "private", "debug", "dev", "staging", "secret")
    entries = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(("disallow:", "allow:")) and any(word in stripped.lower() for word in interesting_words):
            entries.append(stripped)
    return entries


def is_soft_404(body: str) -> bool:
    lower = body.lower()
    return any(marker in lower for marker in ("not found", "404", "does not exist", "introuvable"))


def collect_urls_with_params(urls: Iterable[str]) -> List[str]:
    return [url for url in dedupe(urls) if parse.urlparse(url).query]


def inject_canary(url: str, canary: str) -> str:
    parsed = parse.urlparse(url)
    params = parse.parse_qsl(parsed.query, keep_blank_values=True)
    injected = [(key, canary) for key, _ in params]
    return parse.urlunparse(parsed._replace(query=parse.urlencode(injected)))


def render_markdown(report: Dict[str, object]) -> str:
    lines = [
        "# Rapport Web Bug Bounty",
        "",
        f"- Cible: `{report['target']}`",
        f"- Pages scannees: `{report['summary']['pages_scanned']}`",
        f"- Sondes actives: `{report['active_probes']}`",
        "",
        "## Synthese",
        "",
    ]
    summary = report["summary"]
    assert isinstance(summary, dict)
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"- {severity}: `{summary.get(severity, 0)}`")
    lines.extend(["", "## Findings", ""])
    findings = report["findings"]
    assert isinstance(findings, list)
    if not findings:
        lines.append("Aucun finding detecte.")
    for finding in findings:
        assert isinstance(finding, dict)
        lines.extend(
            [
                f"### [{finding['severity']}] {finding['title']}",
                "",
                f"- URL: `{finding['url']}`",
                f"- Preuve: {finding['evidence']}",
                f"- Recommandation: {finding['recommendation']}",
                "",
            ]
        )
    return "\n".join(lines)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scanner bug bounty web non destructif pour reconnaissance et hygiene de securite."
    )
    parser.add_argument("target", help="URL cible autorisee, ex: https://example.com")
    parser.add_argument("--scope-domain", action="append", default=[], help="Domaine supplementaire autorise dans le scope.")
    parser.add_argument("--max-pages", type=int, default=25, help="Nombre maximum de pages a crawler.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Timeout HTTP en secondes.")
    parser.add_argument("--delay", type=float, default=0.2, help="Pause entre requetes pour rester courtois.")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent envoye aux cibles.")
    parser.add_argument("--active-probes", action="store_true", help="Active les sondes GET limitees et le canari de reflection.")
    parser.add_argument("--format", choices=("json", "markdown"), default="json", help="Format de sortie.")
    parser.add_argument("--output", help="Fichier de sortie. Par defaut, imprime sur stdout.")
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Confirme que vous etes autorise a tester cette cible.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if not args.i_have_authorization:
        print(
            "Refus: ajoutez --i-have-authorization uniquement pour un programme bug bounty ou un scope que vous controlez.",
            file=sys.stderr,
        )
        return 2
    if args.max_pages < 1:
        print("Refus: --max-pages doit etre superieur ou egal a 1.", file=sys.stderr)
        return 2
    scanner = WebBugBountyScanner(
        target=args.target,
        scope_domains=args.scope_domain,
        max_pages=args.max_pages,
        timeout=args.timeout,
        delay=max(args.delay, 0),
        user_agent=args.user_agent,
        active_probes=args.active_probes,
    )
    report = scanner.scan()
    output = json.dumps(report, indent=2, ensure_ascii=False) if args.format == "json" else render_markdown(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
            handle.write("\n")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
