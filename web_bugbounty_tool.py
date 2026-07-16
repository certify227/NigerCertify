#!/usr/bin/env python3
"""
Outil de bug bounty web (usage autorisé uniquement).
"""

from __future__ import annotations

import argparse
import json
import random
import re
import string
import sys
import threading
import time
from collections import Counter, deque
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

import ssl


DEFAULT_WORDLIST = (
    "/admin",
    "/login",
    "/dashboard",
    "/api",
    "/api/v1",
    "/.env",
    "/.git/config",
    "/robots.txt",
    "/sitemap.xml",
    "/backup.zip",
    "/debug",
    "/phpinfo.php",
)

SENSITIVE_PATHS = (
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/config.php.bak",
    "/database.sql",
    "/.DS_Store",
)

SECURITY_HEADERS = (
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "content-security-policy",
    "referrer-policy",
)

ERROR_DISCLOSURE_PATTERNS = (
    r"traceback \(most recent call last\)",
    r"sql syntax.*mysql",
    r"warning:.*\bon line\b",
    r"uncaught exception",
    r"stack trace",
    r"fatal error",
)

REDIRECT_PARAMS = {
    "next",
    "url",
    "target",
    "dest",
    "destination",
    "redirect",
    "return",
    "return_url",
    "continue",
    "callback",
}

XSS_PARAMS = {
    "q",
    "query",
    "search",
    "term",
    "keyword",
    "redirect",
    "next",
    "url",
    "id",
    "name",
    "message",
}


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        return None


class LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: Set[str] = set()

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_map = dict(attrs)
        if tag in {"a", "link"} and attrs_map.get("href"):
            self.links.add(attrs_map["href"])
        elif tag in {"script", "img", "iframe"} and attrs_map.get("src"):
            self.links.add(attrs_map["src"])
        elif tag == "form" and attrs_map.get("action"):
            self.links.add(attrs_map["action"])


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    url: str
    evidence: str
    recommendation: str


@dataclass
class ResponseData:
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: int


class BugBountyScanner:
    def __init__(
        self,
        base_url: str,
        max_depth: int,
        timeout: int,
        max_urls: int,
        user_agent: str,
        insecure: bool,
        extra_paths: Iterable[str],
    ) -> None:
        self.base_url = self._normalize_url(base_url)
        self.base_origin = self._origin(self.base_url)
        self.max_depth = max_depth
        self.timeout = timeout
        self.max_urls = max_urls
        self.user_agent = user_agent
        self.findings: Set[Finding] = set()
        self.responses: Dict[str, ResponseData] = {}
        self.visited: Set[str] = set()
        self.discovered: Set[str] = set()
        self.extra_paths = tuple(extra_paths)
        self.lock = threading.Lock()
        self.context = ssl.create_default_context()
        if insecure:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        self.opener = build_opener(NoRedirectHandler())

    @staticmethod
    def _normalize_url(url: str) -> str:
        parsed = urlparse(url.strip())
        if not parsed.scheme:
            url = f"https://{url}"
            parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        normalized = parsed._replace(netloc=netloc, path=path, fragment="")
        return urlunparse(normalized)

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _same_origin(self, url: str) -> bool:
        return self._origin(url) == self.base_origin

    def _request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[ResponseData]:
        req_headers = {"User-Agent": self.user_agent}
        if headers:
            req_headers.update(headers)
        req = Request(url=url, method=method, headers=req_headers)
        start = time.perf_counter()
        try:
            with self.opener.open(req, timeout=self.timeout, context=self.context) as response:
                body = response.read().decode("utf-8", errors="replace")
                headers_map = {k.lower(): v for k, v in response.headers.items()}
                elapsed = int((time.perf_counter() - start) * 1000)
                return ResponseData(
                    url=url,
                    status=response.status,
                    headers=headers_map,
                    body=body,
                    elapsed_ms=elapsed,
                )
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            headers_map = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            elapsed = int((time.perf_counter() - start) * 1000)
            return ResponseData(url=url, status=exc.code, headers=headers_map, body=body, elapsed_ms=elapsed)
        except (URLError, TimeoutError, ValueError):
            return None

    def _add_finding(self, finding: Finding) -> None:
        with self.lock:
            self.findings.add(finding)

    def crawl(self) -> None:
        queue: deque[Tuple[str, int]] = deque([(self.base_url, 0)])
        self.discovered.add(self.base_url)
        for raw_path in self.extra_paths:
            queue.append((urljoin(self.base_origin, raw_path.strip()), 1))

        while queue and len(self.visited) < self.max_urls:
            current, depth = queue.popleft()
            normalized = self._normalize_url(current)
            if normalized in self.visited or not self._same_origin(normalized):
                continue
            self.visited.add(normalized)
            response = self._request(normalized)
            if not response:
                continue
            self.responses[normalized] = response
            self._check_response(normalized, response)

            if depth >= self.max_depth:
                continue
            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type:
                continue

            extractor = LinkExtractor()
            extractor.feed(response.body)
            for raw_link in extractor.links:
                joined = self._normalize_url(urljoin(normalized, raw_link))
                if not self._same_origin(joined):
                    continue
                if joined in self.discovered:
                    continue
                self.discovered.add(joined)
                queue.append((joined, depth + 1))

    def _check_response(self, url: str, response: ResponseData) -> None:
        self._check_security_headers(url, response)
        self._check_information_disclosure(url, response)
        self._check_http_methods(url)
        self._check_cors(url)
        self._check_open_redirect(url)
        self._check_reflected_xss(url)

    def _check_security_headers(self, url: str, response: ResponseData) -> None:
        missing = [header for header in SECURITY_HEADERS if header not in response.headers]
        if missing:
            self._add_finding(
                Finding(
                    severity="medium",
                    category="MISSING_SECURITY_HEADERS",
                    url=url,
                    evidence=f"Absents: {', '.join(missing)}",
                    recommendation="Ajouter les en-têtes de sécurité HTTP de base.",
                )
            )

    def _check_information_disclosure(self, url: str, response: ResponseData) -> None:
        lowered = response.body.lower()
        for pattern in ERROR_DISCLOSURE_PATTERNS:
            if re.search(pattern, lowered):
                self._add_finding(
                    Finding(
                        severity="medium",
                        category="INFORMATION_DISCLOSURE",
                        url=url,
                        evidence=f"Motif détecté: {pattern}",
                        recommendation="Masquer les erreurs serveur et désactiver le debug en production.",
                    )
                )
                return

    def _check_http_methods(self, url: str) -> None:
        response = self._request(url, method="OPTIONS")
        if not response:
            return
        allow = response.headers.get("allow", "")
        dangerous = sorted({method for method in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT") if method in allow.upper()})
        if dangerous:
            self._add_finding(
                Finding(
                    severity="high",
                    category="DANGEROUS_HTTP_METHODS",
                    url=url,
                    evidence=f"Allow: {allow}",
                    recommendation=f"Désactiver les méthodes non nécessaires: {', '.join(dangerous)}",
                )
            )

    def _check_cors(self, url: str) -> None:
        evil_origin = "https://evil.example.com"
        response = self._request(url, headers={"Origin": evil_origin})
        if not response:
            return
        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "").lower()
        if acao == evil_origin:
            self._add_finding(
                Finding(
                    severity="high",
                    category="CORS_ORIGIN_REFLECTION",
                    url=url,
                    evidence=f"Origin reflétée: {acao}",
                    recommendation="N'autoriser que des origines de confiance explicites.",
                )
            )
        if acao == "*" and acac == "true":
            self._add_finding(
                Finding(
                    severity="critical",
                    category="CORS_WILDCARD_WITH_CREDENTIALS",
                    url=url,
                    evidence="`Access-Control-Allow-Origin: *` avec credentials.",
                    recommendation="Interdire `*` lorsque les credentials sont autorisés.",
                )
            )

    def _check_open_redirect(self, url: str) -> None:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not query:
            return
        candidate_params = [name for name in query if name.lower() in REDIRECT_PARAMS]
        if not candidate_params:
            return
        marker = f"https://evil.example.com/{self._token(6)}"
        injected = query.copy()
        for param in candidate_params:
            injected[param] = [marker]
        new_query = urlencode(injected, doseq=True)
        target_url = urlunparse(parsed._replace(query=new_query))
        response = self._request(target_url)
        if not response:
            return
        location = response.headers.get("location", "")
        if marker in location:
            self._add_finding(
                Finding(
                    severity="high",
                    category="OPEN_REDIRECT",
                    url=target_url,
                    evidence=f"Redirection contrôlable: {location}",
                    recommendation="Mettre en place une allowlist stricte des destinations.",
                )
            )

    def _check_reflected_xss(self, url: str) -> None:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not query:
            return
        target_params = [name for name in query if name.lower() in XSS_PARAMS]
        if not target_params:
            return
        payload = f"<svg/onload=alert('{self._token(4)}')>"
        injected = query.copy()
        for param in target_params:
            injected[param] = [payload]
        new_url = urlunparse(parsed._replace(query=urlencode(injected, doseq=True)))
        response = self._request(new_url)
        if not response:
            return
        if payload.lower() in response.body.lower():
            self._add_finding(
                Finding(
                    severity="high",
                    category="REFLECTED_XSS",
                    url=new_url,
                    evidence=f"Payload reflété: {payload}",
                    recommendation="Encoder/sanitiser les entrées utilisateurs côté serveur et sortie HTML.",
                )
            )

    def check_sensitive_files(self) -> None:
        for path in SENSITIVE_PATHS:
            url = urljoin(self.base_origin, path)
            response = self._request(url)
            if not response:
                continue
            if response.status != 200:
                continue
            snippet = response.body[:200].replace("\n", " ")
            self._add_finding(
                Finding(
                    severity="high",
                    category="SENSITIVE_FILE_EXPOSED",
                    url=url,
                    evidence=f"HTTP 200 avec contenu: {snippet}",
                    recommendation="Supprimer le fichier de l'exposition web ou restreindre l'accès.",
                )
            )

    def scan(self) -> Dict[str, object]:
        self.crawl()
        self.check_sensitive_files()
        findings_list = sorted(self.findings, key=lambda item: (item.severity, item.category, item.url))
        severities = Counter(finding.severity for finding in findings_list)
        return {
            "target": self.base_url,
            "scanned_urls": len(self.visited),
            "discovered_urls": len(self.discovered),
            "summary": dict(severities),
            "findings": [asdict(finding) for finding in findings_list],
        }

    @staticmethod
    def _token(length: int) -> str:
        return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def load_wordlist(wordlist_path: Optional[str]) -> List[str]:
    if not wordlist_path:
        return list(DEFAULT_WORDLIST)
    lines = Path(wordlist_path).read_text(encoding="utf-8").splitlines()
    cleaned = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    return cleaned or list(DEFAULT_WORDLIST)


def write_json_report(report: Dict[str, object], output_path: str) -> None:
    Path(output_path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def write_markdown_report(report: Dict[str, object], output_path: str) -> None:
    lines = [
        "# Rapport Bug Bounty Web",
        "",
        f"- Cible: `{report['target']}`",
        f"- URLs scannées: `{report['scanned_urls']}`",
        f"- URLs découvertes: `{report['discovered_urls']}`",
        "",
        "## Résumé",
        "",
    ]
    summary = report.get("summary", {})
    if summary:
        for sev, count in sorted(summary.items()):
            lines.append(f"- **{sev}**: {count}")
    else:
        lines.append("- Aucun finding.")

    lines.extend(["", "## Findings", ""])
    findings = report.get("findings", [])
    if not findings:
        lines.append("Aucune vulnérabilité détectée.")
    else:
        for finding in findings:
            lines.extend(
                [
                    f"### [{finding['severity'].upper()}] {finding['category']}",
                    f"- URL: `{finding['url']}`",
                    f"- Evidence: {finding['evidence']}",
                    f"- Recommandation: {finding['recommendation']}",
                    "",
                ]
            )

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scanner bug bounty web orienté reconnaissance applicative et vulnérabilités courantes."
    )
    parser.add_argument("--url", required=True, help="URL cible (ex: https://target.tld)")
    parser.add_argument("--depth", type=int, default=2, help="Profondeur de crawl (défaut: 2)")
    parser.add_argument("--timeout", type=int, default=8, help="Timeout HTTP en secondes (défaut: 8)")
    parser.add_argument("--max-urls", type=int, default=200, help="Nombre maximal d'URLs à scanner (défaut: 200)")
    parser.add_argument("--user-agent", default="BugBountyScanner/1.0", help="User-Agent HTTP")
    parser.add_argument("--wordlist", default=None, help="Fichier de chemins supplémentaires à scanner")
    parser.add_argument("--output", default="bugbounty_report.json", help="Chemin de sortie JSON")
    parser.add_argument("--markdown", default="bugbounty_report.md", help="Chemin de sortie Markdown")
    parser.add_argument("--insecure", action="store_true", help="Désactive la vérification TLS")
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    extra_paths = load_wordlist(args.wordlist)
    scanner = BugBountyScanner(
        base_url=args.url,
        max_depth=max(0, args.depth),
        timeout=max(1, args.timeout),
        max_urls=max(1, args.max_urls),
        user_agent=args.user_agent,
        insecure=args.insecure,
        extra_paths=extra_paths,
    )
    report = scanner.scan()
    write_json_report(report, args.output)
    write_markdown_report(report, args.markdown)
    print(f"[+] Scan terminé: {report['scanned_urls']} URLs scannées, {len(report['findings'])} findings.")
    print(f"[+] Rapport JSON: {args.output}")
    print(f"[+] Rapport Markdown: {args.markdown}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
