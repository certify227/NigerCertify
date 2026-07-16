from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen


DEFAULT_HEADERS = {
    "User-Agent": "Cursor-Bounty-Tool/1.0 (+authorized-testing-only)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


SENSITIVE_PATHS: Sequence[Tuple[str, str]] = (
    ("/.git/config", "Potential source code exposure."),
    ("/.env", "Potential environment secrets exposure."),
    ("/backup.zip", "Potential backup archive exposed."),
    ("/admin/", "Administration panel publicly reachable."),
    ("/phpinfo.php", "Potential debug page disclosure."),
    ("/server-status", "Potential server status exposure."),
)


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    url: str
    recommendation: str
    evidence: Optional[str] = None


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: Dict[str, str]
    set_cookies: List[str]
    body: str


class LinkAndFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: Set[str] = set()
        self.forms: List[Dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_map = {k.lower(): v for k, v in attrs}
        if tag.lower() == "a":
            href = attr_map.get("href")
            if href:
                self.links.add(href)
        if tag.lower() == "form":
            method = (attr_map.get("method") or "GET").upper()
            action = attr_map.get("action") or ""
            self.forms.append({"method": method, "action": action})


class BountyScanner:
    def __init__(
        self,
        base_url: str,
        max_pages: int = 40,
        max_depth: int = 2,
        timeout: int = 10,
        delay: float = 0.2,
        user_agent: Optional[str] = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be a valid http(s) URL.")
        self.base_url = self._strip_fragment(base_url.rstrip("/"))
        self.base_host = urlparse(self.base_url).netloc
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.delay = delay
        self.headers = dict(DEFAULT_HEADERS)
        if user_agent:
            self.headers["User-Agent"] = user_agent

        self.findings: List[Finding] = []
        self.visited: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.discovered_forms: List[Dict[str, str]] = []
        self.errors: List[str] = []

    @staticmethod
    def _strip_fragment(url: str) -> str:
        parts = urlparse(url)
        return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, parts.query, ""))

    @staticmethod
    def _normalize_url(url: str) -> str:
        parts = urlparse(url)
        path = parts.path or "/"
        return urlunparse((parts.scheme.lower(), parts.netloc.lower(), path, parts.params, parts.query, ""))

    def _is_same_host(self, url: str) -> bool:
        return urlparse(url).netloc == self.base_host

    def _request(self, url: str, extra_headers: Optional[Dict[str, str]] = None) -> Optional[HttpResponse]:
        headers = dict(self.headers)
        if extra_headers:
            headers.update(extra_headers)
        request = Request(url=url, headers=headers, method="GET")
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = response.read(300_000).decode("utf-8", errors="replace")
                headers_map = {k.lower(): v for k, v in response.headers.items()}
                set_cookies = list(response.headers.get_all("Set-Cookie", []))
                return HttpResponse(
                    url=response.geturl(),
                    status=response.getcode(),
                    headers=headers_map,
                    set_cookies=set_cookies,
                    body=body,
                )
        except HTTPError as exc:
            self.errors.append(f"HTTPError {exc.code} on {url}")
        except URLError as exc:
            self.errors.append(f"URLError on {url}: {exc.reason}")
        except TimeoutError:
            self.errors.append(f"Timeout on {url}")
        return None

    def _add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def _extract_urls_and_forms(self, base_url: str, body: str) -> Tuple[Set[str], List[Dict[str, str]]]:
        parser = LinkAndFormParser()
        parser.feed(body)

        absolute_urls: Set[str] = set()
        for link in parser.links:
            full = self._strip_fragment(urljoin(base_url, link))
            parsed = urlparse(full)
            if parsed.scheme in {"http", "https"}:
                absolute_urls.add(self._normalize_url(full))

        forms: List[Dict[str, str]] = []
        for form in parser.forms:
            action = form.get("action", "")
            absolute_action = self._strip_fragment(urljoin(base_url, action))
            forms.append({"method": form["method"], "action": self._normalize_url(absolute_action)})

        return absolute_urls, forms

    def _check_security_headers(self, response: HttpResponse) -> None:
        expected = {
            "strict-transport-security": (
                "HIGH",
                "Missing HSTS header",
                "Set Strict-Transport-Security for HTTPS responses.",
            ),
            "content-security-policy": (
                "MEDIUM",
                "Missing Content-Security-Policy",
                "Define a restrictive CSP to reduce XSS impact.",
            ),
            "x-content-type-options": (
                "LOW",
                "Missing X-Content-Type-Options",
                "Set X-Content-Type-Options: nosniff.",
            ),
            "x-frame-options": (
                "LOW",
                "Missing X-Frame-Options",
                "Set X-Frame-Options: DENY or SAMEORIGIN.",
            ),
            "referrer-policy": (
                "LOW",
                "Missing Referrer-Policy",
                "Set a strict Referrer-Policy.",
            ),
        }
        for header_name, (severity, title, recommendation) in expected.items():
            if header_name not in response.headers:
                self._add_finding(
                    Finding(
                        severity=severity,
                        category="headers",
                        title=title,
                        detail=f"{header_name} not found on response.",
                        url=response.url,
                        recommendation=recommendation,
                    )
                )

    def _check_cookie_flags(self, response: HttpResponse) -> None:
        for cookie in response.set_cookies:
            cookie_lower = cookie.lower()
            if "secure" not in cookie_lower:
                self._add_finding(
                    Finding(
                        severity="MEDIUM",
                        category="cookies",
                        title="Cookie missing Secure flag",
                        detail="A cookie is set without Secure attribute.",
                        url=response.url,
                        recommendation="Set Secure on cookies transmitted over HTTPS.",
                        evidence=cookie,
                    )
                )
            if "httponly" not in cookie_lower:
                self._add_finding(
                    Finding(
                        severity="MEDIUM",
                        category="cookies",
                        title="Cookie missing HttpOnly flag",
                        detail="A cookie is set without HttpOnly attribute.",
                        url=response.url,
                        recommendation="Set HttpOnly to limit script access to cookies.",
                        evidence=cookie,
                    )
                )
            if "samesite=" not in cookie_lower:
                self._add_finding(
                    Finding(
                        severity="LOW",
                        category="cookies",
                        title="Cookie missing SameSite attribute",
                        detail="A cookie is set without SameSite attribute.",
                        url=response.url,
                        recommendation="Set SameSite=Lax or SameSite=Strict where possible.",
                        evidence=cookie,
                    )
                )

    def _check_disclosure_headers(self, response: HttpResponse) -> None:
        for header_name in ("server", "x-powered-by"):
            if header_name in response.headers:
                self._add_finding(
                    Finding(
                        severity="LOW",
                        category="information-disclosure",
                        title=f"Technology disclosure via {header_name}",
                        detail=f"{header_name} header discloses stack details.",
                        url=response.url,
                        recommendation="Minimize or sanitize technology-identifying headers.",
                        evidence=response.headers[header_name],
                    )
                )

    def _check_reflected_input(self, url: str) -> None:
        marker = "CURSOR_BB_MARKER_12345"
        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        params["bbtest"] = marker
        query = urlencode(params)
        target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))
        response = self._request(target)
        if response and marker in response.body:
            self._add_finding(
                Finding(
                    severity="LOW",
                    category="input-reflection",
                    title="Reflected input candidate",
                    detail="Injected marker was reflected in response body.",
                    url=target,
                    recommendation="Review output encoding and input handling for XSS risks.",
                    evidence=marker,
                )
            )

    def _check_cors(self, url: str) -> None:
        response = self._request(url, extra_headers={"Origin": "https://evil.example"})
        if not response:
            return
        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            self._add_finding(
                Finding(
                    severity="HIGH",
                    category="cors",
                    title="Potentially unsafe CORS policy",
                    detail="ACAO is '*' while credentials are allowed.",
                    url=url,
                    recommendation="Avoid wildcard ACAO when credentials are enabled.",
                    evidence=f"ACAO={acao}, ACAC={acac}",
                )
            )
        elif acao == "https://evil.example":
            self._add_finding(
                Finding(
                    severity="MEDIUM",
                    category="cors",
                    title="Origin reflection in CORS policy",
                    detail="Server reflected arbitrary Origin value.",
                    url=url,
                    recommendation="Allow-list trusted origins explicitly.",
                    evidence=f"ACAO={acao}",
                )
            )

    def _check_sensitive_paths(self) -> None:
        for path, rationale in SENSITIVE_PATHS:
            url = urljoin(self.base_url + "/", path.lstrip("/"))
            response = self._request(url)
            if not response:
                continue
            if response.status < 400:
                severity = "HIGH" if path in {"/.git/config", "/.env"} else "MEDIUM"
                self._add_finding(
                    Finding(
                        severity=severity,
                        category="exposed-resource",
                        title=f"Sensitive path reachable: {path}",
                        detail=rationale,
                        url=url,
                        recommendation="Restrict public access or remove exposed resource.",
                        evidence=f"HTTP {response.status}",
                    )
                )
            time.sleep(self.delay)

    def crawl(self) -> None:
        queue = deque([(self.base_url, 0)])
        while queue and len(self.visited) < self.max_pages:
            current_url, depth = queue.popleft()
            normalized = self._normalize_url(current_url)
            if normalized in self.visited:
                continue
            if not self._is_same_host(normalized):
                continue

            response = self._request(normalized)
            self.visited.add(normalized)
            self.discovered_urls.add(normalized)

            if not response:
                continue

            self._check_security_headers(response)
            self._check_cookie_flags(response)
            self._check_disclosure_headers(response)

            content_type = response.headers.get("content-type", "")
            if "text/html" in content_type:
                urls, forms = self._extract_urls_and_forms(normalized, response.body)
                self.discovered_forms.extend(forms)
                for url in urls:
                    if self._is_same_host(url) and url not in self.visited and depth + 1 <= self.max_depth:
                        queue.append((url, depth + 1))

            time.sleep(self.delay)

    def run(self) -> Dict[str, object]:
        started = datetime.now(timezone.utc)
        self.crawl()

        sample_for_deeper_checks = list(self.discovered_urls)[:6] or [self.base_url]
        for url in sample_for_deeper_checks:
            self._check_reflected_input(url)
            self._check_cors(url)
            time.sleep(self.delay)

        self._check_sensitive_paths()
        duration = (datetime.now(timezone.utc) - started).total_seconds()

        severity_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        severity_counts = {sev: 0 for sev in severity_order}
        for finding in self.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1

        unique_forms = {
            (form["method"], form["action"]): form for form in self.discovered_forms
        }
        report = {
            "target": self.base_url,
            "started_at_utc": started.isoformat(),
            "duration_seconds": round(duration, 2),
            "crawled_pages": len(self.visited),
            "discovered_urls": sorted(self.discovered_urls),
            "discovered_forms": sorted(unique_forms.values(), key=lambda x: (x["action"], x["method"])),
            "severity_counts": severity_counts,
            "findings": [asdict(finding) for finding in self.findings],
            "errors": self.errors,
            "note": "Run only against targets you are explicitly authorized to test.",
        }
        return report


def report_to_markdown(report: Dict[str, object]) -> str:
    lines = [
        "# Web Bug Bounty Report",
        "",
        f"- Target: `{report['target']}`",
        f"- Started: `{report['started_at_utc']}`",
        f"- Duration (s): `{report['duration_seconds']}`",
        f"- Crawled pages: `{report['crawled_pages']}`",
        "",
        "## Severity summary",
    ]
    severity_counts = report.get("severity_counts", {})
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"- {severity}: `{severity_counts.get(severity, 0)}`")

    lines.append("")
    lines.append("## Findings")
    findings = report.get("findings", [])
    if not findings:
        lines.append("- No findings detected with current non-intrusive checks.")
    else:
        for item in findings:
            lines.extend(
                [
                    f"### [{item['severity']}] {item['title']}",
                    f"- Category: `{item['category']}`",
                    f"- URL: `{item['url']}`",
                    f"- Detail: {item['detail']}",
                    f"- Recommendation: {item['recommendation']}",
                ]
            )
            evidence = item.get("evidence")
            if evidence:
                lines.append(f"- Evidence: `{evidence}`")
            lines.append("")

    lines.append("## Errors")
    errors = report.get("errors", [])
    if not errors:
        lines.append("- None")
    else:
        for error in errors:
            lines.append(f"- {error}")

    return "\n".join(lines).strip() + "\n"


def report_to_json(report: Dict[str, object]) -> str:
    return json.dumps(report, indent=2, sort_keys=False)
