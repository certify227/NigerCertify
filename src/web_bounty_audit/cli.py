from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

SEVERITY_WEIGHT = {
    "critical": 13,
    "high": 8,
    "medium": 5,
    "low": 2,
    "info": 1,
}

ENDPOINT_RE = re.compile(
    r"""(?P<quote>["'])(
        https?://[^"'\\\s<>]+
        |
        /(?:api|auth|admin|graphql|v\d|assets|static)[^"'\\\s<>]*
    )(?P=quote)""",
    re.IGNORECASE | re.VERBOSE,
)
SOURCE_MAP_RE = re.compile(r"sourceMappingURL\s*=\s*(?P<target>[^\s*]+)")
XML_LOC_RE = re.compile(r"<loc>\s*(?P<url>https?://[^<\s]+)\s*</loc>", re.IGNORECASE)


@dataclass(slots=True)
class Issue:
    severity: str
    category: str
    title: str
    target: str
    evidence: str
    remediation: str


@dataclass(slots=True)
class Endpoint:
    url: str
    source: str
    context: str


@dataclass(slots=True)
class AnalysisResult:
    scanned_inputs: int
    requests_analyzed: int
    issues: list[Issue]
    endpoints: list[Endpoint]

    @property
    def risk_score(self) -> int:
        return sum(SEVERITY_WEIGHT.get(issue.severity, 0) for issue in self.issues)

    def severity_counts(self) -> dict[str, int]:
        counts = Counter(issue.severity for issue in self.issues)
        ordered = ["critical", "high", "medium", "low", "info"]
        return {name: counts.get(name, 0) for name in ordered if counts.get(name, 0)}

    def to_dict(self) -> dict[str, object]:
        return {
            "scanned_inputs": self.scanned_inputs,
            "requests_analyzed": self.requests_analyzed,
            "risk_score": self.risk_score,
            "severity_counts": self.severity_counts(),
            "issues": [asdict(issue) for issue in self.issues],
            "endpoints": [asdict(endpoint) for endpoint in self.endpoints],
        }


class PasswordFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._form_stack: list[dict[str, str | bool]] = []
        self.password_forms: list[dict[str, str | bool]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "form":
            self._form_stack.append(
                {"action": attr_map.get("action", ""), "method": attr_map.get("method", "get"), "has_password": False}
            )
        elif tag.lower() == "input" and self._form_stack:
            if attr_map.get("type", "").lower() == "password":
                self._form_stack[-1]["has_password"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form_stack:
            form = self._form_stack.pop()
            if form.get("has_password"):
                self.password_forms.append(form)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="web-bounty-audit",
        description="Offline defensive analyzer for HAR captures of web apps.",
    )
    parser.add_argument("inputs", nargs="+", help="HAR file or directory containing HAR files")
    parser.add_argument("--json", dest="json_path", help="Write JSON report to a file")
    parser.add_argument("--markdown", dest="markdown_path", help="Write Markdown report to a file")
    parser.add_argument("--max-endpoints", type=int, default=50, help="Maximum endpoints to print in console output")
    parser.add_argument("--quiet", action="store_true", help="Only write exported reports")
    return parser.parse_args(argv)


def discover_har_files(inputs: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for raw in inputs:
        path = Path(raw).expanduser().resolve()
        if path.is_dir():
            files.extend(sorted(path.rglob("*.har")))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(f"Input not found: {raw}")
    if not files:
        raise FileNotFoundError("No HAR files found in the provided inputs")
    return files


def normalize_headers(headers: list[dict[str, object]]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for header in headers:
        name = str(header.get("name", "")).strip().lower()
        if not name:
            continue
        normalized[name] = str(header.get("value", "")).strip()
    return normalized


def decode_content_text(content: dict[str, object]) -> str:
    text = str(content.get("text", "") or "")
    if not text:
        return ""
    encoding = str(content.get("encoding", "") or "").lower()
    if encoding != "base64":
        return text
    try:
        return base64.b64decode(text).decode("utf-8", errors="replace")
    except Exception:
        return ""


def add_issue(issues: list[Issue], severity: str, category: str, title: str, target: str, evidence: str, remediation: str) -> None:
    issues.append(
        Issue(
            severity=severity,
            category=category,
            title=title,
            target=target,
            evidence=evidence,
            remediation=remediation,
        )
    )


def analyze_headers(url: str, response_headers: dict[str, str], issues: list[Issue]) -> None:
    parsed = urlparse(url)
    required_headers = {
        "content-security-policy": (
            "medium",
            "Missing Content-Security-Policy header",
            "Define a restrictive Content-Security-Policy with explicit script and frame controls.",
        ),
        "x-content-type-options": (
            "low",
            "Missing X-Content-Type-Options header",
            "Set X-Content-Type-Options to nosniff.",
        ),
        "referrer-policy": (
            "low",
            "Missing Referrer-Policy header",
            "Set a Referrer-Policy such as strict-origin-when-cross-origin.",
        ),
        "permissions-policy": (
            "low",
            "Missing Permissions-Policy header",
            "Disable browser features that are not required by the application.",
        ),
    }
    for header_name, (severity, title, remediation) in required_headers.items():
        if header_name not in response_headers:
            add_issue(
                issues,
                severity,
                "headers",
                title,
                url,
                f"Response is missing {header_name}.",
                remediation,
            )

    has_frame_ancestor = "frame-ancestors" in response_headers.get("content-security-policy", "").lower()
    if "x-frame-options" not in response_headers and not has_frame_ancestor:
        add_issue(
            issues,
            "medium",
            "headers",
            "Missing anti-clickjacking protection",
            url,
            "Response is missing both X-Frame-Options and CSP frame-ancestors.",
            "Add X-Frame-Options or CSP frame-ancestors to restrict framing.",
        )

    if parsed.scheme == "https" and "strict-transport-security" not in response_headers:
        add_issue(
            issues,
            "medium",
            "headers",
            "Missing Strict-Transport-Security header",
            url,
            "HTTPS response does not advertise HSTS.",
            "Enable HSTS with an appropriate max-age and includeSubDomains if suitable.",
        )

    for disclosure_header in ("server", "x-powered-by", "x-aspnet-version"):
        if disclosure_header in response_headers:
            add_issue(
                issues,
                "info",
                "fingerprint",
                f"Technology disclosure via {disclosure_header}",
                url,
                f"{disclosure_header}: {response_headers[disclosure_header]}",
                "Remove or minimize version-revealing server banners.",
            )


def analyze_cookies(url: str, cookies: list[dict[str, object]], issues: list[Issue]) -> None:
    for cookie in cookies:
        name = str(cookie.get("name", "")).strip() or "<unnamed>"
        secure = bool(cookie.get("secure"))
        http_only = bool(cookie.get("httpOnly"))
        same_site = str(cookie.get("sameSite", "")).strip().lower()
        if not secure:
            add_issue(
                issues,
                "medium",
                "cookies",
                "Cookie missing Secure flag",
                url,
                f"Cookie {name} is not marked Secure.",
                "Mark session cookies with the Secure attribute.",
            )
        if not http_only:
            add_issue(
                issues,
                "medium",
                "cookies",
                "Cookie missing HttpOnly flag",
                url,
                f"Cookie {name} is accessible to client-side scripts.",
                "Mark sensitive cookies with the HttpOnly attribute.",
            )
        if same_site not in {"lax", "strict"}:
            add_issue(
                issues,
                "low",
                "cookies",
                "Cookie missing explicit SameSite protection",
                url,
                f"Cookie {name} has SameSite={same_site or 'unset'}.",
                "Set SameSite=Lax or SameSite=Strict unless cross-site usage is required.",
            )


def analyze_cors(url: str, request_headers: dict[str, str], response_headers: dict[str, str], issues: list[Issue]) -> None:
    allow_origin = response_headers.get("access-control-allow-origin")
    allow_credentials = response_headers.get("access-control-allow-credentials", "").lower()
    request_origin = request_headers.get("origin")
    if allow_origin == "*" and allow_credentials == "true":
        add_issue(
            issues,
            "high",
            "cors",
            "Wildcard CORS with credentials enabled",
            url,
            "Access-Control-Allow-Origin is '*' while credentials are allowed.",
            "Return a specific allowlist origin and avoid wildcard with credentials.",
        )
    elif allow_origin == "*":
        add_issue(
            issues,
            "medium",
            "cors",
            "Permissive wildcard CORS policy",
            url,
            "Access-Control-Allow-Origin is '*'.",
            "Restrict CORS to trusted origins if responses contain sensitive data.",
        )
    elif request_origin and allow_origin and allow_origin == request_origin:
        add_issue(
            issues,
            "medium",
            "cors",
            "Origin reflected in CORS response",
            url,
            f"Request origin {request_origin} is echoed back in Access-Control-Allow-Origin.",
            "Ensure origin reflection is backed by a strict allowlist.",
        )


def extract_endpoints(url: str, text: str, mime_type: str, endpoints: list[Endpoint]) -> None:
    if not text:
        return
    for match in ENDPOINT_RE.finditer(text):
        endpoint = match.group(2)
        endpoints.append(Endpoint(url=endpoint, source=url, context="inline reference"))

    lowered_url = url.lower()
    if lowered_url.endswith("/robots.txt"):
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith(("allow:", "disallow:", "sitemap:")):
                endpoints.append(Endpoint(url=stripped.split(":", 1)[1].strip(), source=url, context="robots.txt"))

    if "xml" in mime_type.lower():
        for match in XML_LOC_RE.finditer(text):
            endpoints.append(Endpoint(url=match.group("url"), source=url, context="xml loc"))


def analyze_body(url: str, mime_type: str, text: str, issues: list[Issue], endpoints: list[Endpoint]) -> None:
    if not text:
        return

    extract_endpoints(url, text, mime_type, endpoints)

    if "javascript" in mime_type.lower() or url.lower().endswith(".js"):
        source_map = SOURCE_MAP_RE.search(text)
        if source_map:
            add_issue(
                issues,
                "low",
                "assets",
                "JavaScript source map reference exposed",
                url,
                f"Found sourceMappingURL={source_map.group('target')}.",
                "Remove public source maps or ensure they do not expose sensitive source code.",
            )

    if "html" in mime_type.lower():
        parser = PasswordFormParser()
        parser.feed(text)
        parsed = urlparse(url)
        for form in parser.password_forms:
            action = str(form.get("action", "") or "")
            if parsed.scheme == "http" or action.startswith("http://"):
                add_issue(
                    issues,
                    "high",
                    "forms",
                    "Password form served without HTTPS",
                    url,
                    f"Form action={action or '<same page>'} while page scheme is {parsed.scheme}.",
                    "Serve login flows exclusively over HTTPS.",
                )


def deduplicate_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Endpoint] = []
    for endpoint in endpoints:
        key = (endpoint.url, endpoint.source, endpoint.context)
        if key in seen:
            continue
        seen.add(key)
        unique.append(endpoint)
    return unique


def analyze_har_file(path: Path) -> tuple[list[Issue], list[Endpoint], int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])
    issues: list[Issue] = []
    endpoints: list[Endpoint] = []

    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = str(request.get("url", "")).strip()
        if not url:
            continue

        request_headers = normalize_headers(request.get("headers", []))
        response_headers = normalize_headers(response.get("headers", []))
        response_cookies = response.get("cookies", [])
        content = response.get("content", {})
        mime_type = str(content.get("mimeType", "") or "")
        body_text = decode_content_text(content)

        analyze_headers(url, response_headers, issues)
        analyze_cookies(url, response_cookies, issues)
        analyze_cors(url, request_headers, response_headers, issues)
        analyze_body(url, mime_type, body_text, issues, endpoints)

    return issues, deduplicate_endpoints(endpoints), len(entries)


def analyze_files(paths: list[Path]) -> AnalysisResult:
    all_issues: list[Issue] = []
    all_endpoints: list[Endpoint] = []
    total_requests = 0
    for path in paths:
        issues, endpoints, request_count = analyze_har_file(path)
        all_issues.extend(issues)
        all_endpoints.extend(endpoints)
        total_requests += request_count
    return AnalysisResult(
        scanned_inputs=len(paths),
        requests_analyzed=total_requests,
        issues=all_issues,
        endpoints=deduplicate_endpoints(all_endpoints),
    )


def render_console_report(result: AnalysisResult, max_endpoints: int) -> str:
    lines = [
        f"Scanned inputs: {result.scanned_inputs}",
        f"Requests analyzed: {result.requests_analyzed}",
        f"Issues found: {len(result.issues)}",
        f"Unique endpoints: {len(result.endpoints)}",
        f"Risk score: {result.risk_score}",
        "",
        "Severity counts:",
    ]
    for severity, count in result.severity_counts().items():
        lines.append(f"  - {severity}: {count}")

    lines.extend(["", "Top issues:"])
    top_issues = sorted(result.issues, key=lambda issue: (-SEVERITY_WEIGHT[issue.severity], issue.title, issue.target))[:8]
    for issue in top_issues:
        lines.append(f"  [{issue.severity}] {issue.title} -> {issue.target}")

    if result.endpoints:
        lines.extend(["", "Interesting endpoints:"])
        for endpoint in result.endpoints[:max_endpoints]:
            lines.append(f"  - {endpoint.url} ({endpoint.context} from {endpoint.source})")
    return "\n".join(lines)


def render_markdown_report(result: AnalysisResult) -> str:
    lines = [
        "# web-bounty-audit report",
        "",
        f"- Scanned inputs: {result.scanned_inputs}",
        f"- Requests analyzed: {result.requests_analyzed}",
        f"- Issues found: {len(result.issues)}",
        f"- Unique endpoints: {len(result.endpoints)}",
        f"- Risk score: {result.risk_score}",
        "",
        "## Severity counts",
    ]
    for severity, count in result.severity_counts().items():
        lines.append(f"- {severity}: {count}")

    lines.extend(["", "## Issues"])
    for issue in sorted(result.issues, key=lambda item: (-SEVERITY_WEIGHT[item.severity], item.title, item.target)):
        lines.extend(
            [
                f"### {issue.title}",
                f"- Severity: {issue.severity}",
                f"- Category: {issue.category}",
                f"- Target: {issue.target}",
                f"- Evidence: {issue.evidence}",
                f"- Remediation: {issue.remediation}",
                "",
            ]
        )

    lines.extend(["## Endpoints"])
    for endpoint in result.endpoints:
        lines.append(f"- `{endpoint.url}` from `{endpoint.source}` ({endpoint.context})")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        files = discover_har_files(args.inputs)
        result = analyze_files(files)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json_path:
        Path(args.json_path).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    if args.markdown_path:
        Path(args.markdown_path).write_text(render_markdown_report(result), encoding="utf-8")
    if not args.quiet:
        print(render_console_report(result, args.max_endpoints))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
