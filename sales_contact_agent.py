#!/usr/bin/env python3
"""CLI simple pour extraire des emails et numeros de telephone depuis une URL.

Le script visite l'URL fournie puis suit quelques liens internes pertinents
("contact", "about", "support", etc.) afin de recuperer les coordonnees
visibles dans le HTML, les liens ``mailto:`` et ``tel:``.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
PHONE_PATTERN = re.compile(
    r"(?:(?:\+\d{1,3}[\s().-]*)?(?:\(?\d{1,4}\)?[\s().-]*){2,}\d)"
)
CONTACT_HINTS = (
    "contact",
    "about",
    "a-propos",
    "apropos",
    "support",
    "help",
    "team",
    "company",
    "service-client",
    "mentions-legales",
    "legal",
)
USER_AGENT = "SalesContactAgent/1.0 (+https://example.local)"


def has_scheme(url: str) -> bool:
    return bool(urlparse(url).scheme)


def ensure_scheme(url: str, default_scheme: str = "https") -> str:
    parsed = urlparse(url)
    if parsed.scheme:
        return url
    return f"{default_scheme}://{url}"


def normalize_email(candidate: str) -> str | None:
    email = candidate.strip(" \t\r\n.,;:()[]{}<>\"'").lower()
    if not EMAIL_PATTERN.fullmatch(email):
        return None
    return email


def normalize_phone(candidate: str) -> str | None:
    trimmed = candidate.strip()
    has_plus = trimmed.lstrip().startswith("+")
    digits = re.sub(r"\D", "", trimmed)
    if not 8 <= len(digits) <= 15:
        return None
    if len(set(digits)) == 1:
        return None
    return f"+{digits}" if has_plus else digits


def deobfuscate_text(text: str) -> str:
    normalized = text
    replacements = {
        "[at]": "@",
        "(at)": "@",
        " at ": " @ ",
        "[dot]": ".",
        "(dot)": ".",
        " dot ": " . ",
    }
    for source, target in replacements.items():
        normalized = normalized.replace(source, target)
        normalized = normalized.replace(source.upper(), target)
        normalized = normalized.replace(source.title(), target)
    return normalized


class ContactHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.mailtos: list[str] = []
        self.tels: list[str] = []
        self._text_chunks: list[str] = []
        self._ignored_stack: list[str] = []

    @property
    def text(self) -> str:
        return " ".join(self._text_chunks)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = dict(attrs)
        if tag in {"script", "style", "noscript"}:
            self._ignored_stack.append(tag)
            return
        href = attrs_map.get("href")
        if not href:
            return
        if href.startswith("mailto:"):
            self.mailtos.append(href[len("mailto:") :])
        elif href.startswith("tel:"):
            self.tels.append(href[len("tel:") :])
        else:
            self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if self._ignored_stack and self._ignored_stack[-1] == tag:
            self._ignored_stack.pop()

    def handle_data(self, data: str) -> None:
        if self._ignored_stack:
            return
        cleaned = data.strip()
        if cleaned:
            self._text_chunks.append(cleaned)


@dataclass
class PageExtraction:
    links: list[str]
    emails: set[str]
    phones: set[str]


def extract_emails_from_text(text: str) -> set[str]:
    matches = set()
    for candidate in EMAIL_PATTERN.findall(text):
        email = normalize_email(candidate)
        if email:
            matches.add(email)

    deobfuscated = deobfuscate_text(text)
    for candidate in EMAIL_PATTERN.findall(deobfuscated):
        email = normalize_email(candidate)
        if email:
            matches.add(email)
    return matches


def extract_phones_from_text(text: str) -> set[str]:
    matches = set()
    for candidate in PHONE_PATTERN.findall(text):
        phone = normalize_phone(candidate)
        if phone:
            matches.add(phone)
    return matches


def extract_from_html(html: str, base_url: str) -> PageExtraction:
    parser = ContactHTMLParser()
    parser.feed(html)
    combined_text = unescape(parser.text)

    emails = extract_emails_from_text(combined_text)
    phones = extract_phones_from_text(combined_text)

    for candidate in parser.mailtos:
        email = normalize_email(unescape(candidate.split("?", 1)[0]))
        if email:
            emails.add(email)

    for candidate in parser.tels:
        phone = normalize_phone(unescape(candidate.split("?", 1)[0]))
        if phone:
            phones.add(phone)

    resolved_links = []
    for href in parser.links:
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            continue
        resolved_links.append(absolute)

    return PageExtraction(links=resolved_links, emails=emails, phones=phones)


def fetch_text(url: str, timeout: int = 10) -> str:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:
        payload = response.read()
        content_type = response.headers.get_content_charset() or "utf-8"
        return payload.decode(content_type, errors="replace")


def prioritize_links(urls: Iterable[str], root_domain: str) -> list[str]:
    same_domain = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc != root_domain:
            continue
        same_domain.append(url)

    return sorted(
        dict.fromkeys(same_domain),
        key=lambda url: (
            0 if any(hint in url.lower() for hint in CONTACT_HINTS) else 1,
            len(url),
            url,
        ),
    )


def extract_contacts_from_url(url: str, max_pages: int = 6, timeout: int = 10) -> dict:
    start_url = ensure_scheme(url)
    root_domain = urlparse(start_url).netloc
    queue = deque([start_url])
    scheduled = {start_url}
    visited_pages: list[str] = []
    email_sources: dict[str, set[str]] = defaultdict(set)
    phone_sources: dict[str, set[str]] = defaultdict(set)
    errors: list[dict[str, str]] = []
    tried_http_fallback = False

    while queue and len(visited_pages) < max_pages:
        current_url = queue.popleft()
        visited_pages.append(current_url)

        try:
            html = fetch_text(current_url, timeout=timeout)
        except Exception as exc:  # pragma: no cover - exercise via CLI/manual test
            if (
                current_url == start_url
                and not has_scheme(url)
                and not tried_http_fallback
                and start_url.startswith("https://")
            ):
                http_url = ensure_scheme(url, default_scheme="http")
                tried_http_fallback = True
                start_url = http_url
                root_domain = urlparse(start_url).netloc
                queue.appendleft(http_url)
                scheduled.add(http_url)
                errors.append({"url": current_url, "error": str(exc)})
                continue
            errors.append({"url": current_url, "error": str(exc)})
            continue

        extracted = extract_from_html(html, current_url)
        for email in extracted.emails:
            email_sources[email].add(current_url)
        for phone in extracted.phones:
            phone_sources[phone].add(current_url)

        for link in prioritize_links(extracted.links, root_domain):
            if link in scheduled or link in visited_pages:
                continue
            queue.append(link)
            scheduled.add(link)

    return {
        "input_url": url,
        "normalized_url": start_url,
        "visited_pages": visited_pages,
        "emails": [
            {"value": email, "sources": sorted(email_sources[email])}
            for email in sorted(email_sources)
        ],
        "phones": [
            {"value": phone, "sources": sorted(phone_sources[phone])}
            for phone in sorted(phone_sources)
        ],
        "errors": errors,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recupere emails et numeros de telephone depuis une URL."
    )
    parser.add_argument("url", help="URL a analyser")
    parser.add_argument(
        "--max-pages",
        type=int,
        default=6,
        help="Nombre maximum de pages internes a visiter",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout reseau par requete en secondes",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.max_pages < 1:
        raise SystemExit("--max-pages doit etre superieur ou egal a 1")

    result = extract_contacts_from_url(
        url=args.url,
        max_pages=args.max_pages,
        timeout=args.timeout,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
