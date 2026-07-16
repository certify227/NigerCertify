#!/usr/bin/env python3
"""
Agent commercial: extraction de contacts (emails + telephones) depuis une URL.

Usage:
    python agent_commercial.py https://exemple.com
    python agent_commercial.py https://exemple.com --json
"""

from __future__ import annotations

import argparse
import json
import re
from collections import deque
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
PHONE_REGEX = re.compile(
    r"(?:(?:\+|00)\d{1,3}[\s.\-/]?)?(?:\(?\d{1,4}\)?[\s.\-/]?){2,6}\d{2,4}"
)

CONTACT_HINTS = (
    "contact",
    "about",
    "a-propos",
    "apropos",
    "support",
    "team",
    "company",
    "service-client",
    "nous",
)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; CommercialContactAgent/1.0; "
        "+https://example.local/agent)"
    )
}


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.hrefs.append(value.strip())


@dataclass
class ExtractionResult:
    emails: set[str]
    phones: set[str]
    scanned_pages: list[str]


def fetch_html(url: str, timeout: int) -> str:
    request = Request(url, headers=DEFAULT_HEADERS)
    with urlopen(request, timeout=timeout) as response:  # nosec B310
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")


def normalize_obfuscated_text(text: str) -> str:
    normalized = unescape(text)
    normalized = re.sub(r"\(\s*at\s*\)|\[\s*at\s*\]", "@", normalized, flags=re.I)
    normalized = re.sub(r"\(\s*dot\s*\)|\[\s*dot\s*\]", ".", normalized, flags=re.I)
    return normalized


def normalize_phone(candidate: str) -> str | None:
    compact = re.sub(r"[()\s.\-/]", "", candidate)
    if compact.startswith("00"):
        compact = "+" + compact[2:]

    digits_only = re.sub(r"\D", "", compact)
    if len(digits_only) < 8 or len(digits_only) > 15:
        return None

    if compact.startswith("+"):
        return "+" + digits_only
    return digits_only


def extract_emails(text: str) -> set[str]:
    return {match.lower() for match in EMAIL_REGEX.findall(text)}


def extract_phones(text: str) -> set[str]:
    phones: set[str] = set()
    for match in PHONE_REGEX.findall(text):
        normalized = normalize_phone(match)
        if normalized:
            phones.add(normalized)
    return phones


def parse_links(html: str, base_url: str) -> list[str]:
    parser = LinkParser()
    parser.feed(html)
    result: list[str] = []
    for href in parser.hrefs:
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            continue
        cleaned = parsed._replace(fragment="", query="").geturl()
        result.append(cleaned)
    return result


def score_link(link: str) -> tuple[int, int]:
    lowered = link.lower()
    hint_score = sum(1 for hint in CONTACT_HINTS if hint in lowered)
    return (-hint_score, len(link))


def same_domain(url_a: str, url_b: str) -> bool:
    return urlparse(url_a).netloc == urlparse(url_b).netloc


def unique_preserving_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def collect_contacts(start_url: str, max_pages: int, timeout: int) -> ExtractionResult:
    queue: deque[str] = deque([start_url])
    visited: set[str] = set()
    emails: set[str] = set()
    phones: set[str] = set()
    scanned_pages: list[str] = []

    while queue and len(visited) < max_pages:
        current_url = queue.popleft()
        if current_url in visited:
            continue

        visited.add(current_url)
        try:
            html = fetch_html(current_url, timeout=timeout)
        except Exception:
            continue

        scanned_pages.append(current_url)
        text = normalize_obfuscated_text(html)
        emails.update(extract_emails(text))
        phones.update(extract_phones(text))

        links = parse_links(html, current_url)
        internal_links = [link for link in links if same_domain(start_url, link)]
        prioritized = sorted(unique_preserving_order(internal_links), key=score_link)

        for link in prioritized:
            if link not in visited and link not in queue:
                queue.append(link)

    return ExtractionResult(emails=emails, phones=phones, scanned_pages=scanned_pages)


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agent commercial: extraction d'emails et telephones depuis un site."
    )
    parser.add_argument("url", help="URL de depart (http/https).")
    parser.add_argument(
        "--max-pages",
        type=int,
        default=5,
        help="Nombre maximum de pages a scanner sur le domaine (defaut: 5).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=12,
        help="Timeout HTTP en secondes (defaut: 12).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Affiche la sortie au format JSON.",
    )
    return parser


def validate_input_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("L'URL doit commencer par http:// ou https://")
    if not parsed.netloc:
        raise ValueError("L'URL fournie est invalide.")


def main() -> int:
    parser = build_cli()
    args = parser.parse_args()

    try:
        validate_input_url(args.url)
    except ValueError as exc:
        print(f"[ERREUR] {exc}")
        return 1

    result = collect_contacts(args.url, max_pages=max(1, args.max_pages), timeout=args.timeout)

    payload = {
        "source_url": args.url,
        "scanned_pages_count": len(result.scanned_pages),
        "scanned_pages": sorted(result.scanned_pages),
        "emails": sorted(result.emails),
        "phones": sorted(result.phones),
    }

    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    print(f"URL source: {payload['source_url']}")
    print(f"Pages scannees: {payload['scanned_pages_count']}")
    print("\nEmails trouves:")
    if payload["emails"]:
        for email in payload["emails"]:
            print(f"  - {email}")
    else:
        print("  - aucun")

    print("\nTelephones trouves:")
    if payload["phones"]:
        for phone in payload["phones"]:
            print(f"  - {phone}")
    else:
        print("  - aucun")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
