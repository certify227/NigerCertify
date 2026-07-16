#!/usr/bin/env python3
"""Agent commercial simple pour extraire emails et telephones publics."""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Iterable
from urllib import error, parse, request


EMAIL_RE = re.compile(
    r"(?<![\w.+-])[\w.!#$%&'*+/=?^_`{|}~-]+@[\w-]+(?:\.[\w-]+)+",
    re.IGNORECASE,
)
PHONE_RE = re.compile(
    r"(?:(?:\+|00)\d{1,3}[\s().-]*)?(?:\(?\d{1,4}\)?[\s().-]*){2,}\d{2,4}"
)
CONTACT_KEYWORDS = (
    "contact",
    "about",
    "a-propos",
    "apropos",
    "nous-contacter",
    "mentions-legales",
    "legal",
    "impressum",
    "team",
    "equipe",
)
COMMON_CONTACT_PATHS = (
    "/contact",
    "/contact-us",
    "/nous-contacter",
    "/a-propos",
    "/about",
    "/mentions-legales",
)


@dataclass
class ContactHit:
    value: str
    sources: set[str] = field(default_factory=set)


@dataclass
class PageContacts:
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    links: set[str] = field(default_factory=set)


@dataclass
class ExtractionResult:
    target_url: str
    pages_scanned: list[str] = field(default_factory=list)
    emails: dict[str, ContactHit] = field(default_factory=dict)
    phones: dict[str, ContactHit] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def add_email(self, email: str, source: str) -> None:
        key = email.lower()
        self.emails.setdefault(key, ContactHit(value=email, sources=set())).sources.add(source)

    def add_phone(self, phone: str, source: str) -> None:
        self.phones.setdefault(phone, ContactHit(value=phone, sources=set())).sources.add(source)

    def to_dict(self) -> dict[str, object]:
        return {
            "target_url": self.target_url,
            "pages_scanned": self.pages_scanned,
            "emails": [
                {"value": hit.value, "sources": sorted(hit.sources)}
                for hit in sorted(self.emails.values(), key=lambda item: item.value.lower())
            ],
            "phones": [
                {"value": hit.value, "sources": sorted(hit.sources)}
                for hit in sorted(self.phones.values(), key=lambda item: item.value)
            ],
            "errors": self.errors,
        }


class ContactHTMLParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.text_parts: list[str] = []
        self.emails: set[str] = set()
        self.phones: set[str] = set()
        self.links: set[str] = set()
        self._ignored_tag_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._ignored_tag_depth += 1
            return

        attr_map = {name.lower(): value or "" for name, value in attrs}
        href = attr_map.get("href")
        if tag == "a" and href:
            self._handle_href(href)

        for value in attr_map.values():
            self._extract_from_text(value)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._ignored_tag_depth:
            self._ignored_tag_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._ignored_tag_depth:
            return
        cleaned = data.strip()
        if cleaned:
            self.text_parts.append(cleaned)
            self._extract_from_text(cleaned)

    def _handle_href(self, href: str) -> None:
        href = html.unescape(href.strip())
        parsed = parse.urlparse(href)

        if parsed.scheme.lower() == "mailto":
            email = parsed.path.split("?", 1)[0]
            self.emails.update(extract_emails(email))
            return

        if parsed.scheme.lower() == "tel":
            phone = normalize_phone(parsed.path)
            if phone:
                self.phones.add(phone)
            return

        absolute_url = normalize_candidate_url(parse.urljoin(self.base_url, href))
        if absolute_url:
            self.links.add(absolute_url)

    def _extract_from_text(self, text: str) -> None:
        self.emails.update(extract_emails(text))
        self.phones.update(extract_phones(text))


def normalize_start_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("URL vide.")
    parsed = parse.urlparse(raw_url)
    if not parsed.scheme:
        raw_url = "https://" + raw_url
        parsed = parse.urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL invalide. Exemple: https://example.com")
    return normalize_candidate_url(raw_url) or raw_url


def normalize_candidate_url(raw_url: str) -> str | None:
    parsed = parse.urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    parsed = parsed._replace(fragment="")
    return parse.urlunparse(parsed)


def extract_emails(text: str) -> set[str]:
    return {match.group(0).strip(".,;:()[]{}<>").lower() for match in EMAIL_RE.finditer(text)}


def normalize_phone(raw_phone: str) -> str | None:
    raw_phone = html.unescape(raw_phone)
    digits = re.sub(r"\D", "", raw_phone)
    if not 7 <= len(digits) <= 15:
        return None

    value = re.sub(r"[^\d+]", " ", raw_phone)
    value = re.sub(r"\s+", " ", value).strip()
    value = value.replace("+ ", "+")
    if raw_phone.strip().startswith("+") and not value.startswith("+"):
        value = "+" + value
    return value


def extract_phones(text: str) -> set[str]:
    phones: set[str] = set()
    for match in PHONE_RE.finditer(text):
        phone = normalize_phone(match.group(0))
        if phone:
            phones.add(phone)
    return phones


def fetch_html(url: str, timeout: int = 10) -> str:
    headers = {
        "User-Agent": "CommercialContactAgent/1.0 (+https://example.com/contact-agent)",
        "Accept": "text/html,application/xhtml+xml",
    }
    req = request.Request(url, headers=headers)
    with request.urlopen(req, timeout=timeout) as response:
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
            raise ValueError(f"Contenu non HTML: {content_type or 'inconnu'}")
        encoding = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(encoding, errors="replace")


def parse_contacts(base_url: str, page_html: str) -> PageContacts:
    parser = ContactHTMLParser(base_url)
    parser.feed(page_html)
    return PageContacts(emails=parser.emails, phones=parser.phones, links=parser.links)


def is_same_site(base_url: str, candidate_url: str) -> bool:
    return parse.urlparse(base_url).netloc.lower() == parse.urlparse(candidate_url).netloc.lower()


def is_contact_candidate(url: str) -> bool:
    parsed = parse.urlparse(url)
    haystack = f"{parsed.path} {parsed.query}".lower()
    return any(keyword in haystack for keyword in CONTACT_KEYWORDS)


def common_contact_urls(start_url: str) -> Iterable[str]:
    parsed = parse.urlparse(start_url)
    root = parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    for path in COMMON_CONTACT_PATHS:
        yield parse.urljoin(root, path)


def extract_contacts(start_url: str, max_pages: int = 6, timeout: int = 10) -> ExtractionResult:
    normalized_start = normalize_start_url(start_url)
    result = ExtractionResult(target_url=normalized_start)
    queue: list[str] = [normalized_start, *common_contact_urls(normalized_start)]
    queued = set(queue)
    scanned: set[str] = set()

    while queue and len(scanned) < max_pages:
        current_url = queue.pop(0)
        if current_url in scanned:
            continue
        scanned.add(current_url)

        try:
            page_html = fetch_html(current_url, timeout=timeout)
        except (error.URLError, TimeoutError, ValueError, UnicodeDecodeError) as exc:
            result.errors[current_url] = str(exc)
            continue

        result.pages_scanned.append(current_url)
        contacts = parse_contacts(current_url, page_html)
        for email in contacts.emails:
            result.add_email(email, current_url)
        for phone in contacts.phones:
            result.add_phone(phone, current_url)

        for link in sorted(contacts.links):
            if (
                link not in queued
                and link not in scanned
                and is_same_site(normalized_start, link)
                and is_contact_candidate(link)
            ):
                queue.append(link)
                queued.add(link)

    return result


def print_human_result(result: ExtractionResult) -> None:
    print(f"URL cible: {result.target_url}")
    print(f"Pages analysees: {len(result.pages_scanned)}")
    for page in result.pages_scanned:
        print(f"  - {page}")

    print("\nEmails trouves:")
    if result.emails:
        for hit in sorted(result.emails.values(), key=lambda item: item.value.lower()):
            print(f"  - {hit.value} (sources: {', '.join(sorted(hit.sources))})")
    else:
        print("  Aucun email trouve.")

    print("\nTelephones trouves:")
    if result.phones:
        for hit in sorted(result.phones.values(), key=lambda item: item.value):
            print(f"  - {hit.value} (sources: {', '.join(sorted(hit.sources))})")
    else:
        print("  Aucun telephone trouve.")

    if result.errors:
        print("\nPages ignorees:")
        for page, reason in sorted(result.errors.items()):
            print(f"  - {page}: {reason}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agent commercial: recupere emails et telephones publics depuis une URL."
    )
    parser.add_argument("url", help="URL du site a analyser, ex: https://example.com")
    parser.add_argument("--max-pages", type=int, default=6, help="Nombre maximum de pages a analyser")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout HTTP en secondes")
    parser.add_argument("--json", action="store_true", help="Afficher le resultat en JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        result = extract_contacts(args.url, max_pages=args.max_pages, timeout=args.timeout)
    except ValueError as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print_human_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
