#!/usr/bin/env python3
"""Agent commercial simple pour extraire emails et telephones depuis une URL."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urljoin, urlparse
from urllib.request import Request, urlopen


DEFAULT_USER_AGENT = "NigerCertifyContactAgent/1.0"
CONTACT_LINK_KEYWORDS = (
    "contact",
    "contacts",
    "about",
    "a-propos",
    "apropos",
    "nous-contacter",
    "contactez",
)
EMAIL_RE = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b",
    re.IGNORECASE,
)
PHONE_RE = re.compile(
    r"(?<![\w])(?:\+?\d[\d\s().-]{6,}\d)(?![\w])",
)


@dataclass
class ContactResult:
    """Contacts trouves sur une page."""

    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    sources: dict[str, set[str]] = field(default_factory=dict)

    def add_email(self, email: str, source: str) -> None:
        email = email.strip().lower().strip(".,;:()[]{}<>")
        if EMAIL_RE.fullmatch(email):
            self.emails.add(email)
            self.sources.setdefault(email, set()).add(source)

    def add_phone(self, phone: str, source: str) -> None:
        normalized = normalize_phone(phone)
        if normalized:
            self.phones.add(normalized)
            self.sources.setdefault(normalized, set()).add(source)

    def merge(self, other: "ContactResult") -> None:
        for email in other.emails:
            self.emails.add(email)
        for phone in other.phones:
            self.phones.add(phone)
        for contact, sources in other.sources.items():
            self.sources.setdefault(contact, set()).update(sources)

    def as_dict(self) -> dict[str, object]:
        return {
            "emails": sorted(self.emails),
            "telephones": sorted(self.phones),
            "sources": {
                contact: sorted(sources)
                for contact, sources in sorted(self.sources.items())
            },
        }


class ContactHTMLParser(HTMLParser):
    """Collecte le texte visible, les liens et les attributs utiles."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self.contact_values: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {name.lower(): value or "" for name, value in attrs}
        href = attrs_dict.get("href")
        if href:
            self.links.append(href)
            if href.lower().startswith(("mailto:", "tel:")):
                self.contact_values.append(unquote(href))

        for attr in ("content", "aria-label", "title", "alt", "data-email", "data-phone"):
            value = attrs_dict.get(attr)
            if value:
                self.contact_values.append(value)

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.text_parts.append(data)

    @property
    def searchable_text(self) -> str:
        return " ".join([*self.text_parts, *self.contact_values])


def fetch_url(url: str, timeout: float = 10, max_bytes: int = 1_000_000) -> str:
    """Telecharge une page HTTP(S) et retourne son contenu texte."""

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Seules les URL http:// et https:// sont acceptees.")

    request = Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    with urlopen(request, timeout=timeout) as response:
        content_type = response.headers.get("Content-Type", "")
        if content_type and "text/html" not in content_type and "text/plain" not in content_type:
            raise ValueError(f"Type de contenu non supporte: {content_type}")

        raw = response.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError(f"Page trop volumineuse: limite de {max_bytes} octets depassee.")

        charset = response.headers.get_content_charset() or "utf-8"
        return raw.decode(charset, errors="replace")


def parse_html(html: str) -> ContactHTMLParser:
    parser = ContactHTMLParser()
    parser.feed(html)
    return parser


def normalize_phone(value: str) -> str | None:
    value = unquote(value)
    value = re.sub(r"^tel:\s*", "", value, flags=re.IGNORECASE).strip()
    value = value.strip(".,;:[]{}<>")
    has_international_prefix = value.startswith("+")

    digits = re.sub(r"\D", "", value)
    if not 7 <= len(digits) <= 15:
        return None

    if sum(char.isdigit() for char in value) < 7:
        return None

    return f"+{digits}" if has_international_prefix else digits


def deobfuscate_emails(text: str) -> str:
    replacements = [
        (r"\s*(?:\[|\()\s*at\s*(?:\]|\))\s*", "@"),
        (r"\s+(?:at|AT)\s+", "@"),
        (r"\s*(?:\[|\()\s*dot\s*(?:\]|\))\s*", "."),
        (r"\s+(?:dot|DOT)\s+", "."),
    ]
    result = text
    for pattern, replacement in replacements:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


def extract_contacts_from_text(text: str, source: str) -> ContactResult:
    result = ContactResult()
    searchable = deobfuscate_emails(text)

    for email in EMAIL_RE.findall(searchable):
        result.add_email(email, source)

    for phone in PHONE_RE.findall(searchable):
        result.add_phone(phone, source)

    return result


def discover_contact_links(base_url: str, links: Iterable[str], limit: int) -> list[str]:
    base_domain = urlparse(base_url).netloc.lower()
    candidates: list[str] = []

    for link in links:
        normalized = urljoin(base_url, link)
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"}:
            continue
        if parsed.netloc.lower() != base_domain:
            continue

        searchable = f"{parsed.path} {parsed.query}".lower()
        if any(keyword in searchable for keyword in CONTACT_LINK_KEYWORDS):
            clean_url = parsed._replace(fragment="").geturl()
            if clean_url not in candidates:
                candidates.append(clean_url)

        if len(candidates) >= limit:
            break

    return candidates


def analyze_page(url: str, timeout: float, max_bytes: int) -> tuple[ContactResult, list[str]]:
    html = fetch_url(url, timeout=timeout, max_bytes=max_bytes)
    parser = parse_html(html)
    contacts = extract_contacts_from_text(parser.searchable_text, url)
    return contacts, parser.links


def analyze_url(
    url: str,
    timeout: float = 10,
    max_bytes: int = 1_000_000,
    follow_contact_links: int = 3,
) -> ContactResult:
    """Analyse l'URL donnee et quelques pages internes de contact."""

    final_result, links = analyze_page(url, timeout=timeout, max_bytes=max_bytes)
    for contact_url in discover_contact_links(url, links, follow_contact_links):
        try:
            page_result, _ = analyze_page(contact_url, timeout=timeout, max_bytes=max_bytes)
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            print(f"[avertissement] Impossible d'analyser {contact_url}: {exc}", file=sys.stderr)
            continue
        final_result.merge(page_result)

    return final_result


def format_text(result: ContactResult) -> str:
    lines = ["Contacts trouves:"]
    lines.append("Emails:")
    emails = sorted(result.emails)
    if emails:
        lines.extend(f"  - {email}" for email in emails)
    else:
        lines.append("  Aucun")

    lines.append("Telephones:")
    phones = sorted(result.phones)
    if phones:
        lines.extend(f"  - {phone}" for phone in phones)
    else:
        lines.append("  Aucun")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agent commercial: extrait emails et numeros de telephone depuis une URL publique.",
    )
    parser.add_argument("url", help="URL publique a analyser, par exemple https://example.com")
    parser.add_argument("--json", action="store_true", help="Afficher le resultat au format JSON")
    parser.add_argument(
        "--follow-contact-links",
        type=int,
        default=3,
        help="Nombre maximum de liens internes de contact/a-propos a analyser (defaut: 3)",
    )
    parser.add_argument("--timeout", type=float, default=10, help="Timeout HTTP en secondes")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=1_000_000,
        help="Taille maximum d'une page a lire en octets",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = analyze_url(
            args.url,
            timeout=args.timeout,
            max_bytes=args.max_bytes,
            follow_contact_links=max(0, args.follow_contact_links),
        )
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.as_dict(), indent=2, ensure_ascii=False))
    else:
        print(format_text(result))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
