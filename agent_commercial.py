#!/usr/bin/env python3
"""Agent commercial CLI pour extraire emails et telephones depuis une URL."""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from typing import Iterable
from urllib.error import URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.IGNORECASE)
OBFUSCATED_EMAIL_PATTERN = re.compile(
    r"([A-Z0-9._%+\-]+)\s*(?:\[at\]|\(at\)|\sat\s)\s*([A-Z0-9.\-]+)\s*(?:\[dot\]|\(dot\)|\sdot\s)\s*([A-Z]{2,})",
    re.IGNORECASE,
)
PHONE_PATTERN = re.compile(r"(?:\+?\d[\d\s().\-]{6,}\d)")
HREF_PATTERN = re.compile(r"""href\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)

CONTACT_KEYWORDS = (
    "contact",
    "contactez",
    "about",
    "support",
    "sales",
    "customer",
    "service-client",
)
COMMON_CONTACT_PATHS = (
    "/contact",
    "/contact-us",
    "/contactez-nous",
    "/support",
    "/about/contact",
)


def normalize_input_url(url: str) -> str:
    candidate = url.strip()
    if not candidate:
        raise ValueError("URL vide.")
    if not urlparse(candidate).scheme:
        candidate = f"https://{candidate}"
    return normalize_url(candidate)


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    clean_path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, clean_path, "", parsed.query, ""))


def fetch_page(url: str, timeout: int = 10) -> str:
    request = Request(url, headers={"User-Agent": "CommercialAgent/1.0"})
    with urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")


def html_to_text(content: str) -> str:
    without_scripts = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", content)
    without_tags = re.sub(r"(?s)<[^>]+>", " ", without_scripts)
    unescaped = html.unescape(without_tags)
    return re.sub(r"\s+", " ", unescaped).strip()


def extract_emails(raw_content: str) -> list[str]:
    text_content = html_to_text(raw_content)
    emails = {match.lower() for match in EMAIL_PATTERN.findall(raw_content + " " + text_content)}
    for local_part, domain, extension in OBFUSCATED_EMAIL_PATTERN.findall(text_content):
        emails.add(f"{local_part}@{domain}.{extension}".lower())
    return sorted(emails)


def normalize_phone(candidate: str) -> str | None:
    has_plus = candidate.strip().startswith("+")
    digits = re.sub(r"\D", "", candidate)
    if not 9 <= len(digits) <= 15:
        return None
    return f"+{digits}" if has_plus else digits


def extract_phones(raw_content: str) -> list[str]:
    text_content = html_to_text(raw_content)
    phones = set()
    for match in PHONE_PATTERN.findall(raw_content + " " + text_content):
        normalized = normalize_phone(match)
        if normalized:
            phones.add(normalized)
    return sorted(phones)


def extract_links(raw_content: str, base_url: str) -> set[str]:
    base_domain = urlparse(base_url).netloc
    links = set()
    for href in HREF_PATTERN.findall(raw_content):
        absolute = normalize_url(urljoin(base_url, href))
        parsed = urlparse(absolute)
        if parsed.scheme in {"http", "https"} and parsed.netloc == base_domain:
            links.add(absolute)
    return links


def looks_like_contact_url(url: str) -> bool:
    target = f"{urlparse(url).path} {urlparse(url).query}".lower()
    return any(keyword in target for keyword in CONTACT_KEYWORDS)


def build_candidate_urls(start_url: str, raw_content: str) -> list[str]:
    parsed = urlparse(start_url)
    base_root = f"{parsed.scheme}://{parsed.netloc}"
    candidates = [start_url]
    from_links = sorted(link for link in extract_links(raw_content, start_url) if looks_like_contact_url(link))
    for link in from_links:
        if link not in candidates:
            candidates.append(link)
    for path in COMMON_CONTACT_PATHS:
        guess = normalize_url(urljoin(base_root, path))
        if guess not in candidates:
            candidates.append(guess)
    return candidates


def collect_contacts(url: str, max_pages: int = 6, timeout: int = 10) -> dict[str, Iterable[str]]:
    start_url = normalize_input_url(url)
    first_page = fetch_page(start_url, timeout=timeout)
    pages_to_scan = build_candidate_urls(start_url, first_page)[:max_pages]

    emails: set[str] = set()
    phones: set[str] = set()
    scanned_pages: list[str] = []

    for page_url in pages_to_scan:
        try:
            raw_content = fetch_page(page_url, timeout=timeout)
        except URLError:
            continue
        except TimeoutError:
            continue
        scanned_pages.append(page_url)
        emails.update(extract_emails(raw_content))
        phones.update(extract_phones(raw_content))

    return {
        "source_url": start_url,
        "scanned_pages": scanned_pages,
        "emails": sorted(emails),
        "phones": sorted(phones),
    }


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agent commercial: extrait les emails et telephones disponibles sur une URL."
    )
    parser.add_argument("url", help="URL du site a analyser")
    parser.add_argument("--max-pages", type=int, default=6, help="Nombre max de pages a scanner (defaut: 6)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout reseau en secondes (defaut: 10)")
    parser.add_argument("--json", action="store_true", help="Affiche le resultat au format JSON")
    return parser


def main() -> int:
    parser = build_cli_parser()
    args = parser.parse_args()
    try:
        results = collect_contacts(args.url, max_pages=args.max_pages, timeout=args.timeout)
    except Exception as error:  # pragma: no cover - securite CLI
        print(f"[ERREUR] Impossible d'analyser l'URL: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return 0

    print("=== Agent Commercial: resultats ===")
    print(f"URL source : {results['source_url']}")
    print("Pages scannees :")
    for page in results["scanned_pages"]:
        print(f" - {page}")
    print("Emails :")
    for email in results["emails"] or ["Aucun email detecte"]:
        print(f" - {email}")
    print("Telephones :")
    for phone in results["phones"] or ["Aucun telephone detecte"]:
        print(f" - {phone}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
