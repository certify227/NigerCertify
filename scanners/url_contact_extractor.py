#!/usr/bin/env python3
import argparse
import json
import re
import sys
from collections import deque
from html import unescape
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Set, Tuple
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


EMAIL_PATTERN = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
PHONE_PATTERN = re.compile(r"(?:(?:\+|00)?\d[\d\s().-]{6,}\d)")
PRIORITY_KEYWORDS = ("contact", "contacts", "about", "team", "support", "sales")


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []
        self.visible_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple]) -> None:
        if tag != "a":
            return
        attributes = dict(attrs)
        href = attributes.get("href")
        if href:
            self.links.append(href.strip())

    def handle_data(self, data: str) -> None:
        chunk = data.strip()
        if chunk:
            self.visible_text.append(chunk)


def fetch_html(url: str, timeout: int) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (compatible; ContactExtractor/1.0; +https://example.local)"
            )
        },
    )
    with urlopen(request, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")


def normalize_email(value: str) -> str:
    return value.strip(" ,;:()[]{}<>").lower()


def normalize_phone(value: str) -> str:
    cleaned = re.sub(r"(?:ext\.?|poste)\s*\d+$", "", value, flags=re.IGNORECASE).strip()
    had_plus = cleaned.startswith("+")
    digits = re.sub(r"\D", "", cleaned)
    if cleaned.startswith("00"):
        return f"+{digits[2:]}"
    if had_plus:
        return f"+{digits}"
    return digits


def extract_emails(text: str) -> Set[str]:
    return {
        normalize_email(match.group(0))
        for match in EMAIL_PATTERN.finditer(unescape(text))
        if normalize_email(match.group(0))
    }


def extract_phones(text: str) -> Set[str]:
    phones: Set[str] = set()
    for match in PHONE_PATTERN.finditer(unescape(text)):
        raw_value = match.group(0)
        normalized = normalize_phone(raw_value)
        digit_count = len(re.sub(r"\D", "", normalized))
        if 8 <= digit_count <= 15:
            phones.add(normalized)
    return phones


def same_host(base_url: str, candidate_url: str) -> bool:
    base = urlparse(base_url)
    candidate = urlparse(candidate_url)
    return base.netloc == candidate.netloc


def score_link(link: str) -> Tuple[int, str]:
    lowered = link.lower()
    keyword_score = 0 if any(keyword in lowered for keyword in PRIORITY_KEYWORDS) else 1
    return (keyword_score, lowered)


def collect_candidate_links(base_url: str, links: Iterable[str]) -> List[str]:
    candidates: Set[str] = set()
    for link in links:
        if link.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        absolute = urljoin(base_url, link)
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            continue
        if not same_host(base_url, absolute):
            continue
        normalized = parsed._replace(fragment="", query=parsed.query).geturl()
        candidates.add(normalized)
    return sorted(candidates, key=score_link)


def add_sources(store: Dict[str, Set[str]], values: Iterable[str], source_url: str) -> None:
    for value in values:
        if value:
            store.setdefault(value, set()).add(source_url)


def extract_mailto_value(link: str) -> str:
    return normalize_email(link.split(":", 1)[1].split("?", 1)[0])


def extract_tel_value(link: str) -> str:
    raw = link.split(":", 1)[1].split("?", 1)[0].split(";", 1)[0]
    return normalize_phone(raw)


def crawl_contacts(start_url: str, max_pages: int, timeout: int) -> Dict[str, object]:
    pending = deque([start_url])
    visited: List[str] = []
    seen: Set[str] = set()
    email_sources: Dict[str, Set[str]] = {}
    phone_sources: Dict[str, Set[str]] = {}
    errors: List[str] = []

    while pending and len(visited) < max_pages:
        current_url = pending.popleft()
        if current_url in seen:
            continue
        seen.add(current_url)

        try:
            html = fetch_html(current_url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{current_url}: {exc}")
            continue

        parser = LinkParser()
        parser.feed(html)

        combined_text = " ".join(parser.visible_text) + "\n" + html
        add_sources(email_sources, extract_emails(combined_text), current_url)
        add_sources(phone_sources, extract_phones(combined_text), current_url)

        for link in parser.links:
            if link.lower().startswith("mailto:"):
                add_sources(
                    email_sources,
                    [extract_mailto_value(link)],
                    current_url,
                )
            elif link.lower().startswith("tel:"):
                add_sources(
                    phone_sources,
                    [extract_tel_value(link)],
                    current_url,
                )

        for next_link in collect_candidate_links(start_url, parser.links):
            if next_link not in seen and next_link not in pending and len(seen) + len(pending) < max_pages * 3:
                pending.append(next_link)

        visited.append(current_url)

    return {
        "target_url": start_url,
        "pages_scanned": visited,
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


def print_human_readable(result: Dict[str, object]) -> None:
    print(f"URL cible : {result['target_url']}")
    print(f"Pages analysees : {len(result['pages_scanned'])}")

    emails = result["emails"]
    phones = result["phones"]

    if emails:
        print("\nEmails trouves :")
        for item in emails:
            print(f"- {item['value']} ({', '.join(item['sources'])})")
    else:
        print("\nEmails trouves : aucun")

    if phones:
        print("\nTelephones trouves :")
        for item in phones:
            print(f"- {item['value']} ({', '.join(item['sources'])})")
    else:
        print("\nTelephones trouves : aucun")

    if result["errors"]:
        print("\nErreurs :")
        for error in result["errors"]:
            print(f"- {error}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recupere les emails et numeros de telephone publics depuis une URL."
    )
    parser.add_argument("url", help="URL de depart a analyser")
    parser.add_argument(
        "--max-pages",
        type=int,
        default=5,
        help="Nombre maximum de pages a visiter sur le meme domaine (defaut: 5)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout HTTP en secondes (defaut: 10)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Affiche le resultat en JSON",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.max_pages < 1:
        print("--max-pages doit etre superieur ou egal a 1", file=sys.stderr)
        return 2

    result = crawl_contacts(args.url, args.max_pages, args.timeout)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=True))
    else:
        print_human_readable(result)

    if not result["pages_scanned"] and result["errors"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
