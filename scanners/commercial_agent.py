#!/usr/bin/env python3
"""
Agent commercial — extraction d'emails et numéros de téléphone depuis une URL.
Usage pédagogique : reconnaissance OSINT / collecte de contacts publics.
"""

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from termcolor import cprint

try:
    import phonenumbers
    from phonenumbers import PhoneNumberFormat

    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
}

EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

PHONE_PATTERN = re.compile(
    r"(?:"
    r"\+?\d{1,3}[\s.\-]?"
    r"(?:\(?\d{1,4}\)?[\s.\-]?)?"
    r"\d{2,4}[\s.\-]?"
    r"\d{2,4}[\s.\-]?"
    r"\d{2,4}[\s.\-]?"
    r"\d{0,4}"
    r")"
)

CONTACT_KEYWORDS = (
    "contact",
    "nous-contacter",
    "about",
    "a-propos",
    "apropos",
    "equipe",
    "team",
    "support",
    "help",
    "assistance",
)

FALSE_POSITIVE_EMAIL_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".css",
    ".js",
    ".woff",
    ".woff2",
)


@dataclass
class ContactResult:
    url: str
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    pages_scanned: list[str] = field(default_factory=list)
    error: Optional[str] = None


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def is_valid_email(email: str) -> bool:
    email = email.lower().strip()
    if any(email.endswith(suffix) for suffix in FALSE_POSITIVE_EMAIL_SUFFIXES):
        return False
    if email.count("@") != 1:
        return False
    local, domain = email.split("@", 1)
    if not local or not domain or "." not in domain:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    return True


def clean_phone(raw: str) -> str:
    cleaned = re.sub(r"\s+", " ", raw.strip())
    cleaned = re.sub(r"[^\d+\s().\-]", "", cleaned)
    return cleaned.strip(" .-")


def is_plausible_phone(phone: str) -> bool:
    digits = re.sub(r"\D", "", phone)
    if len(digits) < 8 or len(digits) > 15:
        return False
    if len(set(digits)) == 1:
        return False
    return True


def format_phone(phone: str, default_region: str = "FR") -> Optional[str]:
    phone = clean_phone(phone)
    if not is_plausible_phone(phone):
        return None

    if PHONENUMBERS_AVAILABLE:
        try:
            parsed = phonenumbers.parse(phone, default_region)
            if phonenumbers.is_valid_number(parsed):
                return phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
        except phonenumbers.NumberParseException:
            pass

    return phone if is_plausible_phone(phone) else None


def extract_emails_from_text(text: str) -> set[str]:
    found = set()
    for match in EMAIL_PATTERN.findall(text):
        email = match.lower()
        if is_valid_email(email):
            found.add(email)
    return found


def extract_phones_from_text(text: str, default_region: str = "FR") -> set[str]:
    found = set()
    for match in PHONE_PATTERN.findall(text):
        formatted = format_phone(match, default_region)
        if formatted:
            found.add(formatted)

    tel_links = re.findall(r"tel:([+\d\s().\-]+)", text, flags=re.IGNORECASE)
    for tel in tel_links:
        formatted = format_phone(tel, default_region)
        if formatted:
            found.add(formatted)

    return found


def extract_mailto_links(soup: BeautifulSoup) -> set[str]:
    emails = set()
    for link in soup.select('a[href^="mailto:"]'):
        href = link.get("href", "")
        email = href.replace("mailto:", "").split("?")[0].strip()
        if is_valid_email(email):
            emails.add(email.lower())
    return emails


def extract_tel_links(soup: BeautifulSoup, default_region: str = "FR") -> set[str]:
    phones = set()
    for link in soup.select('a[href^="tel:"]'):
        href = link.get("href", "")
        phone = href.replace("tel:", "").strip()
        formatted = format_phone(phone, default_region)
        if formatted:
            phones.add(formatted)
    return phones


def find_contact_links(soup: BeautifulSoup, base_url: str) -> list[str]:
    links = []
    seen = set()
    base_domain = urlparse(base_url).netloc

    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        text = anchor.get_text(" ", strip=True).lower()
        href_lower = href.lower()

        if not any(keyword in href_lower or keyword in text for keyword in CONTACT_KEYWORDS):
            continue

        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.netloc != base_domain:
            continue
        if absolute in seen:
            continue

        seen.add(absolute)
        links.append(absolute)

    return links[:5]


def fetch_page(url: str, timeout: int = 15) -> tuple[Optional[str], Optional[str]]:
    try:
        response = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return None, f"Type de contenu non HTML : {content_type}"
        return response.text, None
    except requests.RequestException as exc:
        return None, str(exc)


def extract_contacts_from_html(html: str, default_region: str = "FR") -> tuple[set[str], set[str]]:
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = soup.get_text(" ", strip=True)

    emails = extract_emails_from_text(text)
    emails.update(extract_mailto_links(soup))

    phones = extract_phones_from_text(text, default_region)
    phones.update(extract_tel_links(soup, default_region))

    return emails, phones


def scan_url(
    url: str,
    follow_contact_pages: bool = True,
    timeout: int = 15,
    default_region: str = "FR",
) -> ContactResult:
    url = normalize_url(url)
    result = ContactResult(url=url)

    cprint(f"[*] Analyse de {url}...", "cyan")

    html, error = fetch_page(url, timeout=timeout)
    if error:
        result.error = error
        cprint(f"[ERROR] {url} : {error}", "red")
        return result

    result.pages_scanned.append(url)
    emails, phones = extract_contacts_from_html(html, default_region)
    result.emails.extend(sorted(emails))
    result.phones.extend(sorted(phones))

    if follow_contact_pages:
        soup = BeautifulSoup(html, "html.parser")
        contact_links = find_contact_links(soup, url)

        for link in contact_links:
            if link in result.pages_scanned:
                continue
            cprint(f"[*] Page contact détectée : {link}", "yellow")
            sub_html, sub_error = fetch_page(link, timeout=timeout)
            if sub_error:
                cprint(f"[WARN] Impossible de charger {link} : {sub_error}", "yellow")
                continue

            result.pages_scanned.append(link)
            sub_emails, sub_phones = extract_contacts_from_html(sub_html, default_region)
            result.emails = sorted(set(result.emails) | sub_emails)
            result.phones = sorted(set(result.phones) | sub_phones)

    if result.emails:
        cprint(f"[+] {len(result.emails)} email(s) trouvé(s)", "green")
    else:
        cprint("[!] Aucun email trouvé", "yellow")

    if result.phones:
        cprint(f"[+] {len(result.phones)} téléphone(s) trouvé(s)", "green")
    else:
        cprint("[!] Aucun téléphone trouvé", "yellow")

    return result


def print_result(result: ContactResult) -> None:
    cprint(f"\n{'=' * 60}", "cyan")
    cprint(f"URL : {result.url}", "cyan")
    cprint(f"{'=' * 60}", "cyan")

    if result.error:
        cprint(f"Erreur : {result.error}", "red")
        return

    cprint(f"Pages analysées : {len(result.pages_scanned)}", "white")
    for page in result.pages_scanned:
        cprint(f"  - {page}", "white")

    cprint("\nEmails :", "green")
    if result.emails:
        for email in result.emails:
            cprint(f"  • {email}", "green")
    else:
        cprint("  (aucun)", "yellow")

    cprint("\nTéléphones :", "green")
    if result.phones:
        for phone in result.phones:
            cprint(f"  • {phone}", "green")
    else:
        cprint("  (aucun)", "yellow")


def save_results(results: list[ContactResult], output_path: str) -> None:
    data = [asdict(r) for r in results]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    cprint(f"[+] Résultats exportés vers {output_path}", "green")


def load_urls_from_file(path: str) -> list[str]:
    urls = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agent commercial — extrait emails et téléphones depuis une URL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python commercial_agent.py https://example.com
  python commercial_agent.py -u https://site1.com https://site2.com
  python commercial_agent.py -f urls.txt -o resultats.json
  python commercial_agent.py https://example.com --no-follow --region US
        """,
    )
    parser.add_argument("url", nargs="?", help="URL cible à analyser")
    parser.add_argument("-u", "--urls", nargs="+", help="Liste d'URLs à analyser")
    parser.add_argument("-f", "--file", help="Fichier contenant une URL par ligne")
    parser.add_argument("-o", "--output", help="Exporter les résultats en JSON")
    parser.add_argument(
        "--no-follow",
        action="store_true",
        help="Ne pas suivre les liens contact / à propos",
    )
    parser.add_argument(
        "--region",
        default="FR",
        help="Région par défaut pour la validation des numéros (défaut: FR)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Délai max par requête HTTP en secondes (défaut: 15)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    urls: list[str] = []
    if args.url:
        urls.append(args.url)
    if args.urls:
        urls.extend(args.urls)
    if args.file:
        urls.extend(load_urls_from_file(args.file))

    if not urls:
        parser.print_help()
        cprint("\n[ERROR] Fournissez au moins une URL.", "red")
        return 1

    cprint("[*] Agent commercial — extraction de contacts", "cyan", attrs=["bold"])
    if not PHONENUMBERS_AVAILABLE:
        cprint("[WARN] phonenumbers non installé — validation téléphone basique", "yellow")

    results: list[ContactResult] = []
    for url in urls:
        result = scan_url(
            url,
            follow_contact_pages=not args.no_follow,
            timeout=args.timeout,
            default_region=args.region,
        )
        results.append(result)
        print_result(result)

    if args.output:
        save_results(results, args.output)

    has_error = any(r.error for r in results)
    has_contacts = any(r.emails or r.phones for r in results)
    return 0 if has_contacts or not has_error else 1


if __name__ == "__main__":
    sys.exit(main())
