#!/usr/bin/env python3
"""
Agent Commercial — Extracteur de contacts (emails & telephones) depuis des URLs.

Donnez une ou plusieurs URLs a l'outil : il telecharge les pages, explore
optionnellement les pages de contact du meme domaine, puis extrait automatiquement
les adresses email et numeros de telephone.

Exemples :
    python3 agent_commercial.py https://exemple.com
    python3 agent_commercial.py https://a.com https://b.com --crawl --json resultats.json
    python3 agent_commercial.py -f liste_urls.txt --csv contacts.csv --region NE

Usage pedagogique / prospection legitime uniquement. Respectez les conditions
d'utilisation des sites, le fichier robots.txt et la reglementation (RGPD, etc.).
"""

import argparse
import csv
import json
import re
import sys
import time
from urllib.parse import urljoin, urlparse

import requests

try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:  # pragma: no cover
    _HAS_BS4 = False

try:
    import phonenumbers
    _HAS_PHONENUMBERS = True
except ImportError:  # pragma: no cover
    _HAS_PHONENUMBERS = False


DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
}

# Regex email : tolerante mais evite les extensions de fichiers courantes.
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}"
)

# Extensions souvent capturees par erreur comme "email" (ex: logo@2x.png).
_BAD_EMAIL_ENDINGS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
    ".css", ".js", ".ico", ".pdf", ".mp4", ".woff", ".ttf",
)

# Regex telephone generique (fallback quand phonenumbers est absent).
PHONE_REGEX = re.compile(
    r"(?<![\w.])"
    r"(\+?\d[\d\s().\-]{6,17}\d)"
    r"(?![\w])"
)

# Motifs d'URL suggerant une page de contact (pour le mode --crawl).
CONTACT_HINTS = (
    "contact", "contactez", "about", "a-propos", "apropos",
    "nous", "team", "equipe", "mentions", "legal", "support",
    "impressum", "kontakt",
)


def clean_text(html):
    """Retourne le texte visible + conserve le HTML pour les liens mailto/tel."""
    if _HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        return soup
    return None


def extract_emails(html, soup):
    """Extrait les emails depuis le texte brut et les liens mailto:."""
    emails = set()

    # 1) Liens mailto:
    if soup is not None:
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.lower().startswith("mailto:"):
                addr = href[7:].split("?")[0].strip()
                if addr:
                    emails.add(addr.lower())

    # 2) Texte brut (deobfuscation basique de [at]/[dot]).
    text = html
    text = re.sub(r"\s*\[\s*at\s*\]\s*|\s*\(\s*at\s*\)\s*", "@", text, flags=re.I)
    text = re.sub(r"\s*\[\s*dot\s*\]\s*|\s*\(\s*dot\s*\)\s*", ".", text, flags=re.I)

    for match in EMAIL_REGEX.findall(text):
        low = match.lower()
        if low.endswith(_BAD_EMAIL_ENDINGS):
            continue
        emails.add(low)

    return emails


def _normalize_phone(raw, region):
    """Valide/normalise un numero via phonenumbers si dispo, sinon nettoyage simple."""
    if _HAS_PHONENUMBERS:
        try:
            num = phonenumbers.parse(raw, region)
            if phonenumbers.is_valid_number(num):
                return phonenumbers.format_number(
                    num, phonenumbers.PhoneNumberFormat.E164
                )
        except phonenumbers.NumberParseException:
            return None
        return None
    # Fallback : garder les numeros ayant assez de chiffres.
    digits = re.sub(r"\D", "", raw)
    if 8 <= len(digits) <= 15:
        return raw.strip()
    return None


def extract_phones(html, soup, region):
    """Extrait les telephones depuis les liens tel: et le texte."""
    phones = set()

    # 1) Liens tel:
    if soup is not None:
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.lower().startswith("tel:"):
                raw = href[4:].strip()
                norm = _normalize_phone(raw, region)
                if norm:
                    phones.add(norm)

    # 2) Texte brut.
    if _HAS_PHONENUMBERS:
        for match in phonenumbers.PhoneNumberMatcher(html, region):
            if phonenumbers.is_valid_number(match.number):
                phones.add(
                    phonenumbers.format_number(
                        match.number, phonenumbers.PhoneNumberFormat.E164
                    )
                )
    else:
        for match in PHONE_REGEX.findall(html):
            norm = _normalize_phone(match, region)
            if norm:
                phones.add(norm)

    return phones


def fetch(url, timeout, session):
    """Telecharge une URL, renvoie (html, status) ou (None, erreur)."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype and "text" not in ctype and ctype:
            return None, f"type non-HTML ({ctype})"
        resp.encoding = resp.encoding or resp.apparent_encoding
        return resp.text, resp.status_code
    except requests.RequestException as exc:
        return None, str(exc)


def find_contact_links(base_url, soup, max_links):
    """Trouve des liens internes suggerant des pages de contact."""
    if soup is None:
        return []
    base_domain = urlparse(base_url).netloc
    found = []
    seen = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if parsed.netloc != base_domain:
            continue
        haystack = (href + " " + a.get_text(" ")).lower()
        if any(h in haystack for h in CONTACT_HINTS):
            clean = full.split("#")[0]
            if clean not in seen and clean != base_url:
                seen.add(clean)
                found.append(clean)
        if len(found) >= max_links:
            break
    return found


def process_url(url, args, session):
    """Traite une URL (+ ses pages de contact si --crawl) et renvoie un dict resultat."""
    result = {"url": url, "emails": set(), "phones": set(), "errors": []}

    html, status = fetch(url, args.timeout, session)
    if html is None:
        result["errors"].append(f"{url} : {status}")
        return result

    soup = clean_text(html)
    result["emails"] |= extract_emails(html, soup)
    result["phones"] |= extract_phones(html, soup, args.region)

    if args.crawl:
        for link in find_contact_links(url, soup, args.max_pages):
            time.sleep(args.delay)
            sub_html, sub_status = fetch(link, args.timeout, session)
            if sub_html is None:
                result["errors"].append(f"{link} : {sub_status}")
                continue
            sub_soup = clean_text(sub_html)
            result["emails"] |= extract_emails(sub_html, sub_soup)
            result["phones"] |= extract_phones(sub_html, sub_soup, args.region)

    return result


def load_urls(args):
    urls = list(args.urls)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    # Normalise : ajoute https:// si le schema manque.
    normalized = []
    for u in urls:
        if not re.match(r"^https?://", u, re.I):
            u = "https://" + u
        normalized.append(u)
    # Dedup en gardant l'ordre.
    seen = set()
    out = []
    for u in normalized:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def print_report(results):
    for r in results:
        print("\n" + "=" * 60)
        print(f"[URL] {r['url']}")
        print("-" * 60)
        if r["emails"]:
            print("  Emails :")
            for e in sorted(r["emails"]):
                print(f"    - {e}")
        else:
            print("  Emails : (aucun)")
        if r["phones"]:
            print("  Telephones :")
            for p in sorted(r["phones"]):
                print(f"    - {p}")
        else:
            print("  Telephones : (aucun)")
        if r["errors"]:
            print("  Erreurs :")
            for err in r["errors"]:
                print(f"    ! {err}")
    print("\n" + "=" * 60)
    total_mail = sum(len(r["emails"]) for r in results)
    total_tel = sum(len(r["phones"]) for r in results)
    print(f"Total : {total_mail} email(s), {total_tel} telephone(s) "
          f"sur {len(results)} URL(s).")


def export_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "type", "valeur"])
        for r in results:
            for e in sorted(r["emails"]):
                writer.writerow([r["url"], "email", e])
            for p in sorted(r["phones"]):
                writer.writerow([r["url"], "telephone", p])
    print(f"[+] CSV ecrit : {path}")


def export_json(results, path):
    data = [
        {
            "url": r["url"],
            "emails": sorted(r["emails"]),
            "phones": sorted(r["phones"]),
            "errors": r["errors"],
        }
        for r in results
    ]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    print(f"[+] JSON ecrit : {path}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Agent Commercial : extrait emails & telephones depuis des URLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("urls", nargs="*", help="Une ou plusieurs URLs a analyser.")
    parser.add_argument("-f", "--file",
                        help="Fichier texte contenant une URL par ligne.")
    parser.add_argument("--crawl", action="store_true",
                        help="Explore aussi les pages de contact du meme domaine.")
    parser.add_argument("--max-pages", type=int, default=5,
                        help="Nb max de pages de contact a explorer par site (defaut 5).")
    parser.add_argument("--region", default="FR",
                        help="Region par defaut pour les telephones (ex: FR, NE, US).")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Timeout HTTP en secondes (defaut 15).")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delai entre requetes en secondes (defaut 0.5).")
    parser.add_argument("--csv", help="Chemin d'export CSV.")
    parser.add_argument("--json", dest="json_path", help="Chemin d'export JSON.")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    if not _HAS_PHONENUMBERS:
        print("[!] Module 'phonenumbers' absent : detection telephone en mode basique.",
              file=sys.stderr)
    if not _HAS_BS4:
        print("[!] Module 'bs4' absent : liens mailto/tel et crawl desactives.",
              file=sys.stderr)

    urls = load_urls(args)
    if not urls:
        build_parser().print_help()
        return 1

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    results = []
    for i, url in enumerate(urls):
        print(f"[*] ({i + 1}/{len(urls)}) Analyse de {url} ...", file=sys.stderr)
        results.append(process_url(url, args, session))
        if i < len(urls) - 1:
            time.sleep(args.delay)

    print_report(results)

    if args.csv:
        export_csv(results, args.csv)
    if args.json_path:
        export_json(results, args.json_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
