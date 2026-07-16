#!/usr/bin/env python3
"""Agent commercial - Extracteur de contacts (email + telephone) depuis des URLs.

Donne une (ou plusieurs) URL(s) et l'outil parcourt le site pour recuperer
les adresses email et numeros de telephone publiquement affiches.

Usage rapide :
    python3 contact_scraper.py https://exemple.com
    python3 contact_scraper.py https://a.com https://b.com --json resultats.json
    python3 contact_scraper.py --input urls.txt --csv leads.csv --crawl

Usage pedagogique / prospection legitime uniquement. Respectez le fichier
robots.txt, les CGU des sites et la reglementation en vigueur (RGPD).
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from urllib.parse import urljoin, urlparse
from urllib import robotparser

import requests
from bs4 import BeautifulSoup

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; AgentCommercialBot/1.0; +contact-scraper)"
    ),
    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
}

# --- Expressions regulieres -------------------------------------------------

# Email : robuste sans etre trop permissif.
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Telephone : formats internationaux et locaux courants.
# Accepte +, indicatifs, espaces, points, tirets, parentheses.
PHONE_RE = re.compile(
    r"""(?<![\w.])(
        (?:\+?\d{1,3}[\s.\-]?)?        # indicatif international optionnel
        (?:\(?\d{1,4}\)?[\s.\-]?)      # premier groupe / prefixe
        (?:\d[\s.\-]?){5,12}\d         # reste du numero
    )(?![\w])""",
    re.VERBOSE,
)

# Mots parasites qui ressemblent a des emails mais n'en sont pas.
IMAGE_LIKE_RE = re.compile(r"\.(png|jpe?g|gif|svg|webp|css|js)$", re.IGNORECASE)

# Pages a visiter en priorite lors d'un crawl leger.
CONTACT_HINTS = (
    "contact", "contacts", "nous-contacter", "nous-joindre", "mentions",
    "mentions-legales", "legal", "about", "a-propos", "apropos",
    "impressum", "support", "aide", "help", "team", "equipe",
)


@dataclass
class ContactResult:
    url: str
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    pages_visitees: list[str] = field(default_factory=list)
    erreur: str | None = None


# --- Utilitaires -----------------------------------------------------------

def normaliser_url(url: str) -> str:
    """Ajoute un schema http(s) si absent."""
    url = url.strip()
    if not url:
        return url
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url


def est_email_valide(email: str) -> bool:
    email = email.lower()
    if IMAGE_LIKE_RE.search(email):
        return False
    # Domaines de placeholders frequents.
    if any(bad in email for bad in ("example.com", "domain.com", "email.com",
                                    "sentry.io", "wixpress.com", "@2x")):
        return False
    return True


# Dates du type 2024-01-01, 01/01/2024, 1.1.24 -> a ne pas prendre pour un tel.
DATE_LIKE_RE = re.compile(
    r"^\s*(?:"
    r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}"   # AAAA-MM-JJ
    r"|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}"  # JJ/MM/AAAA
    r")\s*$"
)


# Plage d'annees type "2001-2026" (copyright) a ne pas prendre pour un tel.
YEAR_RANGE_RE = re.compile(r"^\s*(19|20)\d{2}\s*[-/ ]\s*(19|20)\d{2}\s*$")


def nettoyer_telephone(brut: str, strict: bool = True) -> str | None:
    """Normalise un numero et rejette les faux positifs (dates, prix, ids...).

    ``strict`` s'applique au texte libre (moins fiable). Les liens ``tel:``
    utilisent ``strict=False`` car la source est explicite.
    """
    brut = brut.strip()
    if DATE_LIKE_RE.match(brut) or YEAR_RANGE_RE.match(brut):
        return None

    plus = brut.lstrip().startswith("+")
    a_separateur = bool(re.search(r"[\s.\-()]", brut))
    chiffres = re.sub(r"\D", "", brut)

    # Un vrai numero a en general entre 7 et 15 chiffres.
    if not (7 <= len(chiffres) <= 15):
        return None
    # Rejette les suites triviales (une seule valeur repetee).
    if len(set(chiffres)) <= 1:
        return None

    if strict:
        if not plus and not a_separateur:
            # Suite de chiffres collee sans indicatif ni separateur :
            # on n'accepte que les longueurs nationales usuelles (10 ou 11).
            if len(chiffres) not in (10, 11):
                return None
        else:
            # Numeros ecrits avec separateurs : verifie un groupage plausible.
            groupes = [g for g in re.split(r"[\s.\-()]+", brut) if g]
            # Un vrai numero depasse rarement 6 groupes.
            if len(groupes) > 6:
                return None
            # Ex. suite "0 1 1 2 3 5..." : trop de groupes d'un seul chiffre.
            mono = sum(1 for g in groupes if len(g) == 1)
            if len(groupes) >= 4 and mono > len(groupes) / 2:
                return None

    return ("+" if plus else "") + chiffres


def extraire_depuis_texte(texte: str) -> tuple[set[str], set[str]]:
    emails = {e for e in EMAIL_RE.findall(texte) if est_email_valide(e)}
    phones = set()
    for match in PHONE_RE.findall(texte):
        num = nettoyer_telephone(match)
        if num:
            phones.add(num)
    return emails, phones


def extraire_depuis_html(html: str, base_url: str) -> tuple[set[str], set[str], list[str]]:
    """Retourne (emails, phones, liens_internes) depuis une page HTML."""
    soup = BeautifulSoup(html, "lxml")

    # Supprime scripts/styles pour du texte propre.
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    emails: set[str] = set()
    phones: set[str] = set()

    # 1) Liens mailto: / tel: (source la plus fiable).
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        low = href.lower()
        if low.startswith("mailto:"):
            addr = href[7:].split("?")[0].strip()
            if addr and est_email_valide(addr):
                emails.add(addr)
        elif low.startswith("tel:"):
            num = nettoyer_telephone(href[4:], strict=False)
            if num:
                phones.add(num)

    # 2) Texte visible.
    texte = soup.get_text(separator=" ")
    e2, p2 = extraire_depuis_texte(texte)
    emails |= e2
    phones |= p2

    # 3) Liens internes utiles pour un eventuel crawl.
    liens: list[str] = []
    domaine = urlparse(base_url).netloc
    for a in soup.find_all("a", href=True):
        lien = urljoin(base_url, a["href"])
        if urlparse(lien).netloc == domaine:
            liens.append(lien.split("#")[0])

    return emails, phones, liens


def lien_est_contact(lien: str) -> bool:
    low = lien.lower()
    return any(h in low for h in CONTACT_HINTS)


def peut_visiter(rp: robotparser.RobotFileParser | None, url: str, ua: str) -> bool:
    if rp is None:
        return True
    try:
        return rp.can_fetch(ua, url)
    except Exception:
        return True


def charger_robots(base_url: str, session: requests.Session) -> robotparser.RobotFileParser | None:
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = robotparser.RobotFileParser()
    try:
        resp = session.get(robots_url, timeout=10)
        if resp.status_code == 200:
            rp.parse(resp.text.splitlines())
            return rp
    except requests.RequestException:
        pass
    return None


# --- Coeur du scraper ------------------------------------------------------

def analyser_url(
    url: str,
    session: requests.Session,
    crawl: bool = False,
    max_pages: int = 6,
    delai: float = 1.0,
    respecter_robots: bool = True,
    timeout: int = 15,
) -> ContactResult:
    url = normaliser_url(url)
    resultat = ContactResult(url=url)
    ua = DEFAULT_HEADERS["User-Agent"]

    rp = charger_robots(url, session) if respecter_robots else None

    a_visiter = [url]
    vus: set[str] = set()
    emails: set[str] = set()
    phones: set[str] = set()

    while a_visiter and len(resultat.pages_visitees) < max_pages:
        courante = a_visiter.pop(0)
        if courante in vus:
            continue
        vus.add(courante)

        if not peut_visiter(rp, courante, ua):
            continue

        try:
            resp = session.get(courante, headers=DEFAULT_HEADERS, timeout=timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            if courante == url:
                resultat.erreur = f"{type(exc).__name__}: {exc}"
            continue

        ctype = resp.headers.get("Content-Type", "")
        if "html" not in ctype and "text" not in ctype:
            continue

        resultat.pages_visitees.append(courante)
        e, p, liens = extraire_depuis_html(resp.text, courante)
        emails |= e
        phones |= p

        if crawl:
            # Priorise les pages "contact"/"mentions".
            candidats = [l for l in liens if l not in vus and l not in a_visiter]
            candidats.sort(key=lambda l: (not lien_est_contact(l), len(l)))
            for l in candidats:
                if len(a_visiter) + len(resultat.pages_visitees) >= max_pages:
                    break
                a_visiter.append(l)

        if a_visiter:
            time.sleep(delai)

    resultat.emails = sorted(emails)
    resultat.phones = sorted(phones)
    return resultat


# --- Sorties ---------------------------------------------------------------

def afficher_resultat(res: ContactResult) -> None:
    print("=" * 60)
    print(f"URL      : {res.url}")
    if res.erreur:
        print(f"ERREUR   : {res.erreur}")
    print(f"Emails   : {', '.join(res.emails) if res.emails else '(aucun)'}")
    print(f"Tel.     : {', '.join(res.phones) if res.phones else '(aucun)'}")
    if res.pages_visitees:
        print(f"Pages    : {len(res.pages_visitees)} visitee(s)")


def exporter_json(resultats: list[ContactResult], chemin: str) -> None:
    with open(chemin, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in resultats], f, ensure_ascii=False, indent=2)


def exporter_csv(resultats: list[ContactResult], chemin: str) -> None:
    with open(chemin, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "emails", "telephones", "pages_visitees", "erreur"])
        for r in resultats:
            w.writerow([
                r.url,
                " | ".join(r.emails),
                " | ".join(r.phones),
                len(r.pages_visitees),
                r.erreur or "",
            ])


# --- CLI -------------------------------------------------------------------

def lire_urls_fichier(chemin: str) -> list[str]:
    urls: list[str] = []
    with open(chemin, "r", encoding="utf-8") as f:
        for ligne in f:
            ligne = ligne.strip()
            if ligne and not ligne.startswith("#"):
                urls.append(ligne)
    return urls


def construire_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Agent commercial : recupere email(s) et telephone(s) depuis des URLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("urls", nargs="*", help="Une ou plusieurs URLs a analyser.")
    p.add_argument("-i", "--input", help="Fichier texte : une URL par ligne.")
    p.add_argument("--json", dest="json_out", help="Exporter les resultats en JSON.")
    p.add_argument("--csv", dest="csv_out", help="Exporter les resultats en CSV.")
    p.add_argument("--crawl", action="store_true",
                   help="Explorer aussi les pages internes (contact, mentions...).")
    p.add_argument("--max-pages", type=int, default=6,
                   help="Nombre max de pages par site en mode crawl (defaut 6).")
    p.add_argument("--delai", type=float, default=1.0,
                   help="Delai (s) entre deux requetes (defaut 1.0).")
    p.add_argument("--timeout", type=int, default=15,
                   help="Timeout HTTP en secondes (defaut 15).")
    p.add_argument("--ignore-robots", action="store_true",
                   help="Ne pas verifier robots.txt (a utiliser avec prudence).")
    return p


def main(argv: list[str] | None = None) -> int:
    args = construire_parser().parse_args(argv)

    urls = list(args.urls)
    if args.input:
        urls.extend(lire_urls_fichier(args.input))

    # Dedoublonnage en conservant l'ordre.
    vus = set()
    urls = [u for u in urls if not (u in vus or vus.add(u))]

    if not urls:
        construire_parser().print_help()
        return 1

    session = requests.Session()
    resultats: list[ContactResult] = []

    for url in urls:
        res = analyser_url(
            url,
            session=session,
            crawl=args.crawl,
            max_pages=args.max_pages,
            delai=args.delai,
            respecter_robots=not args.ignore_robots,
            timeout=args.timeout,
        )
        resultats.append(res)
        afficher_resultat(res)

    if args.json_out:
        exporter_json(resultats, args.json_out)
        print(f"\n[+] JSON ecrit dans {args.json_out}")
    if args.csv_out:
        exporter_csv(resultats, args.csv_out)
        print(f"[+] CSV ecrit dans {args.csv_out}")

    total_mails = sum(len(r.emails) for r in resultats)
    total_tel = sum(len(r.phones) for r in resultats)
    print(f"\nResume : {len(resultats)} site(s), {total_mails} email(s), {total_tel} telephone(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
