#!/usr/bin/env python3
"""
Agent commercial intelligent — prospection B2B depuis une URL.
Collecte des informations exploitables pour proposer produits et services.
"""

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Optional
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

EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
# Emails protégés : name [at] domain [dot] com — "at"/"dot" doivent être isolés
OBFUSCATED_EMAIL_PATTERN = re.compile(
    r"\b([a-zA-Z0-9._%+\-]{1,64})\s*"
    r"(?:\[\s*at\s*\]|\(\s*at\s\)|\{\s*at\s*\}|(?<=\s)at(?=\s)|@)\s*"
    r"([a-zA-Z0-9][a-zA-Z0-9.\-]{0,120})\s*"
    r"(?:\[\s*dot\s*\]|\(\s*dot\s\)|\{\s*dot\s\}|(?<=\s)dot(?=\s)|\.)\s*"
    r"([a-zA-Z]{2,24})\b",
    re.IGNORECASE,
)
PHONE_PATTERN = re.compile(
    r"(?:\+?\d{1,3}[\s.\-]?(?:\(?\d{1,4}\)?[\s.\-]?)?\d{2,4}[\s.\-]?\d{2,4}[\s.\-]?\d{2,4}[\s.\-]?\d{0,4})"
)
ADDRESS_PATTERN = re.compile(
    r"\b\d{1,5}[\s,]+[\w\s\-']{3,60}(?:rue|avenue|av\.|boulevard|bd|place|chemin|route|allée|impasse)[\w\s\-',.]{0,80}"
    r"(?:\d{5})?[\s,]*[\w\s\-']{2,40}\b",
    re.IGNORECASE,
)
SIRET_PATTERN = re.compile(r"\b\d{3}\s?\d{3}\s?\d{3}\s?\d{5}\b")
ROLE_PATTERN = re.compile(
    r"([A-ZÀÂÄÉÈÊËÏÎÔÙÛÜÇ][a-zàâäéèêëïîôùûüç\-']+(?:\s+[A-ZÀÂÄÉÈÊËÏÎÔÙÛÜÇ][a-zàâäéèêëïîôùûüç\-']+)+)"
    r"\s*[-–—,:|]\s*"
    r"(directeur|directrice|ceo|pdg|fondateur|fondatrice|président|présidente|"
    r"responsable|manager|commercial|commerciale|marketing|cto|dsi|rh|drh|"
    r"gérant|gérante|associé|associée|chef de projet|consultant|consultante)",
    re.IGNORECASE,
)

FALSE_POSITIVE_EMAIL_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js", ".woff", ".woff2",
)
GENERIC_EMAIL_PREFIXES = ("noreply", "no-reply", "donotreply", "postmaster", "webmaster")
# TLDs / domaines typiques de faux positifs d'extraction HTML
INVALID_EMAIL_TLDS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "html", "htm",
    "vous", "pour", "avec", "dans", "cette", "votre", "notre", "textes",
    "organisation", "exemple", "ces", "ion",
}
PLACEHOLDER_EMAIL_DOMAINS = {
    "exemple.com", "example.com", "example.org", "example.net",
    "domain.com", "email.com", "test.com", "sentry.wixpress.com",
}

PAGE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "contact": ("contact", "nous-contacter", "nous_contacter", "contactez"),
    "about": ("about", "a-propos", "apropos", "qui-sommes", "entreprise", "notre-histoire"),
    "team": ("equipe", "équipe", "team", "notre-equipe", "direction", "leadership"),
    "services": ("services", "prestations", "solutions", "offres", "expertise"),
    "products": ("produits", "products", "catalogue", "boutique", "shop"),
    "careers": ("recrutement", "carrieres", "carrières", "jobs", "emploi", "nous-rejoindre"),
}

SECTOR_KEYWORDS: dict[str, tuple[str, ...]] = {
    "Cybersécurité": ("cybersécurité", "cybersecurite", "pentest", "soc", "siem", "firewall", "iso 27001"),
    "Informatique / IT": ("informatique", "développement", "developpement", "logiciel", "saas", "cloud", "devops"),
    "Formation": ("formation", "certification", "apprentissage", "cours", "e-learning", "pédagogie"),
    "E-commerce": ("e-commerce", "ecommerce", "boutique en ligne", "marketplace", "paiement en ligne"),
    "Santé": ("santé", "sante", "médical", "medical", "clinique", "hôpital", "pharma"),
    "Finance": ("banque", "finance", "assurance", "fintech", "investissement", "comptabilité"),
    "Industrie": ("industrie", "manufacturing", "usine", "production", "ingénierie"),
    "Immobilier": ("immobilier", "agence immobilière", "promoteur", "location"),
    "Restauration / Hôtellerie": ("restaurant", "hôtel", "hotel", "restauration", "traiteur"),
    "Marketing / Communication": ("marketing", "communication", "agence digitale", "seo", "publicité"),
    "Juridique": ("avocat", "juridique", "cabinet", "notaire", "droit"),
    "RH / Recrutement": ("recrutement", "ressources humaines", "talents", "rh", "drh"),
}

PAIN_POINT_KEYWORDS: dict[str, tuple[str, ...]] = {
    "Sécurité insuffisante": ("mot de passe faible", "pas de ssl", "http://", "vulnérabilité", "faille"),
    "Besoin de formation": ("former nos équipes", "montée en compétence", "sensibilisation", "cyber awareness"),
    "Transformation digitale": ("digitalisation", "transformation digitale", "modernisation", "automatisation"),
    "Conformité réglementaire": ("rgpd", "gdpr", "conformité", "audit", "certification iso"),
    "Croissance commerciale": ("développer notre activité", "acquisition client", "prospection", "croissance"),
    "Infrastructure obsolète": ("legacy", "système obsolète", "migration", "refonte"),
}

TECH_SIGNATURES: dict[str, tuple[str, ...]] = {
    "WordPress": ("/wp-content/", "/wp-includes/", "wp-json"),
    "Shopify": ("cdn.shopify.com", "myshopify.com"),
    "Wix": ("static.wixstatic.com", "wixsite.com"),
    "PrestaShop": ("/prestashop/", "prestashop.com"),
    "Drupal": ("/sites/default/", "drupal.js"),
    "React": ("__NEXT_DATA__", "react-dom"),
    "Angular": ("ng-version", "angular.min.js"),
    "HubSpot": ("js.hs-scripts.com", "hubspot.com"),
    "Google Analytics": ("google-analytics.com", "googletagmanager.com"),
    "Cloudflare": ("cdn.cloudflare.com", "cloudflare-static"),
}

SOCIAL_PATTERNS: dict[str, str] = {
    "linkedin": r"linkedin\.com/(?:company|in)/[\w\-]+",
    "facebook": r"facebook\.com/[\w.\-]+",
    "twitter": r"(?:twitter|x)\.com/[\w]+",
    "instagram": r"instagram\.com/[\w.\-]+",
    "youtube": r"youtube\.com/(?:c/|channel/|@)[\w\-]+",
}

EMAIL_PRIORITY: dict[str, int] = {
    "contact": 100, "commercial": 95, "sales": 95, "vente": 95, "ventes": 95,
    "info": 80, "hello": 75, "bonjour": 75, "direction": 90, "ceo": 92, "pdg": 92,
    "rh": 70, "recrutement": 65, "support": 50, "admin": 40, "webmaster": 20,
}


@dataclass
class ContactPerson:
    name: str
    role: str
    email: Optional[str] = None
    source_page: str = ""


@dataclass
class ProspectProfile:
    url: str
    company_name: str = ""
    tagline: str = ""
    description: str = ""
    sector: str = ""
    sectors_detected: list[str] = field(default_factory=list)
    emails: list[dict[str, Any]] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    siret: list[str] = field(default_factory=list)
    social_links: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    services_detected: list[str] = field(default_factory=list)
    team_members: list[ContactPerson] = field(default_factory=list)
    pain_points: list[str] = field(default_factory=list)
    pages_scanned: list[str] = field(default_factory=list)
    opportunity_score: int = 0
    recommended_approach: list[str] = field(default_factory=list)
    matched_offers: list[dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def is_valid_email(email: str) -> bool:
    email = email.lower().strip()
    if any(email.endswith(s) for s in FALSE_POSITIVE_EMAIL_SUFFIXES):
        return False
    if email.count("@") != 1:
        return False
    local, domain = email.split("@", 1)
    if not local or not domain or "." not in domain:
        return False
    if len(local) > 64 or len(email) > 254:
        return False
    if any(local.startswith(p) for p in GENERIC_EMAIL_PREFIXES):
        return False
    tld = domain.rsplit(".", 1)[-1]
    if tld in INVALID_EMAIL_TLDS or len(tld) < 2:
        return False
    if domain in PLACEHOLDER_EMAIL_DOMAINS:
        return False
    # Domaine doit ressembler à un hostname (pas une phrase)
    if " " in domain or domain.startswith(".") or domain.endswith("."):
        return False
    labels = domain.split(".")
    if any(len(label) == 0 for label in labels):
        return False
    return True


def clean_phone(raw: str) -> str:
    cleaned = re.sub(r"\s+", " ", raw.strip())
    return re.sub(r"[^\d+\s().\-]", "", cleaned).strip(" .-")


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
        # Avec phonenumbers installé, on n'accepte que les numéros valides
        # (évite années, dates, suites numériques…)
        return None
    return phone


def is_plausible_phone(phone: str) -> bool:
    digits = re.sub(r"\D", "", phone)
    if not (8 <= len(digits) <= 15):
        return False
    if len(set(digits)) <= 1:
        return False
    # Rejeter suites trop régulières / années collées (ex. 20012026)
    if re.fullmatch(r"(19|20)\d{2}(19|20)\d{2}", digits):
        return False
    return True


def score_email(email: str) -> tuple[int, str]:
    local = email.split("@")[0].lower()
    for prefix, score in EMAIL_PRIORITY.items():
        if prefix in local:
            return score, f"Contact {prefix} — priorité commerciale élevée"
    if "." in local:
        parts = local.split(".")
        if len(parts) == 2 and all(len(p) > 1 for p in parts):
            return 85, "Email nominatif (prénom.nom) — contact direct probable"
    return 60, "Email générique — à qualifier"


def fetch_page(url: str, timeout: int = 15) -> tuple[Optional[str], Optional[str], Optional[str]]:
    try:
        response = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return None, None, f"Type de contenu non HTML : {content_type}"
        # Évite les mojibake (UTF-8 lu en latin-1)
        if not response.encoding or response.encoding.lower() in ("iso-8859-1", "latin-1"):
            response.encoding = response.apparent_encoding or "utf-8"
        return response.text, response.url, None
    except requests.RequestException as exc:
        return None, None, str(exc)


def clean_soup(html: str) -> BeautifulSoup:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return soup


def extract_meta(soup: BeautifulSoup) -> dict[str, str]:
    meta: dict[str, str] = {}
    if soup.title and soup.title.string:
        meta["title"] = soup.title.string.strip()

    for tag in soup.find_all("meta"):
        name = (tag.get("name") or tag.get("property") or "").lower()
        content = tag.get("content", "").strip()
        if not content:
            continue
        if name in ("description", "og:description"):
            meta["description"] = content
        elif name in ("og:site_name", "application-name"):
            meta["site_name"] = content
        elif name == "keywords":
            meta["keywords"] = content
    return meta


def extract_json_ld(soup: BeautifulSoup) -> list[dict]:
    items = []
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string or "")
            if isinstance(data, list):
                items.extend(data)
            elif isinstance(data, dict):
                items.append(data)
        except (json.JSONDecodeError, TypeError):
            continue
    return items


def extract_company_from_schema(json_ld: list[dict]) -> dict[str, Any]:
    info: dict[str, Any] = {}
    for item in json_ld:
        item_type = item.get("@type", "")
        if item_type in ("Organization", "LocalBusiness", "Corporation", "Company"):
            info["name"] = item.get("name", info.get("name", ""))
            info["description"] = item.get("description", info.get("description", ""))
            if item.get("telephone"):
                info.setdefault("phones", []).append(str(item["telephone"]))
            if item.get("email"):
                info.setdefault("emails", []).append(str(item["email"]))
            addr = item.get("address")
            if isinstance(addr, dict):
                parts = [addr.get(k, "") for k in ("streetAddress", "postalCode", "addressLocality", "addressCountry")]
                info.setdefault("addresses", []).append(", ".join(p for p in parts if p))
            elif isinstance(addr, str):
                info.setdefault("addresses", []).append(addr)
    return info


def deobfuscate_emails(text: str) -> set[str]:
    """Récupère les emails masqués (at/dot, &#64;, etc.)."""
    found: set[str] = set()
    decoded = (
        text.replace("&#64;", "@")
        .replace("&#x40;", "@")
        .replace("&amp;#64;", "@")
        .replace("(at)", "@")
        .replace("[at]", "@")
        .replace("(@)", "@")
    )
    for match in EMAIL_PATTERN.findall(decoded):
        if is_valid_email(match):
            found.add(match.lower())
    for local, domain, tld in OBFUSCATED_EMAIL_PATTERN.findall(text):
        email = f"{local}@{domain}.{tld}".lower()
        if is_valid_email(email):
            found.add(email)
    return found


def extract_emails(soup: BeautifulSoup, text: str) -> set[str]:
    emails = set()
    for match in EMAIL_PATTERN.findall(text):
        if is_valid_email(match):
            emails.add(match.lower())
    emails.update(deobfuscate_emails(text))
    for link in soup.select('a[href^="mailto:"]'):
        email = link.get("href", "").replace("mailto:", "").split("?")[0].strip().lower()
        if is_valid_email(email):
            emails.add(email)
    # data-email / data-mail attributs courants sur sites anti-spam
    for tag in soup.find_all(attrs={"data-email": True}):
        raw = tag.get("data-email", "").strip().lower()
        if is_valid_email(raw):
            emails.add(raw)
    for tag in soup.find_all(attrs={"data-mail": True}):
        raw = tag.get("data-mail", "").strip().lower()
        if is_valid_email(raw):
            emails.add(raw)
    return emails


def extract_phones(soup: BeautifulSoup, text: str, region: str) -> set[str]:
    phones = set()
    for match in PHONE_PATTERN.findall(text):
        formatted = format_phone(match, region)
        if formatted:
            phones.add(formatted)
    for link in soup.select('a[href^="tel:"]'):
        formatted = format_phone(link.get("href", "").replace("tel:", ""), region)
        if formatted:
            phones.add(formatted)
    return phones


def extract_social_links(soup: BeautifulSoup, html: str) -> dict[str, str]:
    found: dict[str, str] = {}
    links_text = " ".join(a.get("href", "") for a in soup.find_all("a", href=True)) + " " + html
    for network, pattern in SOCIAL_PATTERNS.items():
        match = re.search(pattern, links_text, re.IGNORECASE)
        if match:
            url = match.group(0)
            if not url.startswith("http"):
                url = "https://" + url
            found[network] = url
    return found


def detect_technologies(html: str) -> list[str]:
    html_lower = html.lower()
    return [tech for tech, sigs in TECH_SIGNATURES.items() if any(s in html_lower for s in sigs)]


def detect_sectors(text: str) -> list[str]:
    text_lower = text.lower()
    scores: list[tuple[int, str]] = []
    for sector, keywords in SECTOR_KEYWORDS.items():
        count = sum(1 for kw in keywords if kw in text_lower)
        if count:
            scores.append((count, sector))
    scores.sort(reverse=True)
    return [s for _, s in scores[:3]]


def detect_pain_points(text: str, html: str) -> list[str]:
    text_lower = text.lower()
    found = []
    if "http://" in html.lower() and "https://" not in html.lower()[:500]:
        found.append("Site sans HTTPS — opportunité sécurité / conformité")
    for pain, keywords in PAIN_POINT_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            found.append(pain)
    return found


def extract_services(soup: BeautifulSoup) -> list[str]:
    services = []
    for heading in soup.find_all(["h1", "h2", "h3", "h4"]):
        text = heading.get_text(" ", strip=True)
        if 5 < len(text) < 120:
            services.append(text)
    return list(dict.fromkeys(services))[:15]


def extract_team_members(soup: BeautifulSoup, page_url: str) -> list[ContactPerson]:
    members = []
    seen = set()

    for block in soup.select("[class*='team'], [class*='member'], [class*='staff'], [id*='team']"):
        line = block.get_text("\n", strip=True)
        for match in ROLE_PATTERN.finditer(line):
            name, role = match.group(1).strip(), match.group(2).strip()
            if _is_valid_person(name, role, seen):
                seen.add(f"{name.lower()}|{role.lower()}")
                members.append(ContactPerson(name=name, role=role.title(), source_page=page_url))

    for line in soup.get_text("\n", strip=True).splitlines():
        line = line.strip()
        if len(line) > 120:
            continue
        for match in ROLE_PATTERN.finditer(line):
            name, role = match.group(1).strip(), match.group(2).strip()
            if _is_valid_person(name, role, seen):
                seen.add(f"{name.lower()}|{role.lower()}")
                members.append(ContactPerson(name=name, role=role.title(), source_page=page_url))

    return members[:10]


def _is_valid_person(name: str, role: str, seen: set[str]) -> bool:
    key = f"{name.lower()}|{role.lower()}"
    if key in seen:
        return False
    words = name.split()
    if len(words) < 2 or len(words) > 4:
        return False
    if any(len(w) < 2 for w in words):
        return False
    if any(c.isdigit() for c in name):
        return False
    blocked = (
        "nos services", "notre équipe", "à propos", "contactez",
        "contact commercial", "contact marketing", "email", "téléphone",
    )
    return not any(b in name.lower() for b in blocked)


def find_priority_pages(soup: BeautifulSoup, base_url: str) -> list[tuple[int, str, str]]:
    candidates: list[tuple[int, str, str]] = []
    seen = set()
    base_domain = urlparse(base_url).netloc

    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        text = anchor.get_text(" ", strip=True).lower()
        href_lower = href.lower()
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)

        if parsed.scheme not in ("http", "https") or parsed.netloc != base_domain:
            continue
        if absolute in seen or absolute.rstrip("/") == base_url.rstrip("/"):
            continue

        for category, keywords in PAGE_KEYWORDS.items():
            if any(kw in href_lower or kw in text for kw in keywords):
                priority = {"contact": 100, "about": 90, "team": 85, "services": 80,
                            "products": 75, "careers": 60}.get(category, 50)
                candidates.append((priority, absolute, category))
                seen.add(absolute)
                break

    candidates.sort(key=lambda x: -x[0])
    return candidates[:8]


def load_offers_config(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("offers", data) if isinstance(data, dict) else data


def match_offers(profile: ProspectProfile, offers: list[dict], full_text: str) -> list[dict]:
    text_lower = full_text.lower()
    matches = []
    for offer in offers:
        name = offer.get("name", "Offre")
        keywords = offer.get("keywords", [])
        sectors = offer.get("sectors", [])
        score = 0
        reasons = []

        for kw in keywords:
            if kw.lower() in text_lower:
                score += 10
                reasons.append(f"Mot-clé détecté : {kw}")

        if profile.sector and profile.sector in sectors:
            score += 25
            reasons.append(f"Secteur compatible : {profile.sector}")

        for sector in profile.sectors_detected:
            if sector in sectors:
                score += 15
                reasons.append(f"Secteur secondaire : {sector}")

        for pain in profile.pain_points:
            offer_pains = offer.get("pain_points", [])
            if any(p.lower() in pain.lower() or pain.lower() in p.lower() for p in offer_pains):
                score += 20
                reasons.append(f"Besoin identifié : {pain}")

        for tech in profile.technologies:
            offer_techs = offer.get("technologies", [])
            if tech in offer_techs:
                score += 10
                reasons.append(f"Stack détectée : {tech}")

        if score > 0:
            matches.append({
                "offer": name,
                "score": score,
                "pitch": offer.get("pitch", ""),
                "reasons": reasons,
            })

    matches.sort(key=lambda x: -x["score"])
    return matches[:5]


def build_recommendations(profile: ProspectProfile) -> list[str]:
    recs = []

    if profile.emails:
        best = profile.emails[0]
        recs.append(f"Contacter en priorité : {best['email']} ({best['reason']})")
    elif profile.phones:
        recs.append(f"Pas d'email identifié — appeler le {profile.phones[0]}")

    if profile.social_links.get("linkedin"):
        recs.append(f"Approche LinkedIn possible : {profile.social_links['linkedin']}")

    if profile.team_members:
        leader = next((m for m in profile.team_members if any(
            r in m.role.lower() for r in ("directeur", "ceo", "pdg", "fondateur", "président")
        )), profile.team_members[0])
        recs.append(f"Cibler {leader.name} ({leader.role}) pour une approche personnalisée")

    if "WordPress" in profile.technologies:
        recs.append("Site WordPress — proposer maintenance, sécurisation ou refonte")
    if "Besoin de formation" in profile.pain_points or profile.sector == "Formation":
        recs.append("Angle formation / montée en compétences adapté au profil")
    if any("Sécurité" in p or "Conformité" in p for p in profile.pain_points):
        recs.append("Opportunité audit sécurité ou mise en conformité RGPD")

    if profile.matched_offers:
        top = profile.matched_offers[0]
        recs.append(f"Offre recommandée : {top['offer']} — {top.get('pitch', '')}")

    if not profile.emails and not profile.phones:
        recs.append("Peu de contacts directs — utiliser le formulaire du site ou LinkedIn")

    return recs[:6]


def compute_opportunity_score(profile: ProspectProfile) -> int:
    score = 0
    score += min(len(profile.emails) * 15, 30)
    score += min(len(profile.phones) * 10, 20)
    score += 10 if profile.company_name else 0
    score += 10 if profile.sector else 0
    score += min(len(profile.team_members) * 8, 24)
    score += min(len(profile.social_links) * 5, 15)
    score += min(len(profile.matched_offers) * 10, 30)
    score += min(len(profile.pain_points) * 5, 15)
    return min(score, 100)


def analyze_page(html: str, page_url: str, region: str) -> dict[str, Any]:
    # JSON-LD avant nettoyage (les <script> sont sinon détruits)
    raw_soup = BeautifulSoup(html, "html.parser")
    json_ld = extract_json_ld(raw_soup)
    schema = extract_company_from_schema(json_ld)

    soup = clean_soup(html)
    text = soup.get_text(" ", strip=True)
    meta = extract_meta(soup)

    emails = extract_emails(soup, text)
    phones = extract_phones(soup, text, region)
    for e in schema.get("emails", []):
        if is_valid_email(str(e)):
            emails.add(str(e).lower())
    for p in schema.get("phones", []):
        formatted = format_phone(str(p), region)
        if formatted:
            phones.add(formatted)

    return {
        "meta": meta,
        "schema": schema,
        "emails": emails,
        "phones": phones,
        "social": extract_social_links(soup, html),
        "technologies": detect_technologies(html),
        "sectors": detect_sectors(text),
        "pain_points": detect_pain_points(text, html),
        "services": extract_services(soup),
        "team": extract_team_members(soup, page_url),
        "addresses": set(ADDRESS_PATTERN.findall(text)) | set(schema.get("addresses", [])),
        "siret": set(SIRET_PATTERN.findall(text)),
        "text_sample": text[:5000],
    }


def scan_prospect(
    url: str,
    follow_pages: bool = True,
    timeout: int = 15,
    region: str = "FR",
    offers: Optional[list[dict]] = None,
) -> ProspectProfile:
    url = normalize_url(url)
    profile = ProspectProfile(url=url)
    all_text = ""
    all_emails: dict[str, dict] = {}
    all_phones: set[str] = set()
    all_addresses: set[str] = set()
    all_siret: set[str] = set()
    all_services: list[str] = []
    all_team: list[ContactPerson] = []
    all_pain: set[str] = set()
    all_tech: set[str] = set()
    all_sectors: list[str] = []
    company_name = ""
    description = ""
    tagline = ""

    cprint(f"[*] Prospection intelligente : {url}", "cyan", attrs=["bold"])

    html, final_url, error = fetch_page(url, timeout)
    if error:
        profile.error = error
        cprint(f"[ERROR] {error}", "red")
        return profile

    profile.url = final_url or url
    pages_to_scan = [profile.url]

    if follow_pages:
        soup = BeautifulSoup(html, "html.parser")
        for _, link, category in find_priority_pages(soup, profile.url):
            pages_to_scan.append(link)
            cprint(f"[*] Page {category} identifiée : {link}", "yellow")

    for page_url in dict.fromkeys(pages_to_scan):
        if page_url != profile.url:
            page_html, _, page_error = fetch_page(page_url, timeout)
            if page_error:
                cprint(f"[WARN] {page_url} : {page_error}", "yellow")
                continue
            html = page_html

        profile.pages_scanned.append(page_url)
        data = analyze_page(html, page_url, region)
        all_text += " " + data["text_sample"]

        meta = data["meta"]
        if not company_name:
            company_name = meta.get("site_name") or meta.get("title", "").split("|")[0].split("-")[0].strip()
        if not description:
            description = meta.get("description", "")
        if not tagline and meta.get("title"):
            tagline = meta["title"]

        schema = data["schema"]
        if schema.get("name"):
            company_name = schema["name"]
        if schema.get("description"):
            description = schema["description"]

        for email in data["emails"]:
            score, reason = score_email(email)
            if email not in all_emails or all_emails[email]["score"] < score:
                all_emails[email] = {"email": email, "score": score, "reason": reason}

        all_phones.update(data["phones"])
        all_addresses.update(data["addresses"])
        all_siret.update(data["siret"])
        all_services.extend(data["services"])
        all_team.extend(data["team"])
        all_pain.update(data["pain_points"])
        all_tech.update(data["technologies"])
        for s in data["sectors"]:
            if s not in all_sectors:
                all_sectors.append(s)

        for network, link in data["social"].items():
            profile.social_links.setdefault(network, link)

    profile.company_name = company_name or urlparse(profile.url).netloc.replace("www.", "")
    profile.tagline = tagline
    profile.description = description[:500]
    profile.sectors_detected = all_sectors
    profile.sector = all_sectors[0] if all_sectors else "Non identifié"
    profile.emails = sorted(all_emails.values(), key=lambda x: -x["score"])
    profile.phones = sorted(all_phones)
    profile.addresses = sorted(all_addresses)[:3]
    profile.siret = sorted(all_siret)
    profile.services_detected = list(dict.fromkeys(all_services))[:12]
    profile.team_members = all_team[:10]
    profile.pain_points = sorted(all_pain)
    profile.technologies = sorted(all_tech)

    if offers:
        profile.matched_offers = match_offers(profile, offers, all_text)

    profile.recommended_approach = build_recommendations(profile)
    profile.opportunity_score = compute_opportunity_score(profile)

    cprint(f"[+] Entreprise : {profile.company_name}", "green")
    cprint(f"[+] Secteur : {profile.sector}", "green")
    cprint(f"[+] Score d'opportunité : {profile.opportunity_score}/100", "green", attrs=["bold"])
    return profile


def print_contacts_only(profile: ProspectProfile) -> None:
    """Affiche uniquement emails et téléphones — mode agent commercial rapide."""
    cprint(f"\n{'=' * 60}", "cyan")
    cprint(f" CONTACTS — {profile.company_name or profile.url}", "cyan", attrs=["bold"])
    cprint(f"{'=' * 60}", "cyan")

    if profile.error:
        cprint(f"Erreur : {profile.error}", "red")
        return

    cprint(f"\nURL : {profile.url}", "white")

    cprint("\n📧 Emails :", "yellow", attrs=["bold"])
    if profile.emails:
        for e in profile.emails:
            cprint(f"  • {e['email']}  (score {e['score']})", "green")
    else:
        cprint("  Aucun email trouvé", "yellow")

    cprint("\n📞 Téléphones :", "yellow", attrs=["bold"])
    if profile.phones:
        for p in profile.phones:
            cprint(f"  • {p}", "green")
    else:
        cprint("  Aucun téléphone trouvé", "yellow")

    cprint(f"\nPages scannées : {len(profile.pages_scanned)}", "white")


def print_prospect_report(profile: ProspectProfile) -> None:
    cprint(f"\n{'=' * 70}", "cyan")
    cprint(f" DOSSIER PROSPECT — {profile.company_name}", "cyan", attrs=["bold"])
    cprint(f"{'=' * 70}", "cyan")

    if profile.error:
        cprint(f"Erreur : {profile.error}", "red")
        return

    cprint(f"\nURL : {profile.url}", "white")
    if profile.tagline:
        cprint(f"Slogan : {profile.tagline}", "white")
    if profile.description:
        cprint(f"\nDescription :\n  {profile.description[:300]}", "white")

    cprint(f"\nSecteur principal : {profile.sector}", "magenta")
    if profile.sectors_detected:
        cprint(f"Secteurs détectés : {', '.join(profile.sectors_detected)}", "magenta")

    cprint(f"\nScore d'opportunité : {profile.opportunity_score}/100", "green", attrs=["bold"])

    cprint("\n--- Contacts prioritaires ---", "yellow")
    if profile.emails:
        for e in profile.emails[:5]:
            cprint(f"  [{e['score']}] {e['email']} — {e['reason']}", "green")
    else:
        cprint("  Aucun email", "yellow")
    if profile.phones:
        for p in profile.phones[:3]:
            cprint(f"  Tel : {p}", "green")

    if profile.team_members:
        cprint("\n--- Équipe / Décideurs ---", "yellow")
        for m in profile.team_members[:5]:
            cprint(f"  • {m.name} — {m.role}", "white")

    if profile.social_links:
        cprint("\n--- Réseaux sociaux ---", "yellow")
        for network, link in profile.social_links.items():
            cprint(f"  {network.capitalize()} : {link}", "blue")

    if profile.technologies:
        cprint(f"\nTechnologies : {', '.join(profile.technologies)}", "white")
    if profile.addresses:
        cprint(f"Adresse : {profile.addresses[0]}", "white")
    if profile.siret:
        cprint(f"SIRET : {profile.siret[0]}", "white")

    if profile.services_detected:
        cprint("\n--- Activités / Services détectés ---", "yellow")
        for s in profile.services_detected[:6]:
            cprint(f"  • {s}", "white")

    if profile.pain_points:
        cprint("\n--- Signaux d'opportunité ---", "yellow")
        for p in profile.pain_points:
            cprint(f"  ! {p}", "red")

    if profile.matched_offers:
        cprint("\n--- Offres recommandées ---", "yellow")
        for o in profile.matched_offers:
            cprint(f"  [{o['score']}] {o['offer']}", "green", attrs=["bold"])
            if o.get("pitch"):
                cprint(f"      Pitch : {o['pitch']}", "white")
            for r in o.get("reasons", [])[:3]:
                cprint(f"      → {r}", "white")

    cprint("\n--- Plan d'approche ---", "yellow", attrs=["bold"])
    for i, rec in enumerate(profile.recommended_approach, 1):
        cprint(f"  {i}. {rec}", "cyan")

    cprint(f"\nPages analysées ({len(profile.pages_scanned)}) :", "white")
    for p in profile.pages_scanned:
        cprint(f"  - {p}", "white")


def prospect_to_dict(profile: ProspectProfile) -> dict:
    data = asdict(profile)
    return data


def save_results(results: list[ProspectProfile], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump([prospect_to_dict(r) for r in results], f, ensure_ascii=False, indent=2)
    cprint(f"[+] Dossier(s) exporté(s) vers {output_path}", "green")


def load_urls_from_file(path: str) -> list[str]:
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agent commercial intelligent — prospection B2B depuis une URL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python3 commercial_agent.py https://example.com
  python3 commercial_agent.py https://example.com --offers scanners/offers.example.json
  python3 commercial_agent.py -f prospects.txt -o dossiers.json
  python3 commercial_agent.py https://example.com --no-follow --region FR
        """,
    )
    parser.add_argument("url", nargs="?", help="URL du prospect à analyser")
    parser.add_argument("-u", "--urls", nargs="+", help="Liste d'URLs")
    parser.add_argument("-f", "--file", help="Fichier d'URLs (une par ligne)")
    parser.add_argument("-o", "--output", help="Exporter les dossiers en JSON")
    parser.add_argument(
        "--offers",
        help="Fichier JSON de vos produits/services pour matching automatique",
    )
    parser.add_argument("--no-follow", action="store_true", help="Analyser uniquement la page d'accueil")
    parser.add_argument(
        "--contacts-only",
        action="store_true",
        help="Afficher uniquement emails et téléphones",
    )
    parser.add_argument("--region", default="FR", help="Région téléphone (défaut: FR)")
    parser.add_argument("--timeout", type=int, default=15, help="Timeout HTTP (défaut: 15s)")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    urls: list[str] = []
    if args.url:
        urls.append(args.url)
    if args.urls:
        urls.extend(args.urls)
    if args.file:
        urls.extend(load_urls_from_file(args.file))

    if not urls:
        build_parser().print_help()
        cprint("\n[ERROR] Fournissez au moins une URL.", "red")
        return 1

    offers = load_offers_config(args.offers) if args.offers else None
    if offers:
        cprint(f"[*] {len(offers)} offre(s) chargée(s) pour le matching", "cyan")

    cprint("[*] Agent commercial intelligent — prospection B2B", "cyan", attrs=["bold"])

    results = []
    for url in urls:
        profile = scan_prospect(
            url,
            follow_pages=not args.no_follow,
            timeout=args.timeout,
            region=args.region,
            offers=offers,
        )
        results.append(profile)
        if args.contacts_only:
            print_contacts_only(profile)
        else:
            print_prospect_report(profile)

    if args.output:
        save_results(results, args.output)

    return 0 if any(r.opportunity_score > 0 or not r.error for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
