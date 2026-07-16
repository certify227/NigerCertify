"""Utilitaires partagés pour WebBounty."""

from __future__ import annotations

import re
import socket
import ssl
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class Finding:
    """Représente une vulnérabilité ou un point d'intérêt détecté."""

    title: str
    severity: str  # critical, high, medium, low, info
    category: str
    url: str
    description: str
    evidence: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }


class Colors:
    """Codes ANSI pour l'affichage terminal."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    SEVERITY = {
        "critical": RED + BOLD,
        "high": RED,
        "medium": YELLOW,
        "low": BLUE,
        "info": CYAN,
    }


def normalize_url(url: str) -> str:
    """Normalise une URL cible."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path.rstrip("/") or "/", "", "", "")
    )


def get_base_url(url: str) -> str:
    """Retourne scheme + netloc."""
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def get_domain(url: str) -> str:
    """Extrait le domaine d'une URL."""
    return urllib.parse.urlparse(url).netloc.split(":")[0]


def create_session(
    timeout: int = 10,
    verify_ssl: bool = True,
    user_agent: str | None = None,
    proxy: str | None = None,
) -> requests.Session:
    """Crée une session HTTP robuste avec retries."""
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(
        {
            "User-Agent": user_agent
            or "WebBounty/1.0 (Bug Bounty Research Tool; +https://github.com)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
        }
    )
    session.verify = verify_ssl
    session.timeout = timeout
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


def safe_request(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs: Any,
) -> requests.Response | None:
    """Effectue une requête HTTP en gérant les erreurs."""
    try:
        return session.request(method, url, timeout=session.timeout, **kwargs)
    except requests.RequestException:
        return None


def extract_links(html: str, base_url: str) -> set[str]:
    """Extrait les liens href d'une page HTML."""
    links: set[str] = set()
    for match in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        href = match.group(1).strip()
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        absolute = urllib.parse.urljoin(base_url, href)
        parsed = urllib.parse.urlparse(absolute)
        if parsed.scheme in ("http", "https"):
            links.add(absolute.split("#")[0])
    return links


def extract_forms(html: str) -> list[dict[str, Any]]:
    """Extrait les formulaires HTML."""
    forms: list[dict[str, Any]] = []
    for form_match in re.finditer(
        r"<form\b([^>]*)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL
    ):
        attrs = form_match.group(1)
        body = form_match.group(2)
        action = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        method = re.search(r'method=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        inputs = re.findall(
            r'<input\b([^>]*)/?>', body, re.IGNORECASE
        )
        fields: list[dict[str, str]] = []
        for inp in inputs:
            name = re.search(r'name=["\']([^"\']+)["\']', inp, re.IGNORECASE)
            itype = re.search(r'type=["\']([^"\']+)["\']', inp, re.IGNORECASE)
            if name:
                fields.append(
                    {
                        "name": name.group(1),
                        "type": (itype.group(1) if itype else "text").lower(),
                    }
                )
        forms.append(
            {
                "action": action.group(1) if action else "",
                "method": (method.group(1) if method else "GET").upper(),
                "fields": fields,
            }
        )
    return forms


def extract_params_from_url(url: str) -> dict[str, str]:
    """Extrait les paramètres GET d'une URL."""
    parsed = urllib.parse.urlparse(url)
    return dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))


def build_url_with_params(base: str, params: dict[str, str]) -> str:
    """Construit une URL avec des paramètres GET."""
    parsed = urllib.parse.urlparse(base)
    query = urllib.parse.urlencode(params)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment)
    )


def resolve_host(domain: str) -> list[str]:
    """Résout un domaine en adresses IP."""
    try:
        return list({info[4][0] for info in socket.getaddrinfo(domain, None)})
    except socket.gaierror:
        return []


def get_ssl_info(hostname: str, port: int = 443) -> dict[str, Any]:
    """Récupère les informations du certificat SSL."""
    info: dict[str, Any] = {"valid": False}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["valid"] = True
                info["subject"] = dict(x[0] for x in cert.get("subject", ()))
                info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                info["not_before"] = cert.get("notBefore", "")
                info["not_after"] = cert.get("notAfter", "")
                info["san"] = [
                    ext[1]
                    for ext in cert.get("subjectAltName", ())
                    if ext[0] == "DNS"
                ]
                info["version"] = ssock.version()
    except (ssl.SSLError, socket.error, OSError) as exc:
        info["error"] = str(exc)
    return info


def print_banner() -> None:
  """Affiche la bannière WebBounty."""
  banner = f"""
{Colors.CYAN}{Colors.BOLD}
 ██╗    ██╗███████╗██████╗ ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
 ╚███╔███╔╝███████╗██████╔╝██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   
{Colors.RESET}
{Colors.YELLOW}  Outil de Bug Bounty Web — Recon | Scan | Fuzz | Report{Colors.RESET}
{Colors.WHITE}  Usage éthique uniquement — Autorisation requise{Colors.RESET}
"""
  print(banner)


def print_finding(finding: Finding) -> None:
    """Affiche un finding coloré dans le terminal."""
    color = Colors.SEVERITY.get(finding.severity, Colors.WHITE)
    print(
        f"\n{color}[{finding.severity.upper()}]{Colors.RESET} "
        f"{Colors.BOLD}{finding.title}{Colors.RESET}"
    )
    print(f"  {Colors.CYAN}Catégorie:{Colors.RESET} {finding.category}")
    print(f"  {Colors.CYAN}URL:{Colors.RESET} {finding.url}")
    print(f"  {Colors.CYAN}Description:{Colors.RESET} {finding.description}")
    if finding.evidence:
        evidence = finding.evidence[:300] + ("..." if len(finding.evidence) > 300 else "")
        print(f"  {Colors.CYAN}Preuve:{Colors.RESET} {evidence}")
