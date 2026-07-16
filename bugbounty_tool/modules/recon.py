"""
Module de reconnaissance passive et active.

- Résolution DNS et enregistrements (A, AAAA, MX, NS, TXT, CNAME) via `dnspython`
  (fallback socket si indisponible)
- Énumération de sous-domaines : source passive `crt.sh` + bruteforce
  concurrent depuis la wordlist embarquée
- Fingerprinting technologique (serveur, framework, CMS) via en-têtes,
  cookies et signatures HTML
- Récupération de robots.txt & sitemap.xml pour extraire des chemins
"""

from __future__ import annotations

import concurrent.futures as cf
import re
import socket
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

from ..core import C, Finding, HttpClient, log_info, log_ok, log_warn, log_debug

try:
    import dns.resolver  # type: ignore
    HAS_DNSPYTHON = True
except Exception:
    HAS_DNSPYTHON = False


# ---------------------------------------------------------------------------
# Signatures technologiques (regex sur en-têtes/HTML/cookies)
# ---------------------------------------------------------------------------
TECH_SIGNATURES: List[Tuple[str, str, str]] = [
    # (nom, où : header|html|cookie, regex)
    ("nginx", "header:Server", r"nginx(?:/([\d.]+))?"),
    ("Apache", "header:Server", r"Apache(?:/([\d.]+))?"),
    ("IIS", "header:Server", r"Microsoft-IIS/([\d.]+)"),
    ("LiteSpeed", "header:Server", r"LiteSpeed"),
    ("Cloudflare", "header:Server", r"cloudflare"),
    ("Cloudflare", "header:CF-Ray", r".+"),
    ("Envoy", "header:Server", r"envoy"),
    ("Caddy", "header:Server", r"Caddy"),
    ("PHP", "header:X-Powered-By", r"PHP/?([\d.]+)?"),
    ("ASP.NET", "header:X-Powered-By", r"ASP\.NET"),
    ("ASP.NET", "header:X-AspNet-Version", r".+"),
    ("Express", "header:X-Powered-By", r"Express"),
    ("Next.js", "header:X-Powered-By", r"Next\.js"),
    ("Django", "header:X-Frame-Options", r"^SAMEORIGIN$"),  # faible signal
    ("Laravel", "cookie", r"laravel_session|XSRF-TOKEN"),
    ("WordPress", "html", r"/wp-content/|/wp-includes/|<meta name=\"generator\" content=\"WordPress"),
    ("Drupal", "html", r"Drupal\.settings|/sites/all/|/sites/default/"),
    ("Joomla", "html", r"/media/system/js/|Joomla!"),
    ("Magento", "html", r"Mage\.Cookies|/skin/frontend/"),
    ("Shopify", "html", r"cdn\.shopify\.com|Shopify\.theme"),
    ("React", "html", r"__REACT_DEVTOOLS_GLOBAL_HOOK__|data-reactroot"),
    ("Vue.js", "html", r"__vue__|data-v-[0-9a-f]{8}"),
    ("Angular", "html", r"ng-version=\"|ng-app"),
    ("jQuery", "html", r"jquery(?:[.-]([\d.]+))?(?:\.min)?\.js"),
    ("Bootstrap", "html", r"bootstrap(?:[.-]([\d.]+))?(?:\.min)?\.(?:css|js)"),
    ("Tailwind", "html", r"tailwindcss|tw-"),
    ("Wix", "html", r"static\.wixstatic\.com"),
    ("Squarespace", "html", r"static\.squarespace\.com"),
    ("Ghost", "html", r"ghost\.min\.js|<meta name=\"generator\" content=\"Ghost"),
    ("Kubernetes Ingress", "header:Server", r"kubernetes"),
    ("Varnish", "header:Via", r"varnish"),
    ("Fastly", "header:X-Served-By", r"cache-"),
    ("Akamai", "header:Server", r"AkamaiGHost"),
    ("AWS CloudFront", "header:Via", r"CloudFront"),
    ("HSTS enabled", "header:Strict-Transport-Security", r".+"),
]


class Recon:
    def __init__(self, target: str, http: HttpClient, verbose: bool = False) -> None:
        self.target = target
        self.http = http
        self.verbose = verbose
        parsed = urlparse(target)
        self.host = parsed.netloc.split(":")[0]
        self.scheme = parsed.scheme

    # ------------------------- DNS -----------------------------------------
    def dns_records(self) -> Dict[str, List[str]]:
        log_info(f"Résolution DNS pour {C.BOLD}{self.host}{C.RESET}")
        records: Dict[str, List[str]] = {}
        if HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5.0
            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
                try:
                    answers = resolver.resolve(self.host, rtype)
                    records[rtype] = sorted({r.to_text().strip('"') for r in answers})
                except Exception:
                    continue
        else:
            try:
                infos = socket.getaddrinfo(self.host, None)
                records["A"] = sorted({i[4][0] for i in infos if ":" not in i[4][0]})
                records["AAAA"] = sorted({i[4][0] for i in infos if ":" in i[4][0]})
            except Exception:
                pass
        for rtype, vals in records.items():
            for v in vals:
                log_ok(f"{rtype:>5}  {v}")
        return records

    # ------------------------- Sous-domaines -------------------------------
    def _crtsh(self) -> Set[str]:
        found: Set[str] = set()
        url = f"https://crt.sh/?q=%25.{self.host}&output=json"
        r = self.http.get(url)
        if not r or r.status_code != 200:
            log_warn("crt.sh injoignable (source passive ignorée)")
            return found
        try:
            data = r.json()
        except ValueError:
            return found
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lower().lstrip("*.")
                if line.endswith(self.host) and " " not in line:
                    found.add(line)
        return found

    def _resolve(self, name: str) -> Optional[str]:
        try:
            return socket.gethostbyname(name)
        except Exception:
            return None

    def enumerate_subdomains(
        self,
        wordlist_path: Optional[Path] = None,
        threads: int = 50,
        use_passive: bool = True,
    ) -> Dict[str, str]:
        log_info(f"Énumération de sous-domaines pour {C.BOLD}{self.host}{C.RESET}")
        candidates: Set[str] = set()

        if use_passive:
            passive = self._crtsh()
            if passive:
                log_ok(f"crt.sh : {len(passive)} entrée(s) passive(s)")
            candidates |= passive

        if wordlist_path and wordlist_path.exists():
            words = [
                w.strip() for w in wordlist_path.read_text().splitlines()
                if w.strip() and not w.startswith("#")
            ]
            candidates |= {f"{w}.{self.host}" for w in words}
            log_debug(f"Bruteforce sur {len(words)} préfixes", self.verbose)

        resolved: Dict[str, str] = {}
        with cf.ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(self._resolve, c): c for c in candidates}
            for fut in cf.as_completed(futs):
                name = futs[fut]
                ip = fut.result()
                if ip:
                    resolved[name] = ip
                    log_ok(f"{name}  →  {ip}")
        log_info(f"{len(resolved)} sous-domaine(s) résolu(s)")
        return resolved

    # ------------------------- Fingerprint ---------------------------------
    def fingerprint(self) -> Tuple[List[str], List[Finding]]:
        log_info(f"Fingerprinting {C.BOLD}{self.target}{C.RESET}")
        r = self.http.get(self.target)
        techs: List[str] = []
        findings: List[Finding] = []
        if not r:
            log_warn("Aucune réponse de la cible pour le fingerprinting")
            return techs, findings

        headers = {k.lower(): v for k, v in r.headers.items()}
        html = r.text or ""
        cookies = "; ".join(f"{c.name}={c.value}" for c in r.cookies)

        for tech, where, pattern in TECH_SIGNATURES:
            src = ""
            if where.startswith("header:"):
                h = where.split(":", 1)[1].lower()
                src = headers.get(h, "")
            elif where == "html":
                src = html[:200_000]  # limite mémoire
            elif where == "cookie":
                src = cookies
            if not src:
                continue
            m = re.search(pattern, src, re.IGNORECASE)
            if m:
                version = ""
                if m.groups():
                    version = next((g for g in m.groups() if g), "")
                label = f"{tech}" + (f" {version}" if version else "")
                if label not in techs:
                    techs.append(label)

        for t in techs:
            log_ok(f"Techno détectée : {t}")
            findings.append(
                Finding(
                    module="recon",
                    title=f"Technologie détectée : {t}",
                    severity="info",
                    url=self.target,
                    description=f"L'application expose ou révèle l'usage de {t}.",
                    evidence=t,
                    remediation="Masquer ou minimiser les bannières et versions exposées.",
                )
            )

        # Bannière serveur brute
        if "server" in headers:
            findings.append(
                Finding(
                    module="recon",
                    title="Bannière Server exposée",
                    severity="low",
                    url=self.target,
                    description="L'en-tête Server dévoile la pile logicielle.",
                    evidence=f"Server: {headers['server']}",
                    remediation="Supprimer ou anonymiser l'en-tête Server.",
                )
            )
        if "x-powered-by" in headers:
            findings.append(
                Finding(
                    module="recon",
                    title="En-tête X-Powered-By exposé",
                    severity="low",
                    url=self.target,
                    description="X-Powered-By révèle la technologie côté serveur.",
                    evidence=f"X-Powered-By: {headers['x-powered-by']}",
                    remediation="Supprimer l'en-tête X-Powered-By.",
                )
            )
        return techs, findings

    # ------------------------- robots.txt / sitemap ------------------------
    def robots_and_sitemap(self) -> Tuple[List[str], List[Finding]]:
        paths: Set[str] = set()
        findings: List[Finding] = []
        for name in ("robots.txt", "sitemap.xml"):
            url = urljoin(self.target + "/", name)
            r = self.http.get(url)
            if not r or r.status_code >= 400:
                continue
            log_ok(f"{name} accessible")
            findings.append(
                Finding(
                    module="recon",
                    title=f"{name} accessible",
                    severity="info",
                    url=url,
                    description=f"Le fichier {name} est accessible publiquement.",
                    evidence=f"HTTP {r.status_code}, {len(r.text)} octets",
                )
            )
            if name == "robots.txt":
                for line in r.text.splitlines():
                    m = re.match(r"^\s*(?:Allow|Disallow|Sitemap)\s*:\s*(.+)$", line, re.I)
                    if m:
                        paths.add(m.group(1).strip())
            else:
                for m in re.finditer(r"<loc>([^<]+)</loc>", r.text, re.I):
                    paths.add(m.group(1).strip())
        if paths:
            log_info(f"{len(paths)} chemin(s) extrait(s) de robots/sitemap")
        return sorted(paths), findings
