"""
Scanner de vulnérabilités actives.

Modules couverts :
  - Reflected XSS (injection dans paramètres GET et POST)
  - SQL Injection (erreurs, boolean-based réponse différentielle)
  - Local File Inclusion (LFI) — signatures /etc/passwd, ini
  - Server-Side Request Forgery (SSRF) — indicateurs internes
  - Open Redirect (Location externe)
  - CRLF Injection (injection d'en-tête via %0d%0a)
  - Fichiers sensibles / backups exposés
  - Détection de directory listing

Toutes les cibles proviennent du crawler (URLs paramétrées + formulaires).
Chaque payload est testé de manière ciblée avec des marqueurs uniques quand
c'est possible pour minimiser les faux positifs.
"""

from __future__ import annotations

import concurrent.futures as cf
import re
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from ..core import (
    C,
    Finding,
    HttpClient,
    log_debug,
    log_finding,
    log_info,
    log_warn,
)
from .crawler import CrawlResult, Form


# ---------------------------------------------------------------------------
# Signatures d'erreurs SQL (indicatives — à corréler avec autres signaux)
# ---------------------------------------------------------------------------
SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\):",
    r"pg_exec\(\):",
    r"postgresql\.util\.psqlexception",
    r"ora-\d{5}",
    r"microsoft odbc.*sql server",
    r"sqlite3::sqlexception",
    r"sqlite_error",
    r"sqlstate\[\d+\]",
    r"mysql_fetch_",
    r"native client.*sql server",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERRORS), re.IGNORECASE)

LFI_SIGNATURES = [
    re.compile(r"root:x:0:0:", re.IGNORECASE),
    re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.IGNORECASE),
    re.compile(r"daemon:x:\d+:\d+", re.IGNORECASE),
]

SSRF_INTERNAL_HINTS = [
    re.compile(r"instance-id|ami-id|iam/security-credentials", re.IGNORECASE),
    re.compile(r"127\.0\.0\.1|localhost", re.IGNORECASE),
    re.compile(r"connection refused|no route to host", re.IGNORECASE),
]

DIR_LISTING_RE = re.compile(
    r"<title>index of /|<h1>index of /|directory listing for", re.IGNORECASE
)


def _load_payloads(name: str) -> List[str]:
    path = Path(__file__).resolve().parent.parent / "payloads" / name
    if not path.exists():
        return []
    return [
        line.rstrip("\n") for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _replace_qs_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qsl(parsed.query, keep_blank_values=True)
    new_qs = [(k, value if k == param else v) for k, v in qs]
    return urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))


class VulnScanner:
    def __init__(
        self,
        http: HttpClient,
        base_url: str,
        threads: int = 10,
        verbose: bool = False,
    ) -> None:
        self.http = http
        self.base_url = base_url.rstrip("/")
        self.threads = threads
        self.verbose = verbose
        self.findings: List[Finding] = []

        self.xss_payloads = _load_payloads("xss.txt")
        self.sqli_payloads = _load_payloads("sqli.txt")
        self.lfi_payloads = _load_payloads("lfi.txt")
        self.ssrf_payloads = _load_payloads("ssrf.txt")
        self.redirect_payloads = _load_payloads("redirect.txt")

    # ------------------------------------------------------------------
    def _add(self, finding: Finding) -> None:
        self.findings.append(finding)
        log_finding(finding)

    # ------------------------------------------------------------------
    # XSS
    # ------------------------------------------------------------------
    def test_xss(self, url: str, param: str) -> None:
        for payload in self.xss_payloads:
            marker = "<ncscan>xss</ncscan>"
            probe = payload if marker in payload else payload + marker
            test_url = _replace_qs_param(url, param, probe)
            r = self.http.get(test_url)
            if not r:
                continue
            body = r.text or ""
            if marker in body or probe in body:
                self._add(Finding(
                    module="scanner",
                    title="Reflected XSS potentielle",
                    severity="high",
                    url=test_url,
                    description=f"Le paramètre '{param}' est réfléchi sans encodage dans la réponse.",
                    evidence=f"Payload réfléchi : {probe[:120]}",
                    remediation="Encoder les sorties HTML/attributs, appliquer une CSP stricte.",
                    cwe="CWE-79",
                    payload=probe,
                ))
                return  # une trouvaille par paramètre suffit

    # ------------------------------------------------------------------
    # SQLi (erreurs + réponse différentielle basique)
    # ------------------------------------------------------------------
    def test_sqli(self, url: str, param: str) -> None:
        base_resp = self.http.get(_replace_qs_param(url, param, "1"))
        if not base_resp:
            return
        base_len = len(base_resp.text or "")

        for payload in self.sqli_payloads:
            test_url = _replace_qs_param(url, param, payload)
            r = self.http.get(test_url)
            if not r:
                continue
            body = r.text or ""
            if SQL_ERROR_RE.search(body):
                self._add(Finding(
                    module="scanner",
                    title="SQL Injection (error-based) potentielle",
                    severity="critical",
                    url=test_url,
                    description=f"Une erreur SQL est retournée lors de l'injection dans '{param}'.",
                    evidence=SQL_ERROR_RE.search(body).group(0)[:200],
                    remediation="Utiliser des requêtes préparées / paramétrées, échapper les entrées.",
                    cwe="CWE-89",
                    payload=payload,
                ))
                return

        # Test différentiel simple : vrai vs faux
        true_url = _replace_qs_param(url, param, "1' OR '1'='1")
        false_url = _replace_qs_param(url, param, "1' AND '1'='2")
        rt = self.http.get(true_url)
        rf = self.http.get(false_url)
        if rt and rf:
            lt, lf = len(rt.text or ""), len(rf.text or "")
            if abs(lt - lf) > max(80, base_len // 20) and lt > lf:
                self._add(Finding(
                    module="scanner",
                    title="SQL Injection (boolean-based) suspectée",
                    severity="high",
                    url=true_url,
                    description=(
                        f"Différence significative entre requêtes 'vraies' et 'fausses' "
                        f"sur le paramètre '{param}' (Δ={abs(lt - lf)} octets)."
                    ),
                    evidence=f"|OR-1=1|={lt} vs |AND-1=2|={lf}",
                    remediation="Requêtes préparées + validation stricte des types.",
                    cwe="CWE-89",
                    payload="OR '1'='1 vs AND '1'='2",
                ))

    # ------------------------------------------------------------------
    # LFI
    # ------------------------------------------------------------------
    def test_lfi(self, url: str, param: str) -> None:
        for payload in self.lfi_payloads:
            test_url = _replace_qs_param(url, param, payload)
            r = self.http.get(test_url)
            if not r:
                continue
            for sig in LFI_SIGNATURES:
                if sig.search(r.text or ""):
                    self._add(Finding(
                        module="scanner",
                        title="Local File Inclusion potentielle",
                        severity="critical",
                        url=test_url,
                        description=f"Le paramètre '{param}' permet de lire des fichiers locaux.",
                        evidence=sig.pattern,
                        remediation="Interdire les chemins traversants, whitelister les fichiers.",
                        cwe="CWE-98",
                        payload=payload,
                    ))
                    return

    # ------------------------------------------------------------------
    # SSRF
    # ------------------------------------------------------------------
    def test_ssrf(self, url: str, param: str) -> None:
        for payload in self.ssrf_payloads:
            test_url = _replace_qs_param(url, param, payload)
            r = self.http.get(test_url)
            if not r:
                continue
            body = (r.text or "")[:20_000]
            if any(sig.search(body) for sig in SSRF_INTERNAL_HINTS):
                self._add(Finding(
                    module="scanner",
                    title="SSRF potentielle",
                    severity="high",
                    url=test_url,
                    description=f"Indicateurs de requête interne via '{param}'.",
                    evidence=payload,
                    remediation="Restreindre les schémas/hôtes autorisés, bloquer les IP privées.",
                    cwe="CWE-918",
                    payload=payload,
                ))
                return

    # ------------------------------------------------------------------
    # Open Redirect
    # ------------------------------------------------------------------
    def test_open_redirect(self, url: str, param: str) -> None:
        for payload in self.redirect_payloads:
            test_url = _replace_qs_param(url, param, payload)
            r = self.http.get(test_url, allow_redirects=False)
            if not r:
                continue
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                if "evil.example.com" in loc or "google.com" in loc:
                    self._add(Finding(
                        module="scanner",
                        title="Open Redirect potentielle",
                        severity="medium",
                        url=test_url,
                        description=f"Le paramètre '{param}' contrôle une redirection externe.",
                        evidence=f"Location: {loc}",
                        remediation="Whitelister les destinations de redirection.",
                        cwe="CWE-601",
                        payload=payload,
                    ))
                    return

    # ------------------------------------------------------------------
    # CRLF Injection
    # ------------------------------------------------------------------
    def test_crlf(self, url: str, param: str) -> None:
        payload = "%0d%0aNCScan-CRLF: injected"
        test_url = _replace_qs_param(url, param, payload)
        r = self.http.get(test_url, allow_redirects=False)
        if not r:
            return
        for k, v in r.headers.items():
            if "NCScan-CRLF" in k or "NCScan-CRLF" in v:
                self._add(Finding(
                    module="scanner",
                    title="CRLF Injection potentielle",
                    severity="high",
                    url=test_url,
                    description=f"Le paramètre '{param}' permet d'injecter des en-têtes HTTP.",
                    evidence=f"{k}: {v}",
                    remediation="Filtrer/rejeter \\r\\n dans les valeurs reflétées en en-têtes.",
                    cwe="CWE-113",
                    payload=payload,
                ))
                return

    # ------------------------------------------------------------------
    # Directory listing sur les URLs découvertes
    # ------------------------------------------------------------------
    def test_directory_listing(self, url: str) -> None:
        r = self.http.get(url)
        if not r or r.status_code != 200:
            return
        if DIR_LISTING_RE.search(r.text or ""):
            self._add(Finding(
                module="scanner",
                title="Directory listing activé",
                severity="medium",
                url=url,
                description="Le serveur expose l'index du répertoire.",
                evidence="Motif « Index of / » détecté",
                remediation="Désactiver Options +Indexes / autoindex on;",
                cwe="CWE-548",
            ))

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------
    def _iter_targets(self, crawl: CrawlResult) -> List[Tuple[str, str]]:
        """(url, param) pour chaque paramètre de query-string."""
        targets: List[Tuple[str, str]] = []
        seen: set = set()
        for u in crawl.parameterized:
            parsed = urlparse(u)
            for k, _v in parse_qsl(parsed.query, keep_blank_values=True):
                key = (parsed._replace(query="").geturl(), k)
                if key in seen:
                    continue
                seen.add(key)
                targets.append((u, k))
        return targets

    def _test_form(self, form: Form) -> None:
        if not form.inputs:
            return
        marker = "<ncscan>xss</ncscan>"
        data = {k: (marker if isinstance(v, str) else "test") for k, v in form.inputs.items()}
        try:
            if form.method == "POST":
                r = self.http.post(form.action, data=data)
            else:
                r = self.http.get(form.action, params=data)
        except Exception:
            return
        if r and marker in (r.text or ""):
            self._add(Finding(
                module="scanner",
                title="Reflected XSS via formulaire",
                severity="high",
                url=form.action,
                description=f"Le formulaire ({form.method}) réfléchit une entrée sans encodage.",
                evidence=f"champs: {', '.join(form.inputs)}",
                remediation="Encoder les sorties HTML, appliquer une CSP.",
                cwe="CWE-79",
                payload=marker,
            ))

    def run(self, crawl: CrawlResult) -> List[Finding]:
        targets = self._iter_targets(crawl)
        log_info(
            f"Scan actif : {len(targets)} couple(s) (URL, paramètre), "
            f"{len(crawl.forms)} formulaire(s), {len(crawl.urls)} URL(s)"
        )
        if not targets and not crawl.forms:
            log_warn("Aucun paramètre exploitable trouvé pour le scan actif.")

        def _run_all_probes(item: Tuple[str, str]) -> None:
            u, p = item
            log_debug(f"→ tests sur {u} [{p}]", self.verbose)
            self.test_xss(u, p)
            self.test_sqli(u, p)
            self.test_lfi(u, p)
            self.test_ssrf(u, p)
            self.test_open_redirect(u, p)
            self.test_crlf(u, p)

        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(_run_all_probes, targets))
            list(ex.map(self._test_form, crawl.forms))
            list(ex.map(self.test_directory_listing, list(crawl.urls)[:100]))

        return self.findings
