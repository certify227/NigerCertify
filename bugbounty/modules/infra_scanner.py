"""Vhost discovery, TLS et email security."""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

from .utils import Finding, get_domain, normalize_url, resolve_host, safe_request

VHOST_WORDLIST = ["admin", "api", "dev", "staging", "test", "internal", "portal", "mail", "vpn", "beta"]


class InfraScanner:
    """Vhost, TLS avancé, SPF/DMARC/DKIM."""

    def __init__(self, target: str, session: requests.Session, threads: int = 10):
        self.target = normalize_url(target)
        self.domain = get_domain(self.target)
        self.session = session
        self.threads = threads
        self.findings: list[Finding] = []

    def run_full_scan(self) -> list[Finding]:
        self.scan_tls()
        self.scan_email_security()
        self.scan_vhosts()
        return self.findings

    def scan_tls(self) -> None:
        host = self.domain
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        self.findings.append(
                            Finding(
                                title=f"TLS obsolète: {version}",
                                severity="high",
                                category="TLS",
                                url=self.target,
                                description=f"Protocole TLS faible: {version}",
                                evidence=str(cipher),
                                remediation="Désactiver TLS < 1.2",
                            )
                        )
                    if cipher and cipher[0]:
                        weak = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
                        if any(w in cipher[0].upper() for w in weak):
                            self.findings.append(
                                Finding(
                                    title=f"Cipher faible: {cipher[0]}",
                                    severity="medium",
                                    category="TLS",
                                    url=self.target,
                                    description="Suite cryptographique faible",
                                    evidence=str(cipher),
                                )
                            )
        except (ssl.SSLError, socket.error, OSError) as e:
            self.findings.append(
                Finding(
                    title="Erreur TLS",
                    severity="medium",
                    category="TLS",
                    url=self.target,
                    description=str(e),
                )
            )

    def scan_email_security(self) -> None:
        try:
            import dns.resolver
            for rtype, label in (("TXT", "SPF"), ("TXT", "DMARC")):
                query_domain = self.domain if rtype == "TXT" else f"_dmarc.{self.domain}"
                try:
                    answers = dns.resolver.resolve(query_domain, rtype)
                    records = [str(r) for r in answers]
                    if label == "SPF" and not any("v=spf1" in r for r in records):
                        self.findings.append(
                            Finding(
                                title="SPF manquant",
                                severity="low",
                                category="Email Security",
                                url=self.target,
                                description="Aucun enregistrement SPF trouvé",
                                remediation="Ajouter un enregistrement SPF",
                            )
                        )
                    elif label == "DMARC":
                        dmarc = [r for r in records if "v=DMARC1" in r]
                        if not dmarc:
                            self.findings.append(
                                Finding(
                                    title="DMARC manquant",
                                    severity="medium",
                                    category="Email Security",
                                    url=self.target,
                                    description="Pas de politique DMARC",
                                    remediation="Configurer DMARC (p=reject ou quarantine)",
                                )
                            )
                        elif any("p=none" in d for d in dmarc):
                            self.findings.append(
                                Finding(
                                    title="DMARC policy p=none",
                                    severity="low",
                                    category="Email Security",
                                    url=self.target,
                                    description="DMARC en mode monitoring uniquement",
                                    evidence=str(dmarc),
                                )
                            )
                except Exception:
                    if label == "DMARC":
                        self.findings.append(
                            Finding(
                                title="DMARC manquant",
                                severity="medium",
                                category="Email Security",
                                url=self.target,
                                description="Enregistrement _dmarc introuvable",
                            )
                        )
        except ImportError:
            pass

    def scan_vhosts(self) -> None:
        ips = resolve_host(self.domain)
        if not ips:
            return
        ip = ips[0]
        baseline = safe_request(self.session, "GET", self.target, headers={"Host": self.domain})
        baseline_len = len(baseline.content) if baseline else 0

        def check_vhost(vhost: str) -> Finding | None:
            host = f"{vhost}.{self.domain}"
            resp = safe_request(
                self.session, "GET", f"https://{ip}/",
                headers={"Host": host},
                verify=False,
            )
            if resp and resp.status_code == 200 and abs(len(resp.content) - baseline_len) > 200:
                return Finding(
                    title=f"Vhost découvert: {host}",
                    severity="info",
                    category="Vhost Discovery",
                    url=f"https://{host}",
                    description=f"Virtual host actif sur {ip}",
                    evidence=f"Size: {len(resp.content)} vs baseline {baseline_len}",
                )
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            for f in as_completed({ex.submit(check_vhost, v): v for v in VHOST_WORDLIST}):
                result = f.result()
                if result:
                    self.findings.append(result)
