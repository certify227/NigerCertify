"""Énumération de sous-domaines : crt.sh (passif) + brute-force DNS."""
from __future__ import annotations

import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set

from ..core.findings import Finding, Severity
from ..core.http_client import HttpClient
from ..core.scope import registrable_root

try:
    import dns.resolver  # type: ignore

    HAVE_DNSPYTHON = True
except Exception:  # pragma: no cover
    HAVE_DNSPYTHON = False


DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "admin", "api",
    "dev", "staging", "stage", "test", "beta", "portal", "vpn", "ns1", "ns2",
    "cpanel", "whm", "autodiscover", "m", "mobile", "shop", "blog", "app",
    "apps", "cdn", "assets", "static", "img", "images", "media", "docs",
    "support", "help", "status", "dashboard", "git", "gitlab", "jenkins",
    "jira", "confluence", "grafana", "kibana", "prometheus", "internal",
    "intranet", "corp", "secure", "login", "sso", "auth", "oauth", "db",
    "database", "mysql", "postgres", "redis", "monitor", "backup", "old",
    "new", "demo", "sandbox", "uat", "preprod", "prod", "gateway", "proxy",
    "s3", "storage", "files", "download", "uploads", "cloud", "mx", "ns",
]


def _resolve(host: str) -> List[str]:
    """Résout un hôte en IPs ; renvoie [] si NXDOMAIN."""
    try:
        if HAVE_DNSPYTHON:
            answers = dns.resolver.resolve(host, "A", lifetime=4.0)
            return [r.to_text() for r in answers]
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


def _load_wordlist(path: str | None) -> List[str]:
    if not path or not os.path.isfile(path):
        return DEFAULT_SUBDOMAINS
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        words = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    return words or DEFAULT_SUBDOMAINS


def _crtsh(client: HttpClient, root: str) -> Set[str]:
    found: Set[str] = set()
    resp = client.get(f"https://crt.sh/?q=%25.{root}&output=json")
    if resp is None or resp.status_code != 200:
        return found
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return found
    for entry in data:
        name = entry.get("name_value", "")
        for sub in name.split("\n"):
            sub = sub.strip().lstrip("*.").lower()
            if sub.endswith(root):
                found.add(sub)
    return found


def run(client: HttpClient, url_or_host: str, ctx: dict | None = None) -> List[Finding]:
    ctx = ctx or {}
    threads = ctx.get("threads", 30)
    passive_only = ctx.get("passive", False)
    wordlist = ctx.get("subdomain_wordlist")

    host = url_or_host
    if "://" in host:
        from urllib.parse import urlparse

        host = urlparse(host).hostname or host
    root = registrable_root(host)

    candidates: Set[str] = set()
    # 1) Passif via crt.sh
    passive_found = _crtsh(client, root)
    candidates |= passive_found

    # 2) Brute-force DNS
    if not passive_only:
        for word in _load_wordlist(wordlist):
            candidates.add(f"{word}.{root}")
    candidates.add(root)
    candidates.add(f"www.{root}")

    findings: List[Finding] = []
    resolved = {}

    def check(sub: str):
        ips = _resolve(sub)
        return (sub, ips)

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = [pool.submit(check, sub) for sub in candidates]
        for fut in as_completed(futures):
            sub, ips = fut.result()
            if ips:
                resolved[sub] = ips

    for sub in sorted(resolved):
        ips = resolved[sub]
        via = "crt.sh" if sub in passive_found else "brute/dns"
        findings.append(
            Finding(
                title="Sous-domaine actif",
                severity=Severity.INFO,
                target=sub,
                module="subdomains",
                description=f"Sous-domaine résolu (source: {via}).",
                evidence=f"{sub} → {', '.join(ips)}",
                extra={"ips": ips, "source": via},
            )
        )

    if findings:
        findings.insert(
            0,
            Finding(
                title="Récapitulatif énumération sous-domaines",
                severity=Severity.INFO,
                target=root,
                module="subdomains",
                description="Nombre de sous-domaines actifs découverts.",
                evidence=f"{len(resolved)} sous-domaines résolus (crt.sh: {len(passive_found)}).",
            ),
        )
    return findings
