"""Reconnaissance passive — crt.sh, Wayback Machine."""

from __future__ import annotations

import json
import re
from typing import Any

import requests

from .utils import Finding, get_domain, normalize_url, safe_request


class PassiveRecon:
    """Recon passive via sources OSINT."""

    def __init__(self, target: str, session: requests.Session, shodan_key: str | None = None):
        self.target = normalize_url(target)
        self.domain = get_domain(self.target)
        self.session = session
        self.shodan_key = shodan_key
        self.findings: list[Finding] = []
        self.data: dict[str, Any] = {
            "crt_subdomains": [],
            "wayback_urls": [],
            "shodan_hosts": [],
        }

    def run_full_scan(self) -> dict[str, Any]:
        self._crt_sh()
        self._wayback()
        if self.shodan_key:
            self._shodan()
        self.data["findings"] = [f.to_dict() for f in self.findings]
        return self.data

    def _crt_sh(self) -> None:
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                return
            entries = resp.json()
            subdomains: set[str] = set()
            for entry in entries:
                name = entry.get("name_value", "")
                for part in name.split("\n"):
                    part = part.strip().lower()
                    if part.endswith(self.domain) and "*" not in part:
                        subdomains.add(part)
            self.data["crt_subdomains"] = sorted(subdomains)
            for sd in list(subdomains)[:30]:
                self.findings.append(
                    Finding(
                        title=f"Sous-domaine (crt.sh): {sd}",
                        severity="info",
                        category="Passive Recon",
                        url=f"https://{sd}",
                        description="Découvert via Certificate Transparency",
                        evidence="crt.sh",
                    )
                )
        except (requests.RequestException, json.JSONDecodeError, KeyError):
            pass

    def _wayback(self) -> None:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey&limit=200"
        try:
            resp = requests.get(url, timeout=20)
            if resp.status_code != 200:
                return
            data = resp.json()
            urls: list[str] = []
            for row in data[1:]:
                if row and row[0].startswith("http"):
                    urls.append(row[0])
            self.data["wayback_urls"] = urls[:100]
            interesting = [u for u in urls if re.search(r"(admin|api|backup|config|\.env|\.git|debug|test|staging)", u, re.I)]
            for u in interesting[:15]:
                self.findings.append(
                    Finding(
                        title=f"URL historique intéressante",
                        severity="info",
                        category="Passive Recon",
                        url=u,
                        description="URL découverte via Wayback Machine",
                        evidence=u,
                    )
                )
        except (requests.RequestException, json.JSONDecodeError, IndexError):
            pass

    def _shodan(self) -> None:
        if not self.shodan_key:
            return
        try:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/search?key={self.shodan_key}&query=hostname:{self.domain}",
                timeout=15,
            )
            if resp.status_code != 200:
                return
            data = resp.json()
            for match in data.get("matches", [])[:10]:
                ip = match.get("ip_str", "")
                port = match.get("port", "")
                product = match.get("product", "")
                self.data["shodan_hosts"].append({"ip": ip, "port": port, "product": product})
                self.findings.append(
                    Finding(
                        title=f"Shodan: {ip}:{port} ({product})",
                        severity="info",
                        category="Passive Recon",
                        url=f"http://{ip}:{port}",
                        description=f"Service exposé découvert via Shodan",
                        evidence=str(match.get("data", ""))[:200],
                    )
                )
        except requests.RequestException:
            pass
