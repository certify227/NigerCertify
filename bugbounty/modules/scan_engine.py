"""Moteur d'orchestration central BountyStrike."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import requests

from .aggressive import AggressiveScanner
from .api_scanner import APIScanner
from .auth_context import apply_auth
from .brand import TOOL_NAME
from .business_logic import BusinessLogicScanner
from .cloud_enum import CloudEnumerator
from .database import ScanDatabase
from .exporters import ReportExporter
from .fuzzer import FuzzerModule
from .git_dumper import ClickjackCSPScanner, GitDumper
from .graphql_fuzzer import GraphQLFuzzer
from .graphql_scanner import GraphQLScanner
from .infra_scanner import InfraScanner
from .injection_advanced import InjectionAdvancedScanner
from .integrations import ExternalToolsIntegration, WAFDetector
from .jwt_scanner import JWTScanner
from .nosql_scanner import NoSQLScanner
from .nuclei_scanner import NucleiScanner
from .oauth_scanner import OAuthScanner
from .oob_scanner import OOBScanner
from .passive_recon import PassiveRecon
from .recon import ReconModule
from .reporter import ReportGenerator
from .scanner import VulnScanner
from .scope import ScopeManager
from .smuggling import SmugglingScanner
from .sqli_blind import BlindSQLiScanner
from .ssrf_scanner import SSRFScanner
from .takeover import TakeoverScanner
from .upload_scanner import UploadScanner
from .utils import Colors, Finding, create_session, get_domain, normalize_url, print_finding, safe_request
from .websocket_scanner import WebSocketScanner
from .xss_advanced import XSSAdvancedScanner


@dataclass
class ScanConfig:
    """Configuration d'un scan BountyStrike."""

    target: str
    full: bool = False
    recon: bool = False
    scan: bool = False
    fuzz: bool = False
    aggressive: bool = False
    brutal: bool = False
    jwt: bool = False
    graphql: bool = False
    graphql_fuzz: bool = False
    ssrf: bool = False
    takeover: bool = False
    nuclei: bool = False
    extended: bool = False
    threads: int = 10
    timeout: int = 10
    proxy: str | None = None
    no_ssl_verify: bool = False
    bearer: str | None = None
    cookie: str | None = None
    auth_header: str | None = None
    oob_callback: str | None = None
    shodan_key: str | None = None
    nuclei_templates: str | None = None
    scope_file: Path | None = None
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    quiet: bool = False
    verbose: bool = False
    use_external_tools: bool = False
    save_db: bool = True


class ScanEngine:
    """Orchestre tous les modules de scan."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.target = normalize_url(config.target)
        self.session = create_session(
            timeout=config.timeout,
            verify_ssl=not config.no_ssl_verify,
            proxy=config.proxy,
        )
        apply_auth(self.session, config.bearer, config.cookie, config.auth_header)
        self.scope = ScopeManager(config.scope_file, get_domain(self.target))
        self.findings: list[Finding] = []
        self.recon_data: dict = {}
        self.urls: list[str] = [self.target]
        self.subdomains: list[str] = []
        self.gql_endpoints: list[str] = []

    def _log(self, msg: str) -> None:
        if not self.config.quiet:
            print(msg)

    def _extend_brutal(self) -> None:
        c = self.config
        if c.brutal:
            c.full = c.aggressive = c.jwt = c.graphql = c.graphql_fuzz = True
            c.ssrf = c.takeover = c.nuclei = c.extended = True
            c.use_external_tools = True
        if c.full:
            c.jwt = c.graphql = c.graphql_fuzz = c.aggressive = True
            c.ssrf = c.takeover = c.extended = True
        if c.extended:
            c.jwt = c.graphql = c.graphql_fuzz = c.aggressive = True
            c.ssrf = c.takeover = True

    def run(self) -> list[Finding]:
        self._extend_brutal()
        c = self.config

        if not self.scope.is_in_scope(self.target):
            self._log(f"{Colors.YELLOW}[!] Cible hors scope — skip{Colors.RESET}")
            return []

        # RECON
        if c.full or c.recon or c.extended:
            self._log(f"{Colors.BLUE}[+] Reconnaissance...{Colors.RESET}")
            recon = ReconModule(self.target, session=self.session, threads=c.threads)
            self.recon_data = recon.run_full_recon()
            self.findings.extend(recon.findings)
            self.urls = self.recon_data.get("links", [self.target])
            self.subdomains = self.recon_data.get("subdomains", [])

        # PASSIVE RECON
        if c.full or c.extended or c.recon:
            self._log(f"{Colors.BLUE}[+] Recon passive (crt.sh, Wayback)...{Colors.RESET}")
            passive = PassiveRecon(self.target, self.session, c.shodan_key)
            pdata = passive.run_full_scan()
            self.findings.extend(passive.findings)
            self.subdomains = list(set(self.subdomains + pdata.get("crt_subdomains", [])))
            self.recon_data["passive"] = pdata

        # INFRA
        if c.full or c.extended:
            self._log(f"{Colors.BLUE}[+] Infra (TLS, email, vhost)...{Colors.RESET}")
            self.findings.extend(InfraScanner(self.target, self.session, c.threads).run_full_scan())

        # CLOUD
        if c.full or c.extended or c.brutal:
            self._log(f"{Colors.BLUE}[+] Énumération cloud...{Colors.RESET}")
            self.findings.extend(CloudEnumerator(self.target, self.session).run_full_scan())

        # WAF
        if c.full or c.extended:
            self._log(f"{Colors.BLUE}[+] Détection WAF...{Colors.RESET}")
            self.findings.extend(WAFDetector(self.target, self.session).run_full_scan())

        # SCAN
        if c.full or c.scan:
            self._log(f"{Colors.BLUE}[+] Scan vulnérabilités...{Colors.RESET}")
            self.findings.extend(VulnScanner(self.target, self.session, c.threads, c.aggressive or c.brutal).run_full_scan(self.urls))

        # AGGRESSIVE
        if c.aggressive or c.brutal or c.extended:
            self._log(f"{Colors.RED}[+] Scan agressif...{Colors.RESET}")
            self.findings.extend(AggressiveScanner(self.target, self.session, c.threads).run_full_scan(self.urls))

        # XSS ADVANCED
        if c.extended or c.brutal or c.aggressive:
            self._log(f"{Colors.RED}[+] XSS avancé (DOM, blind, stored)...{Colors.RESET}")
            self.findings.extend(XSSAdvancedScanner(self.target, self.session, c.oob_callback).run_full_scan(self.urls))

        # SQLi BLIND
        if c.extended or c.brutal or c.aggressive:
            self._log(f"{Colors.RED}[+] SQLi aveugle...{Colors.RESET}")
            self.findings.extend(BlindSQLiScanner(self.target, self.session).run_full_scan(self.urls))

        # NOSQL
        if c.extended or c.brutal:
            self._log(f"{Colors.RED}[+] NoSQL injection...{Colors.RESET}")
            self.findings.extend(NoSQLScanner(self.target, self.session).run_full_scan())

        # UPLOAD
        if c.extended or c.brutal:
            self._log(f"{Colors.RED}[+] Upload fichiers...{Colors.RESET}")
            self.findings.extend(UploadScanner(self.target, self.session).run_full_scan())

        # SSRF
        if c.ssrf or c.brutal or c.extended:
            self._log(f"{Colors.RED}[+] SSRF avancé...{Colors.RESET}")
            ssrf = SSRFScanner(self.target, self.session, c.threads)
            self.findings.extend(ssrf.run_full_scan(self.urls))
            for url in self.urls[:3]:
                ssrf.test_blind_ssrf("url", url.split("?")[0])

        # OOB
        if c.oob_callback and (c.extended or c.brutal):
            self._log(f"{Colors.RED}[+] OOB callbacks...{Colors.RESET}")
            self.findings.extend(OOBScanner(self.target, self.session, c.oob_callback).run_full_scan(self.urls))

        # TAKEOVER
        if c.takeover or c.brutal or c.extended:
            self._log(f"{Colors.RED}[+] Subdomain takeover...{Colors.RESET}")
            self.findings.extend(TakeoverScanner(self.target, self.session, self.subdomains, c.threads).run_full_scan())

        # JWT
        if c.jwt or c.brutal:
            self._log(f"{Colors.MAGENTA}[+] JWT...{Colors.RESET}")
            self.findings.extend(JWTScanner(self.target, self.session).run_full_scan())

        # GRAPHQL
        if c.graphql or c.brutal:
            self._log(f"{Colors.MAGENTA}[+] GraphQL...{Colors.RESET}")
            gql = GraphQLScanner(self.target, self.session)
            self.findings.extend(gql.run_full_scan())
            self.gql_endpoints = gql.endpoints

        if c.graphql_fuzz or c.brutal:
            self._log(f"{Colors.MAGENTA}[+] GraphQL fuzzing...{Colors.RESET}")
            self.findings.extend(GraphQLFuzzer(self.target, self.session, self.gql_endpoints or None).run_full_scan())

        # OAUTH / ACCOUNT TAKEOVER
        if c.extended or c.brutal:
            self._log(f"{Colors.MAGENTA}[+] OAuth / Account Takeover...{Colors.RESET}")
            self.findings.extend(OAuthScanner(self.target, self.session).run_full_scan())

        # WEBSOCKET
        if c.extended or c.brutal:
            self._log(f"{Colors.MAGENTA}[+] WebSocket...{Colors.RESET}")
            self.findings.extend(WebSocketScanner(self.target, self.session).run_full_scan())

        # API / OpenAPI
        if c.extended or c.brutal:
            self._log(f"{Colors.MAGENTA}[+] API / OpenAPI...{Colors.RESET}")
            self.findings.extend(APIScanner(self.target, self.session).run_full_scan())

        # SMUGGLING
        if c.extended or c.brutal:
            self._log(f"{Colors.RED}[+] HTTP Request Smuggling...{Colors.RESET}")
            self.findings.extend(SmugglingScanner(self.target).run_full_scan())

        # INJECTIONS ADVANCED
        if c.extended or c.brutal:
            self._log(f"{Colors.RED}[+] LDAP / Prototype pollution / Deser...{Colors.RESET}")
            self.findings.extend(InjectionAdvancedScanner(self.target, self.session).run_full_scan())

        # BUSINESS LOGIC
        if c.extended or c.brutal:
            self._log(f"{Colors.RED}[+] Business logic / Race conditions...{Colors.RESET}")
            self.findings.extend(BusinessLogicScanner(self.target, self.session).run_full_scan())

        # GIT / CLICKJACK / CSP
        if c.extended or c.brutal:
            self._log(f"{Colors.RED}[+] Git dump / Clickjacking / CSP...{Colors.RESET}")
            self.findings.extend(GitDumper(self.target, self.session).run_full_scan())
            self.findings.extend(ClickjackCSPScanner(self.target, self.session).run_full_scan())

        # NUCLEI
        if c.nuclei or c.brutal:
            self._log(f"{Colors.RED}[+] Nuclei / CVE...{Colors.RESET}")
            self.findings.extend(NucleiScanner(self.target, self.session, c.nuclei_templates).run_full_scan())

        # FUZZ
        if c.full or c.fuzz:
            self._log(f"{Colors.BLUE}[+] Fuzzing...{Colors.RESET}")
            fuzzer = FuzzerModule(self.target, self.session, c.threads)
            fuzzer.fuzz_directories()
            fuzzer.fuzz_parameters()
            fuzzer.discover_endpoints_from_js()
            self.findings.extend(fuzzer.findings)

        # EXTERNAL TOOLS
        if c.use_external_tools or c.brutal:
            self._log(f"{Colors.CYAN}[+] Outils externes (ffuf, dalfox, sqlmap)...{Colors.RESET}")
            self.findings.extend(ExternalToolsIntegration(self.target, c.output_dir).run_all())

        return self._deduplicate()

    def _deduplicate(self) -> list[Finding]:
        seen: set[str] = set()
        unique = []
        for f in self.findings:
            key = f"{f.title}|{f.url}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique
        return unique

    def print_findings(self) -> None:
        for f in self.findings:
            if self.config.verbose or f.severity in ("critical", "high", "medium"):
                print_finding(f)
