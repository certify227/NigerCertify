#!/usr/bin/env python3
"""
WebBounty — Outil de Bug Bounty pour applications web.

Usage éthique uniquement. N'utilisez cet outil que sur des cibles
pour lesquelles vous avez une autorisation explicite (programme de
bug bounty, pentest contractuel, lab personnel).

Auteur: Niger Certify Offensive Lab
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from modules.fuzzer import FuzzerModule
from modules.recon import ReconModule
from modules.reporter import ReportGenerator
from modules.scanner import VulnScanner
from modules.utils import Colors, create_session, normalize_url, print_banner, print_finding


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="WebBounty — Outil de reconnaissance et scan pour bug bounty web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python webbounty.py -t https://example.com --full
  python webbounty.py -t example.com --recon
  python webbounty.py -t https://target.com --scan --aggressive
  python webbounty.py -t https://target.com --fuzz --report report.html
        """,
    )
    parser.add_argument("-t", "--target", required=True, help="URL ou domaine cible")
    parser.add_argument("--full", action="store_true", help="Scan complet (recon + scan + fuzz)")
    parser.add_argument("--recon", action="store_true", help="Reconnaissance uniquement")
    parser.add_argument("--scan", action="store_true", help="Scan de vulnérabilités")
    parser.add_argument("--fuzz", action="store_true", help="Fuzzing répertoires/paramètres")
    parser.add_argument("--aggressive", action="store_true", help="Tests agressifs (SQLi, SSRF)")
    parser.add_argument("--threads", type=int, default=10, help="Nombre de threads (défaut: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout HTTP en secondes")
    parser.add_argument("--proxy", help="Proxy HTTP (ex: http://127.0.0.1:8080)")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Désactiver la vérification SSL")
    parser.add_argument("--report", help="Chemin du rapport HTML de sortie")
    parser.add_argument("--json", help="Chemin du rapport JSON de sortie")
    parser.add_argument("-o", "--output-dir", default="reports", help="Dossier de sortie des rapports")
    parser.add_argument("-q", "--quiet", action="store_true", help="Mode silencieux")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mode verbeux")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.quiet:
        print_banner()

    target = normalize_url(args.target)
    if not args.quiet:
        print(f"{Colors.GREEN}[*] Cible:{Colors.RESET} {target}")
        print(f"{Colors.YELLOW}[!] Assurez-vous d'avoir l'autorisation de tester cette cible{Colors.RESET}\n")

    # Si aucun mode spécifié, lancer le scan complet
    if not any([args.full, args.recon, args.scan, args.fuzz]):
        args.full = True

    session = create_session(
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        proxy=args.proxy,
    )

    all_findings = []
    recon_data: dict = {}
    start = time.time()

    # --- RECON ---
    if args.full or args.recon:
        if not args.quiet:
            print(f"{Colors.BLUE}[+] Reconnaissance en cours...{Colors.RESET}")
        recon = ReconModule(target, session=session, threads=args.threads)
        recon_data = recon.run_full_recon()
        all_findings.extend(recon.findings)

        if not args.quiet:
            print(f"  → Technologies: {', '.join(recon_data.get('technologies', [])) or 'N/A'}")
            print(f"  → IPs: {', '.join(recon_data.get('ips', [])) or 'N/A'}")
            print(f"  → Sous-domaines: {len(recon_data.get('subdomains', []))}")
            print(f"  → Liens découverts: {len(recon_data.get('links', []))}")
            if recon_data.get("robots_txt", {}).get("found"):
                print(f"  → robots.txt: {len(recon_data['robots_txt'].get('disallow', []))} chemins Disallow")

    # --- SCAN ---
    if args.full or args.scan:
        if not args.quiet:
            print(f"\n{Colors.BLUE}[+] Scan de vulnérabilités...{Colors.RESET}")
        scanner = VulnScanner(
            target,
            session=session,
            threads=args.threads,
            aggressive=args.aggressive or args.full,
        )
        urls_to_scan = recon_data.get("links", [target]) if recon_data else [target]
        findings = scanner.run_full_scan(urls=urls_to_scan)
        all_findings.extend(findings)
        if not args.quiet:
            print(f"  → {len(findings)} findings de scan")

    # --- FUZZ ---
    if args.full or args.fuzz:
        if not args.quiet:
            print(f"\n{Colors.BLUE}[+] Fuzzing répertoires et paramètres...{Colors.RESET}")
        fuzzer = FuzzerModule(target, session=session, threads=args.threads)
        dirs = fuzzer.fuzz_directories()
        params = fuzzer.fuzz_parameters()
        endpoints = fuzzer.discover_endpoints_from_js()
        all_findings.extend(fuzzer.findings)
        if not args.quiet:
            print(f"  → Répertoires: {len(dirs)}")
            print(f"  → Paramètres: {len(params)}")
            print(f"  → Endpoints JS: {len(endpoints)}")

    elapsed = time.time() - start

    # Dédupliquer les findings
    seen: set[str] = set()
    unique_findings = []
    for f in all_findings:
        key = f"{f.title}|{f.url}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Afficher les findings
    if not args.quiet:
        for finding in unique_findings:
            if args.verbose or finding.severity in ("critical", "high", "medium"):
                print_finding(finding)

    # Générer les rapports
    reporter = ReportGenerator(target, unique_findings, recon_data)
    reporter.print_summary()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    if args.json:
        json_path = Path(args.json)
    else:
        json_path = output_dir / f"webbounty_{domain}_{timestamp}.json"

    if args.report:
        html_path = Path(args.report)
    else:
        html_path = output_dir / f"webbounty_{domain}_{timestamp}.html"

    reporter.to_json(json_path)
    reporter.to_html(html_path)

    if not args.quiet:
        print(f"\n{Colors.GREEN}[✓] Rapport JSON:{Colors.RESET} {json_path}")
        print(f"{Colors.GREEN}[✓] Rapport HTML:{Colors.RESET} {html_path}")
        print(f"{Colors.CYAN}[*] Durée: {elapsed:.1f}s{Colors.RESET}\n")

    # Code de retour basé sur la sévérité
    if any(f.severity == "critical" for f in unique_findings):
        return 2
    if any(f.severity == "high" for f in unique_findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
