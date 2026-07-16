#!/usr/bin/env python3
"""BountyStrike v3.0 — Strike First. Hunt Smart."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from modules.brand import TOOL_BINARY, TOOL_NAME, TOOL_REPORT_PREFIX, TOOL_VERSION
from modules.dashboard import DashboardServer
from modules.database import ScanDatabase
from modules.exporters import ReportExporter
from modules.reporter import ReportGenerator
from modules.scan_engine import ScanConfig, ScanEngine
from modules.utils import Colors, print_banner


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog=TOOL_BINARY, description=f"{TOOL_NAME} v{TOOL_VERSION}")
    p.add_argument("-t", "--target", help="URL ou domaine cible")
    p.add_argument("-l", "--targets-file", help="Fichier de cibles (une par ligne)")
    p.add_argument("--full", action="store_true", help="Scan complet")
    p.add_argument("--recon", action="store_true")
    p.add_argument("--scan", action="store_true")
    p.add_argument("--fuzz", action="store_true")
    p.add_argument("--aggressive", action="store_true")
    p.add_argument("--brutal", action="store_true", help="TOUT activer")
    p.add_argument("--extended", action="store_true", help="Tous les modules avancés v3")
    p.add_argument("--jwt", action="store_true")
    p.add_argument("--graphql", action="store_true")
    p.add_argument("--graphql-fuzz", action="store_true")
    p.add_argument("--ssrf", action="store_true")
    p.add_argument("--takeover", action="store_true")
    p.add_argument("--nuclei", action="store_true")
    p.add_argument("--external-tools", action="store_true", help="ffuf, dalfox, sqlmap")
    p.add_argument("--nuclei-templates")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--proxy")
    p.add_argument("--no-ssl-verify", action="store_true")
    p.add_argument("--bearer", help="Token Bearer")
    p.add_argument("--cookie", help="Cookie (name=value; ...)")
    p.add_argument("--auth-header", help="Header custom (Name: Value)")
    p.add_argument("--oob-callback", help="Domaine OOB (Interactsh/Collaborator)")
    p.add_argument("--shodan-key", help="Clé API Shodan")
    p.add_argument("--scope-file", help="Fichier de scope")
    p.add_argument("--report")
    p.add_argument("--json")
    p.add_argument("--export-h1", help="Export format HackerOne")
    p.add_argument("--export-burp", help="Export XML Burp")
    p.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"), help="Diff deux rapports JSON")
    p.add_argument("-o", "--output-dir", default="reports")
    p.add_argument("--dashboard", action="store_true", help="Lancer le dashboard web")
    p.add_argument("--dashboard-port", type=int, default=8888)
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


def build_config(args: argparse.Namespace, target: str) -> ScanConfig:
    return ScanConfig(
        target=target,
        full=args.full,
        recon=args.recon,
        scan=args.scan,
        fuzz=args.fuzz,
        aggressive=args.aggressive,
        brutal=args.brutal,
        extended=args.extended,
        jwt=args.jwt,
        graphql=args.graphql,
        graphql_fuzz=args.graphql_fuzz,
        ssrf=args.ssrf,
        takeover=args.takeover,
        nuclei=args.nuclei,
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        no_ssl_verify=args.no_ssl_verify,
        bearer=args.bearer,
        cookie=args.cookie,
        auth_header=args.auth_header,
        oob_callback=args.oob_callback,
        shodan_key=args.shodan_key,
        nuclei_templates=args.nuclei_templates,
        scope_file=Path(args.scope_file) if args.scope_file else None,
        output_dir=Path(args.output_dir),
        quiet=args.quiet,
        verbose=args.verbose,
        use_external_tools=args.external_tools,
    )


def scan_target(args: argparse.Namespace, target: str) -> int:
    if not args.quiet:
        print(f"{Colors.GREEN}[*] Cible:{Colors.RESET} {target}")

    start = time.time()
    config = build_config(args, target)
    engine = ScanEngine(config)
    findings = engine.run()
    engine.print_findings()
    elapsed = time.time() - start

    reporter = ReportGenerator(target, findings, engine.recon_data)
    reporter.print_summary()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    json_path = Path(args.json) if args.json else output_dir / f"{TOOL_REPORT_PREFIX}_{domain}_{ts}.json"
    html_path = Path(args.report) if args.report else output_dir / f"{TOOL_REPORT_PREFIX}_{domain}_{ts}.html"
    reporter.to_json(json_path)
    reporter.to_html(html_path)

    if args.export_h1:
        ReportExporter.to_hackerone(findings, Path(args.export_h1))
    if args.export_burp:
        ReportExporter.to_burp_xml(findings, Path(args.export_burp))

    db = ScanDatabase()
    db.save_scan(target, findings, elapsed)

    if not args.quiet:
        print(f"\n{Colors.GREEN}[✓] JSON:{Colors.RESET} {json_path}")
        print(f"{Colors.GREEN}[✓] HTML:{Colors.RESET} {html_path}")
        print(f"{Colors.CYAN}[*] {elapsed:.1f}s — {len(findings)} findings{Colors.RESET}\n")

    if any(f.severity == "critical" for f in findings):
        return 2
    if any(f.severity == "high" for f in findings):
        return 1
    return 0


def main() -> int:
    args = parse_args()

    if args.diff:
        result = ReportExporter.diff_scans(Path(args.diff[0]), Path(args.diff[1]), Path("diff_report.json"))
        print(f"Nouveaux findings: {result['delta']}")
        return 0

    if args.dashboard:
        if not args.quiet:
            print_banner()
        DashboardServer(port=args.dashboard_port).start(blocking=True)
        return 0

    if not args.target and not args.targets_file:
        print("Erreur: -t ou -l requis")
        return 1

    if not args.quiet:
        print_banner()
        print(f"{Colors.YELLOW}[!] Usage éthique — autorisation requise{Colors.RESET}\n")

    if not any([args.full, args.recon, args.scan, args.fuzz, args.jwt, args.graphql,
                args.graphql_fuzz, args.ssrf, args.takeover, args.nuclei, args.aggressive,
                args.brutal, args.extended]):
        args.full = True

    targets = []
    if args.target:
        targets.append(args.target)
    if args.targets_file:
        targets.extend(
            l.strip() for l in Path(args.targets_file).read_text().splitlines()
            if l.strip() and not l.startswith("#")
        )

    worst = 0
    for target in targets:
        code = scan_target(args, target)
        worst = max(worst, code)
    return worst


if __name__ == "__main__":
    sys.exit(main())
