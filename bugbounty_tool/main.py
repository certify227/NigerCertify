"""
NCScan — CLI principal.

Orchestration :
  recon  → crawler → scanner (XSS/SQLi/LFI/SSRF/Redirect/CRLF) → headers → fuzzer → rapport

Usage :
    python -m bugbounty_tool.main https://cible.tld --all
    python -m bugbounty_tool.main https://cible.tld --recon --crawl --scan --headers --fuzz
    python -m bugbounty_tool.main https://cible.tld --scan --threads 30 --proxy http://127.0.0.1:8080
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path
from typing import List

from . import __version__
from .core import (
    C,
    Finding,
    HttpClient,
    log_err,
    log_info,
    log_ok,
    log_warn,
    normalize_target,
    sort_findings,
)
from .modules import crawler as crawler_mod
from .modules import headers as headers_mod
from .modules import recon as recon_mod
from .modules import reporter as reporter_mod
from .modules import scanner as scanner_mod
from .modules import fuzzer as fuzzer_mod


BANNER = rf"""{C.CYAN}
  _   _  ____ ____                  
 | \ | |/ ___/ ___|  ___ __ _ _ __  
 |  \| | |   \___ \ / __/ _` | '_ \ 
 | |\  | |___ ___) | (_| (_| | | | |
 |_| \_|\____|____/ \___\__,_|_| |_|
{C.RESET}{C.BOLD} Niger Certify — Web Bug Bounty Toolkit v{__version__}{C.RESET}
"""

LEGAL = (
    f"{C.YELLOW}⚠  Utilisation strictement autorisée : programmes de bug bounty,\n"
    f"   cibles vous appartenant ou pour lesquelles vous avez un mandat écrit.\n"
    f"   Vous êtes légalement responsable de l'usage de cet outil.{C.RESET}"
)


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="ncscan",
        description="NCScan — Boîte à outils modulaire pour le bug bounty web.",
    )
    p.add_argument("target", help="URL ou domaine cible (ex: example.com)")

    g = p.add_argument_group("Modules (par défaut : recon + crawl + headers + scan)")
    g.add_argument("--all", action="store_true", help="Active tous les modules (recon+crawl+scan+headers+fuzz)")
    g.add_argument("--recon", action="store_true", help="Reconnaissance (DNS, sous-domaines, tech, robots)")
    g.add_argument("--crawl", action="store_true", help="Crawl du site")
    g.add_argument("--scan", action="store_true", help="Scan de vulnérabilités actives (XSS/SQLi/LFI/SSRF/…)")
    g.add_argument("--headers", action="store_true", help="Audit d'en-têtes de sécurité + CORS + cookies")
    g.add_argument("--fuzz", action="store_true", help="Fuzzing de fichiers/répertoires sensibles")

    r = p.add_argument_group("Recon")
    r.add_argument("--subdomains", action="store_true", help="Force l'énumération de sous-domaines (inclus par --recon/--all)")
    r.add_argument("--no-passive", action="store_true", help="Désactive crt.sh")
    r.add_argument("--sub-wordlist", type=Path, default=None, help="Wordlist de sous-domaines (défaut : intégrée)")

    c = p.add_argument_group("Crawler")
    c.add_argument("--depth", type=int, default=2, help="Profondeur max du crawl (défaut : 2)")
    c.add_argument("--max-urls", type=int, default=300, help="Nombre max d'URLs à visiter (défaut : 300)")

    f = p.add_argument_group("Fuzzer")
    f.add_argument("--wordlist", type=Path, default=None, help="Wordlist pour le fuzzing (défaut : intégrée)")

    n = p.add_argument_group("Réseau")
    n.add_argument("--threads", type=int, default=20, help="Threads concurrents (défaut : 20)")
    n.add_argument("--rate", type=float, default=25.0, help="Requêtes/seconde max (défaut : 25)")
    n.add_argument("--timeout", type=int, default=12, help="Timeout HTTP secondes (défaut : 12)")
    n.add_argument("--proxy", default=None, help="Proxy HTTP(S), ex : http://127.0.0.1:8080")
    n.add_argument("-k", "--insecure", action="store_true", help="Ignore la vérification TLS")
    n.add_argument("--cookie", action="append", default=[], help="Cookie(s) : NAME=VALUE (répétable)")
    n.add_argument("--header", action="append", default=[], help="En-tête custom : 'K: V' (répétable)")

    o = p.add_argument_group("Sortie")
    o.add_argument("--out", type=Path, default=Path("reports"), help="Dossier de rapport (défaut : reports/)")
    o.add_argument("--id", default=None, help="Identifiant de run (défaut : uuid court)")
    o.add_argument("-v", "--verbose", action="store_true", help="Mode verbeux")
    o.add_argument("-y", "--yes", action="store_true", help="Accepte automatiquement le rappel légal")

    return p.parse_args(argv)


def _confirm_legal(auto: bool) -> bool:
    print(LEGAL)
    if auto or os.environ.get("NCSCAN_YES") == "1":
        return True
    if not sys.stdin.isatty():
        print()
        log_err("Entrée non interactive : passez -y pour accepter le rappel légal.")
        return False
    try:
        ans = input("Confirmez-vous être autorisé à tester cette cible ? [oui/non] ").strip().lower()
    except EOFError:
        return False
    return ans in ("o", "oui", "y", "yes")


def _select_modules(args: argparse.Namespace) -> dict:
    if args.all:
        return {"recon": True, "crawl": True, "scan": True, "headers": True, "fuzz": True}
    any_flag = any([args.recon, args.crawl, args.scan, args.headers, args.fuzz, args.subdomains])
    if not any_flag:
        return {"recon": True, "crawl": True, "scan": True, "headers": True, "fuzz": False}
    return {
        "recon": args.recon or args.subdomains,
        "crawl": args.crawl or args.scan,
        "scan": args.scan,
        "headers": args.headers,
        "fuzz": args.fuzz,
    }


def _parse_kv(items: List[str], sep: str) -> dict:
    out = {}
    for it in items:
        if sep not in it:
            continue
        k, v = it.split(sep, 1)
        out[k.strip()] = v.strip()
    return out


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    print(BANNER)

    if not _confirm_legal(args.yes):
        log_err("Consentement refusé. Fin.")
        return 2

    target = normalize_target(args.target)
    run_id = args.id or uuid.uuid4().hex[:8]
    modules = _select_modules(args)
    active = [k for k, v in modules.items() if v]
    log_info(f"Cible : {C.BOLD}{target}{C.RESET}  |  Run : {run_id}  |  Modules : {', '.join(active)}")

    http = HttpClient(
        timeout=args.timeout,
        rate_limit=args.rate,
        proxy=args.proxy,
        insecure=args.insecure,
        headers=_parse_kv(args.header, ":"),
        cookies=_parse_kv(args.cookie, "="),
    )

    # Sanity check
    r = http.get(target)
    if not r:
        log_err(f"Cible injoignable : {target}")
        return 3
    log_ok(f"Cible en ligne : HTTP {r.status_code} ({len(r.content)} octets)")

    findings: List[Finding] = []
    tool_root = Path(__file__).resolve().parent
    default_sub_wl = tool_root / "wordlists" / "subdomains.txt"
    default_wl = tool_root / "wordlists" / "common.txt"

    crawl_result = crawler_mod.CrawlResult()

    # ------------------------------------------------------------------
    # RECON
    # ------------------------------------------------------------------
    if modules["recon"]:
        print(f"\n{C.MAGENTA}══ RECON ══{C.RESET}")
        recon = recon_mod.Recon(target, http, verbose=args.verbose)
        recon.dns_records()
        recon.enumerate_subdomains(
            wordlist_path=args.sub_wordlist or default_sub_wl,
            threads=min(args.threads * 3, 100),
            use_passive=not args.no_passive,
        )
        _, tech_findings = recon.fingerprint()
        findings.extend(tech_findings)
        extra_paths, robots_findings = recon.robots_and_sitemap()
        findings.extend(robots_findings)
    else:
        extra_paths = []

    # ------------------------------------------------------------------
    # HEADERS
    # ------------------------------------------------------------------
    if modules["headers"]:
        print(f"\n{C.MAGENTA}══ HEADERS / CORS / COOKIES ══{C.RESET}")
        findings.extend(headers_mod.audit(http, target))

    # ------------------------------------------------------------------
    # CRAWL
    # ------------------------------------------------------------------
    if modules["crawl"]:
        print(f"\n{C.MAGENTA}══ CRAWL ══{C.RESET}")
        crawler = crawler_mod.Crawler(
            base_url=target,
            http=http,
            max_depth=args.depth,
            max_urls=args.max_urls,
            threads=args.threads,
            verbose=args.verbose,
        )
        crawl_result = crawler.crawl(extra_seeds=extra_paths)

    # ------------------------------------------------------------------
    # SCAN
    # ------------------------------------------------------------------
    if modules["scan"]:
        print(f"\n{C.MAGENTA}══ SCAN ACTIF ══{C.RESET}")
        scanner = scanner_mod.VulnScanner(
            http=http, base_url=target, threads=args.threads, verbose=args.verbose
        )
        findings.extend(scanner.run(crawl_result))

    # ------------------------------------------------------------------
    # FUZZ
    # ------------------------------------------------------------------
    if modules["fuzz"]:
        print(f"\n{C.MAGENTA}══ FUZZING ══{C.RESET}")
        findings.extend(fuzzer_mod.fuzz(
            http=http,
            base_url=target,
            wordlist_path=args.wordlist or default_wl,
            threads=args.threads,
        ))

    # ------------------------------------------------------------------
    # RAPPORT
    # ------------------------------------------------------------------
    print(f"\n{C.MAGENTA}══ RAPPORT ══{C.RESET}")
    findings = sort_findings(findings)
    meta = reporter_mod.build_meta(target=target, modules=active, run_id=run_id)
    json_path = reporter_mod.write_json(findings, meta, args.out)
    html_path = reporter_mod.write_html(findings, meta, args.out)

    from collections import Counter
    counts = Counter(f.severity for f in findings)
    summary = "  ".join(
        f"{sev.upper()}={counts.get(sev, 0)}"
        for sev in ("critical", "high", "medium", "low", "info")
    )
    log_ok(f"Résumé : {summary}  |  Total = {len(findings)}")
    log_ok(f"JSON : {json_path}")
    log_ok(f"HTML : {html_path}")

    critical = counts.get("critical", 0) + counts.get("high", 0)
    return 1 if critical > 0 else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
