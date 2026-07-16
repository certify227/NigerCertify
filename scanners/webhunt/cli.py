"""Interface en ligne de commande de WebHunt."""

from __future__ import annotations

import argparse
import sys
import time
from typing import List, Optional
from urllib.parse import urlparse

from . import __version__
from .checks import ALL_CHECKS, CheckContext
from .crawler import Crawler
from .findings import Finding, Severity
from .http_client import HttpClient, OutOfScopeError
from .recon import Recon
from .report import (
    dedup,
    print_console,
    severity_counts,
    write_html,
    write_json,
)
from .scope import Scope

BANNER = r"""
 __        __   _     _   _             _
 \ \      / /__| |__ | | | |_   _ _ __ | |_
  \ \ /\ / / _ \ '_ \| |_| | | | | '_ \| __|
   \ V  V /  __/ |_) |  _  | |_| | | | | |_
    \_/\_/ \___|_.__/|_| |_|\__,_|_| |_|\__|

 WebHunt v%s - Boîte à outils bug bounty web
 Usage AUTORISÉ uniquement. Vous êtes responsable de votre usage.
""" % __version__

LEGAL = (
    "AVERTISSEMENT LÉGAL : n'utilisez WebHunt que sur des systèmes pour "
    "lesquels vous disposez d'une autorisation écrite explicite (programme "
    "de bug bounty dans le périmètre, mandat de pentest, lab personnel). "
    "Tout accès non autorisé à un système informatique est illégal."
)


def _normalize_target(raw: str) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError(f"Cible invalide : {raw}")
    base = f"{parsed.scheme}://{parsed.netloc}"
    if parsed.path and parsed.path != "/":
        base += parsed.path.rstrip("/")
    return base


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webhunt",
        description="Reconnaissance et audit de vulnérabilités d'applications web (bug bounty).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=LEGAL,
    )
    p.add_argument("target", nargs="?", help="URL ou domaine cible (ex: https://exemple.com)")
    p.add_argument(
        "--scope",
        action="append",
        default=[],
        help="Hôte(s) supplémentaire(s) autorisé(s). Répétable. Ex: --scope api.exemple.com",
    )
    p.add_argument(
        "--no-subdomains",
        action="store_true",
        help="Ne pas inclure les sous-domaines de la cible dans le périmètre.",
    )
    p.add_argument(
        "--active",
        action="store_true",
        help="Activer les checks actifs (payloads non destructifs : XSS/redirect/CORS).",
    )
    p.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="Confirme que vous êtes autorisé à tester la cible (requis pour --active en non-interactif).",
    )
    p.add_argument("--rate", type=float, default=5.0, help="Requêtes/seconde max (défaut: 5).")
    p.add_argument("--timeout", type=float, default=12.0, help="Timeout HTTP en secondes.")
    p.add_argument("--max-pages", type=int, default=150, help="Pages max à crawler.")
    p.add_argument("--max-depth", type=int, default=3, help="Profondeur de crawl max.")
    p.add_argument("--no-crawl", action="store_true", help="Désactiver le crawler.")
    p.add_argument("--insecure", action="store_true", help="Ne pas vérifier les certificats TLS.")
    p.add_argument("--proxy", help="Proxy HTTP(S), ex: http://127.0.0.1:8080")
    p.add_argument("--header", action="append", default=[], help="En-tête additionnel 'Nom: valeur'. Répétable.")
    p.add_argument(
        "--only",
        help="Ne lancer que ces checks (liste séparée par des virgules).",
    )
    p.add_argument("--json", dest="json_out", help="Écrire le rapport JSON dans ce fichier.")
    p.add_argument("--html", dest="html_out", help="Écrire le rapport HTML dans ce fichier.")
    p.add_argument(
        "--min-severity",
        default="info",
        help="Gravité minimale affichée (info/low/medium/high/critical).",
    )
    p.add_argument("--no-color", action="store_true", help="Désactiver la couleur.")
    p.add_argument("--quiet", action="store_true", help="Réduire la verbosité.")
    p.add_argument("--version", action="version", version=f"WebHunt {__version__}")
    return p


def _parse_headers(items: List[str]) -> dict:
    headers = {}
    for item in items:
        if ":" in item:
            k, v = item.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def _confirm_authorization(target: str, args) -> bool:
    if args.i_am_authorized:
        return True
    if not sys.stdin.isatty():
        return False
    print(LEGAL + "\n")
    try:
        ans = input(f"Confirmez-vous être autorisé à tester {target} ? [oui/non] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans in ("oui", "o", "yes", "y")


def run_scan(args) -> int:
    quiet = args.quiet
    log = (lambda *a: None) if quiet else (lambda *a: print(*a))

    if not args.no_color:
        print(BANNER)

    try:
        base_url = _normalize_target(args.target)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    target_host = urlparse(base_url).hostname or ""
    allowed = [target_host] + list(args.scope)
    scope = Scope(allowed, include_subdomains=not args.no_subdomains)

    active = args.active
    if active and not _confirm_authorization(base_url, args):
        print(
            "[!] Autorisation non confirmée. Les checks actifs sont désactivés.\n"
            "    Relancez avec --i-am-authorized si vous êtes autorisé.",
            file=sys.stderr,
        )
        active = False

    client = HttpClient(
        scope=scope,
        rate_per_sec=args.rate,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        proxy=args.proxy,
        extra_headers=_parse_headers(args.header),
    )

    log(f"[*] Cible        : {base_url}")
    log(f"[*] Périmètre    : {', '.join(scope.hosts)} (sous-domaines: {not args.no_subdomains})")
    log(f"[*] Mode actif   : {'OUI' if active else 'non (passif)'}")
    log(f"[*] Débit        : {args.rate} req/s\n")

    started = time.time()
    findings: List[Finding] = []

    # 1) Reconnaissance
    log("[*] Phase 1/3 : Reconnaissance...")
    recon = Recon(client)
    try:
        recon_result = recon.run(base_url)
    except OutOfScopeError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    findings.extend(recon_result.findings)
    if recon_result.technologies:
        log(f"    technologies : {', '.join(sorted(recon_result.technologies))}")
    if recon_result.ip_addresses:
        log(f"    IP           : {', '.join(recon_result.ip_addresses)}")

    # 2) Crawl
    crawl_result = None
    if not args.no_crawl:
        log("[*] Phase 2/3 : Exploration (crawl)...")
        crawler = Crawler(
            client, scope, max_pages=args.max_pages, max_depth=args.max_depth
        )
        seeds = [base_url] + [
            u for u in recon_result.sitemap_urls if scope.is_allowed(u)
        ]
        crawl_result = crawler.crawl(seeds)
        log(
            f"    pages        : {len(crawl_result.pages)}  "
            f"| formulaires : {len(crawl_result.forms)}  "
            f"| URLs paramétrées : {len(crawl_result.parameterized_urls())}"
        )
    else:
        log("[*] Phase 2/3 : Crawl désactivé.")

    # 3) Checks
    log("[*] Phase 3/3 : Analyse des vulnérabilités...")
    only = None
    if args.only:
        only = {c.strip() for c in args.only.split(",") if c.strip()}

    ctx = CheckContext(
        base_url=base_url,
        client=client,
        scope=scope,
        recon=recon_result,
        crawl=crawl_result,
        active=active,
    )

    for check_cls in ALL_CHECKS:
        check = check_cls()
        if only and check.name not in only:
            continue
        if check.active and not active:
            log(f"    - {check.name} (ignoré : nécessite --active)")
            continue
        try:
            results = check.run(ctx)
        except OutOfScopeError as e:
            print(f"[!] {check.name}: {e}", file=sys.stderr)
            continue
        except Exception as e:  # robustesse : un check ne doit pas tout casser
            print(f"[!] Erreur dans le check {check.name}: {e}", file=sys.stderr)
            continue
        findings.extend(results)
        log(f"    - {check.name} : {len(results)} découverte(s)")

    findings = dedup(findings)

    # Filtre par gravité min.
    try:
        min_sev = Severity.from_str(args.min_severity)
    except KeyError:
        min_sev = Severity.INFO
    findings = [f for f in findings if f.severity >= min_sev]

    elapsed = time.time() - started
    meta = {
        "duration_seconds": round(elapsed, 2),
        "active_mode": active,
        "requests_sent": client.stats.requests_sent,
        "errors": client.stats.errors,
        "technologies": sorted(recon_result.technologies),
        "ip_addresses": recon_result.ip_addresses,
        "pages_crawled": len(crawl_result.pages) if crawl_result else 0,
    }

    if not quiet:
        print_console(findings, color=not args.no_color)
        print(
            f"\n[+] Terminé en {elapsed:.1f}s | {client.stats.requests_sent} requêtes "
            f"({client.stats.errors} erreurs)"
        )

    if args.json_out:
        write_json(args.json_out, base_url, findings, meta)
        log(f"[+] Rapport JSON : {args.json_out}")
    if args.html_out:
        write_html(args.html_out, base_url, findings, meta)
        log(f"[+] Rapport HTML : {args.html_out}")

    client.close()

    counts = severity_counts(findings)
    # Code de sortie : 1 si découvertes High/Critical, sinon 0.
    if counts.get("Critical") or counts.get("High"):
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.target:
        parser.print_help()
        return 2
    try:
        return run_scan(args)
    except KeyboardInterrupt:
        print("\n[!] Interrompu par l'utilisateur.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
