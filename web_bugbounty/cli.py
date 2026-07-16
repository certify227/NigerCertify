"""Interface en ligne de commande de web_bugbounty."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List

from . import __version__
from .core.findings import Severity, sort_findings
from .core.http_client import HttpClient, HttpConfig
from .core.reporter import (
    console_report,
    summarize,
    to_html,
    to_json,
    to_markdown,
)
from .core.scope import Scope, host_of, normalize_url
from .scanner import DEFAULT_MODULES, MODULES, Scanner

BANNER = r"""
 web_bugbounty  v{version}
 Boîte à outils de reconnaissance & audit de sécurité web (usage autorisé)
""".strip()

LEGAL = (
    "AVERTISSEMENT LÉGAL : n'utilisez cet outil que sur des systèmes pour lesquels\n"
    "vous disposez d'une autorisation écrite explicite (programme de bug bounty en\n"
    "périmètre, mandat de pentest, ou vos propres systèmes). Tout usage non autorisé\n"
    "est illégal et engage votre seule responsabilité."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web_bugbounty",
        description="Outil de reconnaissance et d'audit de sécurité pour le bug bounty (usage autorisé).",
        epilog=LEGAL,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="URL ou domaine cible (ex: https://exemple.com)")
    p.add_argument("-l", "--list", help="Fichier de cibles (une par ligne)")
    p.add_argument(
        "-m",
        "--modules",
        default=",".join(DEFAULT_MODULES),
        help=f"Modules à exécuter, séparés par des virgules. Dispo: {', '.join(MODULES)} (défaut: {','.join(DEFAULT_MODULES)})",
    )
    p.add_argument("--all", action="store_true", help="Exécuter tous les modules (dont subdomains).")
    p.add_argument(
        "-s",
        "--scope",
        help="Domaines dans le périmètre (virgules). Défaut: le domaine racine de la cible.",
    )
    p.add_argument("--exclude", help="Domaines/hôtes à exclure (virgules).")
    p.add_argument("--no-subdomain-scope", action="store_true", help="Ne pas autoriser les sous-domaines du périmètre.")

    # HTTP
    p.add_argument("-t", "--threads", type=int, default=20, help="Threads de concurrence (défaut: 20).")
    p.add_argument("--timeout", type=float, default=10.0, help="Timeout par requête en secondes (défaut: 10).")
    p.add_argument("--rate-limit", type=float, default=0.0, help="Délai min. entre requêtes en secondes (défaut: 0).")
    p.add_argument("--retries", type=int, default=2, help="Nombre de retries HTTP (défaut: 2).")
    p.add_argument("-k", "--insecure", action="store_true", help="Ne pas vérifier les certificats TLS.")
    p.add_argument("--proxy", help="Proxy HTTP(S) (ex: http://127.0.0.1:8080).")
    p.add_argument("-H", "--header", action="append", default=[], help="En-tête personnalisé 'Nom: valeur' (répétable).")
    p.add_argument("-A", "--user-agent", help="User-Agent personnalisé.")
    p.add_argument("--cookie", help="En-tête Cookie à envoyer.")

    # Découverte
    p.add_argument("-w", "--wordlist", help="Wordlist pour la découverte de contenu.")
    p.add_argument("--subdomain-wordlist", help="Wordlist pour l'énumération de sous-domaines.")
    p.add_argument("--passive", action="store_true", help="Sous-domaines : passif uniquement (crt.sh, pas de brute).")

    # Sortie
    p.add_argument("-o", "--output", help="Fichier de sortie du rapport.")
    p.add_argument(
        "-f",
        "--format",
        choices=["console", "json", "md", "html"],
        default="console",
        help="Format du rapport (défaut: console).",
    )
    p.add_argument(
        "--min-severity",
        choices=[s.label.lower() for s in Severity],
        default="info",
        help="Sévérité minimale affichée (défaut: info).",
    )
    p.add_argument("--no-color", action="store_true", help="Désactiver la couleur.")
    p.add_argument("-q", "--quiet", action="store_true", help="Mode silencieux (pas de logs de progression).")
    p.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Confirmer l'autorisation de test sans invite interactive.",
    )
    p.add_argument("--version", action="version", version=f"web_bugbounty {__version__}")
    return p


def parse_headers(header_args: List[str], user_agent: str | None, cookie: str | None) -> dict:
    headers = {}
    for h in header_args:
        if ":" in h:
            name, _, value = h.partition(":")
            headers[name.strip()] = value.strip()
    if cookie:
        headers["Cookie"] = cookie
    return headers


def load_targets(args) -> List[str]:
    targets: List[str] = []
    if args.target:
        targets.append(args.target)
    if args.list:
        if not os.path.isfile(args.list):
            print(f"[!] Fichier de cibles introuvable : {args.list}", file=sys.stderr)
            sys.exit(2)
        with open(args.list, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    return targets


def confirm_authorization(targets: List[str], assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        # Non interactif sans --yes : on refuse par prudence.
        print(
            "[!] Entrée non interactive : ajoutez --yes pour confirmer l'autorisation de test.",
            file=sys.stderr,
        )
        return False
    print(LEGAL)
    print()
    hosts = ", ".join(sorted({host_of(t) for t in targets}))
    answer = input(f"Confirmez-vous être autorisé à tester [{hosts}] ? (oui/non) ").strip().lower()
    return answer in ("oui", "o", "yes", "y")


def run_cli(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    targets = load_targets(args)
    if not targets:
        parser.print_help()
        return 2

    use_color = not args.no_color and sys.stdout.isatty()

    def log(msg: str) -> None:
        if not args.quiet:
            print(msg, file=sys.stderr)

    if not args.quiet:
        print(BANNER.format(version=__version__), file=sys.stderr)

    if not confirm_authorization(targets, args.yes):
        print("[!] Autorisation non confirmée. Abandon.", file=sys.stderr)
        return 3

    # Périmètre
    if args.scope:
        include = [s.strip() for s in args.scope.split(",") if s.strip()]
    else:
        from .core.scope import registrable_root

        include = sorted({registrable_root(host_of(t)) for t in targets})
    exclude = [s.strip() for s in (args.exclude or "").split(",") if s.strip()]
    scope = Scope(include, exclude, allow_subdomains=not args.no_subdomain_scope)

    # Modules
    if args.all:
        modules = list(MODULES.keys())
    else:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    unknown = [m for m in modules if m not in MODULES]
    if unknown:
        print(f"[!] Modules inconnus : {', '.join(unknown)}", file=sys.stderr)
        return 2

    # Client HTTP
    config = HttpConfig(
        timeout=args.timeout,
        max_retries=args.retries,
        rate_limit=args.rate_limit,
        verify_tls=not args.insecure,
        proxy=args.proxy,
        user_agent=args.user_agent or HttpConfig.user_agent,
        extra_headers=parse_headers(args.header, args.user_agent, args.cookie) or None,
    )
    client = HttpClient(config)

    ctx = {
        "threads": args.threads,
        "wordlist": args.wordlist,
        "subdomain_wordlist": args.subdomain_wordlist,
        "passive": args.passive,
    }
    scanner = Scanner(client, scope, modules, ctx, logger=log)

    all_findings = []
    for target in targets:
        log(f"\n[+] Cible : {target}")
        all_findings.extend(scanner.scan(target))

    # Filtre par sévérité minimale
    min_sev = Severity.from_str(args.min_severity)
    filtered = [f for f in all_findings if f.severity >= min_sev]

    primary = normalize_url(targets[0]) if len(targets) == 1 else f"{len(targets)} cibles"
    meta = {"requests_sent": client.requests_sent, "modules": modules}

    fmt = args.format
    if fmt == "json":
        report = to_json(sort_findings(filtered), primary, meta)
    elif fmt == "md":
        report = to_markdown(filtered, primary, meta)
    elif fmt == "html":
        report = to_html(filtered, primary, meta)
    else:
        report = console_report(filtered, use_color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        log(f"\n[+] Rapport écrit dans {args.output}")
        summary = summarize(filtered)
        log(f"[+] {summary['total']} findings ({client.requests_sent} requêtes envoyées).")
    else:
        print(report)

    # Code de sortie : 1 si au moins un finding HIGH/CRITICAL.
    if any(f.severity >= Severity.HIGH for f in filtered):
        return 1
    return 0


def main() -> None:
    try:
        sys.exit(run_cli())
    except KeyboardInterrupt:
        print("\n[!] Interrompu par l'utilisateur.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
