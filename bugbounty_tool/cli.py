from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional, Sequence

from bugbounty_tool.scanner import BountyScanner, report_to_json, report_to_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bugbounty-tool",
        description="Non-intrusive bug bounty helper for authorized web app assessments.",
    )
    parser.add_argument("target", help="Base target URL, e.g. https://example.com")
    parser.add_argument("--max-pages", type=int, default=40, help="Maximum pages to crawl.")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth from base URL.")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds.")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.2,
        help="Delay in seconds between requests (rate limiting).",
    )
    parser.add_argument(
        "--user-agent",
        default=None,
        help="Custom User-Agent header.",
    )
    parser.add_argument(
        "--json-output",
        default="bugbounty_report.json",
        help="Path to JSON report output file.",
    )
    parser.add_argument(
        "--md-output",
        default="bugbounty_report.md",
        help="Path to Markdown report output file.",
    )
    return parser


def run_cli(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    scanner = BountyScanner(
        base_url=args.target,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent,
    )
    report = scanner.run()

    json_path = Path(args.json_output)
    md_path = Path(args.md_output)
    json_path.write_text(report_to_json(report), encoding="utf-8")
    md_path.write_text(report_to_markdown(report), encoding="utf-8")

    print(f"[+] Scan complete for {args.target}")
    print(f"[+] Findings: {len(report.get('findings', []))}")
    print(f"[+] JSON report: {json_path.resolve()}")
    print(f"[+] Markdown report: {md_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
