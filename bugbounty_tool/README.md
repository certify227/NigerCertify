# Web Bug Bounty Tool (Authorized Testing)

This CLI scanner is designed for **authorized and non-intrusive** web application assessments.
It focuses on reconnaissance and baseline misconfiguration checks, not exploitation.

## Features

- Same-origin crawler with depth and page limits.
- Security header checks (HSTS, CSP, XFO, XCTO, Referrer-Policy).
- Cookie flag checks (Secure, HttpOnly, SameSite).
- Basic CORS policy checks.
- Reflection probe for low-risk input reflection discovery.
- Sensitive path exposure checks (`/.git/config`, `/.env`, etc.).
- JSON and Markdown report generation.

## Usage

Run from repository root:

- `python3 bugbounty_cli.py https://target.example`
- `python3 -m bugbounty_tool.cli https://target.example --max-pages 80 --max-depth 3`

Optional arguments:

- `--json-output report.json`
- `--md-output report.md`
- `--timeout 15`
- `--delay 0.1`
- `--user-agent "MyAuthorizedScanner/1.0"`

## Notes

- Only scan assets you are explicitly authorized to test.
- Keep conservative rate limits for production systems.
