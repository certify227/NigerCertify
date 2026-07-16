import unittest

from bugbounty_tool.scanner import BountyScanner, HttpResponse, report_to_markdown


class BountyToolTests(unittest.TestCase):
    def test_extract_urls_and_forms_same_host(self) -> None:
        scanner = BountyScanner("https://app.example")
        html = """
        <html>
          <body>
            <a href="/dashboard">Dashboard</a>
            <a href="https://app.example/profile">Profile</a>
            <a href="https://external.example/">External</a>
            <form method="post" action="/login"></form>
          </body>
        </html>
        """
        urls, forms = scanner._extract_urls_and_forms("https://app.example", html)

        self.assertIn("https://app.example/dashboard", urls)
        self.assertIn("https://app.example/profile", urls)
        self.assertIn("https://external.example/", urls)
        self.assertEqual(forms, [{"method": "POST", "action": "https://app.example/login"}])

    def test_check_security_headers_missing(self) -> None:
        scanner = BountyScanner("https://app.example")
        response = HttpResponse(
            url="https://app.example",
            status=200,
            headers={"content-type": "text/html"},
            set_cookies=[],
            body="<html></html>",
        )
        scanner._check_security_headers(response)
        titles = {item.title for item in scanner.findings}

        self.assertIn("Missing HSTS header", titles)
        self.assertIn("Missing Content-Security-Policy", titles)
        self.assertIn("Missing X-Frame-Options", titles)

    def test_check_cookie_flags(self) -> None:
        scanner = BountyScanner("https://app.example")
        response = HttpResponse(
            url="https://app.example",
            status=200,
            headers={"content-type": "text/html"},
            set_cookies=["session=abc123; Path=/"],
            body="ok",
        )
        scanner._check_cookie_flags(response)
        severities = sorted(item.severity for item in scanner.findings)
        self.assertEqual(severities, ["LOW", "MEDIUM", "MEDIUM"])

    def test_report_markdown_renders(self) -> None:
        scanner = BountyScanner("https://app.example")
        scanner.findings = []
        report = {
            "target": "https://app.example",
            "started_at_utc": "2026-07-16T00:00:00+00:00",
            "duration_seconds": 1.23,
            "crawled_pages": 1,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "findings": [],
            "errors": [],
        }
        markdown = report_to_markdown(report)
        self.assertIn("# Web Bug Bounty Report", markdown)
        self.assertIn("No findings detected", markdown)


if __name__ == "__main__":
    unittest.main()
