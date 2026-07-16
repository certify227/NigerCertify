import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from web_bounty_audit.cli import analyze_files, discover_har_files, render_markdown_report


FIXTURE = Path(__file__).parent / "fixtures" / "sample.har"


class WebBountyAuditTests(unittest.TestCase):
    def test_analyze_files_detects_key_findings(self) -> None:
        result = analyze_files(discover_har_files([str(FIXTURE)]))

        issue_titles = {issue.title for issue in result.issues}
        endpoint_urls = {endpoint.url for endpoint in result.endpoints}

        self.assertIn("Wildcard CORS with credentials enabled", issue_titles)
        self.assertIn("Missing Content-Security-Policy header", issue_titles)
        self.assertIn("Cookie missing Secure flag", issue_titles)
        self.assertIn("Password form served without HTTPS", issue_titles)
        self.assertIn("/api/v1/users", endpoint_urls)
        self.assertIn("https://target.example/graphql", endpoint_urls)
        self.assertIn("/internal", endpoint_urls)

    def test_render_markdown_report_contains_sections(self) -> None:
        result = analyze_files(discover_har_files([str(FIXTURE)]))
        rendered = render_markdown_report(result)

        self.assertIn("# web-bounty-audit report", rendered)
        self.assertIn("## Issues", rendered)
        self.assertIn("## Endpoints", rendered)
        self.assertIn("Wildcard CORS with credentials enabled", rendered)

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path = Path(tmp_dir) / "report.json"
            markdown_path = Path(tmp_dir) / "report.md"
            env = os.environ.copy()
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "web_bounty_audit.cli",
                    str(FIXTURE),
                    "--json",
                    str(json_path),
                    "--markdown",
                    str(markdown_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertGreater(payload["risk_score"], 0)
            self.assertTrue(markdown_path.read_text(encoding="utf-8").startswith("# web-bounty-audit report"))
            self.assertIn("Scanned inputs: 1", completed.stdout)


if __name__ == "__main__":
    unittest.main()
