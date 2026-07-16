import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from web_bugbounty_tool import BugBountyScanner, write_json_report, write_markdown_report


class VulnerableHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args, **_kwargs):
        return

    def _write(self, status=200, headers=None, body=""):
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_OPTIONS(self):
        self._write(204, headers={"Allow": "GET,POST,PUT,DELETE,OPTIONS"})

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/":
            body = """
                <html>
                  <a href="/redirect?next=/home">redir</a>
                  <a href="/xss?q=hello">xss</a>
                  <a href="/cors">cors</a>
                </html>
            """
            self._write(
                headers={"Content-Type": "text/html"},
                body=body,
            )
            return
        if parsed.path == "/redirect":
            location = query.get("next", ["/"])[0]
            self._write(status=302, headers={"Location": location}, body="")
            return
        if parsed.path == "/xss":
            payload = query.get("q", [""])[0]
            self._write(headers={"Content-Type": "text/html"}, body=f"<div>{payload}</div>")
            return
        if parsed.path == "/cors":
            origin = self.headers.get("Origin", "")
            self._write(
                headers={
                    "Content-Type": "text/html",
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
                body="ok",
            )
            return
        if parsed.path == "/.git/config":
            self._write(headers={"Content-Type": "text/plain"}, body="[core]\nrepositoryformatversion=0\n")
            return
        self._write(status=404, headers={"Content-Type": "text/plain"}, body="not-found")


class TestBugBountyScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_detects_key_vulnerabilities(self):
        scanner = BugBountyScanner(
            base_url=self.base_url,
            max_depth=2,
            timeout=3,
            max_urls=20,
            user_agent="unittest",
            insecure=False,
            extra_paths=[],
        )
        report = scanner.scan()
        categories = {finding["category"] for finding in report["findings"]}
        self.assertIn("OPEN_REDIRECT", categories)
        self.assertIn("REFLECTED_XSS", categories)
        self.assertIn("CORS_ORIGIN_REFLECTION", categories)
        self.assertIn("DANGEROUS_HTTP_METHODS", categories)
        self.assertIn("SENSITIVE_FILE_EXPOSED", categories)

    def test_writes_reports(self):
        scanner = BugBountyScanner(
            base_url=self.base_url,
            max_depth=1,
            timeout=3,
            max_urls=10,
            user_agent="unittest",
            insecure=False,
            extra_paths=[],
        )
        report = scanner.scan()
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = Path(temp_dir) / "report.json"
            md_path = Path(temp_dir) / "report.md"
            write_json_report(report, str(json_path))
            write_markdown_report(report, str(md_path))
            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = md_path.read_text(encoding="utf-8")
        self.assertEqual(loaded["target"], report["target"])
        self.assertIn("Rapport Bug Bounty Web", markdown)
        self.assertIn("Findings", markdown)


if __name__ == "__main__":
    unittest.main()
