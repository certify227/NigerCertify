import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanners.websentinel import WebSentinelScanner, main, render_text  # noqa: E402


class DemoBugBountyHandler(BaseHTTPRequestHandler):
    server_version = "DemoServer/1.2.3"

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, PUT")
        self.end_headers()

    def do_GET(self):
        if self.path == "/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main\n")
            return
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Disallow: /admin\n")
            return
        if self.path == "/profile":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>profile</body></html>")
            return
        if self.path != "/":
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "sid=abc123; Path=/")
        self.send_header("X-Powered-By", "DemoFramework 9.9")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(
            b"""
            <html>
              <head><meta name="generator" content="DemoCMS 1.0"></head>
              <body>
                <a href="/profile">profile</a>
                <a href="https://offscope.example/">off scope</a>
                <form method="post" action="/login">
                  <input type="text" name="user">
                  <input type="password" name="pass">
                </form>
              </body>
            </html>
            """
        )

    def log_message(self, format, *args):
        return


class WebSentinelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), DemoBugBountyHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_scanner_detects_web_bug_bounty_findings(self):
        scanner = WebSentinelScanner(self.base_url, rate_limit=0, max_pages=3, max_depth=1)
        report = scanner.run()

        titles = {finding["title"] for finding in report["findings"]}
        self.assertIn("Formulaire de mot de passe servi sans HTTPS", titles)
        self.assertIn("Cookie sans attributs defensifs: sid", titles)
        self.assertIn("CORS invalide: wildcard avec credentials", titles)
        self.assertIn("Methodes HTTP sensibles annoncees", titles)
        self.assertIn("Chemin sensible accessible: /.git/HEAD", titles)
        self.assertNotIn("https://offscope.example/", scanner.visited)
        self.assertGreaterEqual(report["summary"]["high"], 2)

    def test_render_text_contains_summary_and_recommendations(self):
        scanner = WebSentinelScanner(self.base_url, rate_limit=0, max_pages=1, max_depth=0)
        report = scanner.run()
        rendered = render_text(report)

        self.assertIn("WebSentinel - rapport bug bounty non destructif", rendered)
        self.assertIn("Cible:", rendered)
        self.assertIn("Recommandation:", rendered)

    def test_cli_requires_authorization_flag(self):
        with self.assertRaises(SystemExit) as raised:
            main([self.base_url])
        self.assertEqual(raised.exception.code, 2)

    def test_cli_writes_json_report(self):
        with tempfile.NamedTemporaryFile("r+", encoding="utf-8", delete=False) as handle:
            output_path = handle.name
        try:
            status = main(
                [
                    self.base_url,
                    "--i-am-authorized",
                    "--rate-limit",
                    "0",
                    "--max-pages",
                    "1",
                    "--format",
                    "json",
                    "--output",
                    output_path,
                ]
            )
            self.assertEqual(status, 0)
            with open(output_path, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual(data["tool"], "WebSentinel")
            self.assertEqual(data["target"], self.base_url)
            self.assertTrue(data["findings"])
        finally:
            os.unlink(output_path)


if __name__ == "__main__":
    unittest.main()
