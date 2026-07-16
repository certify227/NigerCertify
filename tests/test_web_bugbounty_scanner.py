import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import parse

from scanners.web_bugbounty_scanner import PageParser, WebBugBountyScanner, main


class DemoBugBountyApp(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        parsed = parse.urlparse(self.path)
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "session=abc123")
            self.end_headers()
            self.wfile.write(
                b"""
                <html>
                  <head><title>Demo target</title></head>
                  <body>
                    <a href="/login">Login</a>
                    <a href="/search?q=demo">Search</a>
                    <form method="post" action="/submit">
                      <input name="email">
                      <input type="password" name="password">
                    </form>
                  </body>
                </html>
                """
            )
        elif parsed.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<form><input type='password' name='password'></form>")
        elif parsed.path == "/search":
            query = parse.parse_qs(parsed.query)
            value = query.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body>Result: {value}</body></html>".encode())
        elif parsed.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n")
        elif parsed.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"SECRET_KEY=demo")
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"not found")


class WebBugBountyScannerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DemoBugBountyApp)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=2)
        cls.server.server_close()

    def test_parser_extracts_links_resources_and_forms(self):
        parser = PageParser("https://example.test/app/")
        parser.feed(
            """
            <html><head><title>Example App</title></head>
            <body>
              <a href="/account">Account</a>
              <script src="/static/app.js"></script>
              <form method="post" action="/login">
                <input type="password" name="password">
              </form>
            </body></html>
            """
        )

        self.assertEqual(parser.title, "Example App")
        self.assertIn("https://example.test/account", parser.links)
        self.assertIn("https://example.test/static/app.js", parser.resources)
        self.assertEqual(parser.forms[0]["method"], "post")

    def test_scanner_finds_safe_bug_bounty_signals(self):
        scanner = WebBugBountyScanner(
            target=self.base_url,
            scope_domains=[],
            max_pages=5,
            timeout=2,
            delay=0,
            user_agent="unit-test",
            active_probes=True,
        )
        report = scanner.scan()
        titles = {finding["title"] for finding in report["findings"]}

        self.assertGreaterEqual(report["summary"]["pages_scanned"], 3)
        self.assertIn("HTTP sans TLS", titles)
        self.assertIn("Formulaire POST sans jeton CSRF visible", titles)
        self.assertIn("Fichier ou endpoint sensible accessible", titles)
        self.assertIn("Parametre reflechi avec canari inerte", titles)
        json.dumps(report)

    def test_cli_requires_authorization_confirmation(self):
        self.assertEqual(main([self.base_url, "--max-pages", "1"]), 2)


if __name__ == "__main__":
    unittest.main()
