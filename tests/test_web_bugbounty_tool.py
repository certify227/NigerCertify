import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from scanners.web_bugbounty_tool import scan_target, write_json_report, write_markdown_report


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.end_headers()
            self.wfile.write(
                b"""
                <html>
                  <head><title>Demo App</title></head>
                  <body>
                    <a href="/login?next=/admin">Login</a>
                    <a href="/search?file=report.pdf">Search</a>
                    <a href="/public">Public</a>
                    <script src="/static/app.js"></script>
                    <form method="post" action="/account/update">
                      <input type="text" name="email" />
                    </form>
                  </body>
                </html>
                """
            )
            return
        if self.path.startswith("/login"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"""
                <html>
                  <body>
                    <form method="post" action="/login">
                      <input type="hidden" name="csrf_token" value="ok" />
                      <input type="text" name="username" />
                      <input type="password" name="password" />
                    </form>
                  </body>
                </html>
                """
            )
            return
        if self.path.startswith("/search"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body>Search</body></html>")
            return
        if self.path == "/public":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body>Public</body></html>")
            return
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n")
            return
        if self.path == "/sitemap.xml":
            self.send_response(200)
            self.send_header("Content-Type", "application/xml; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<urlset></urlset>")
            return
        if self.path == "/api/docs":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body>API docs</body></html>")
            return
        if self.path == "/graphql":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')
            return
        if self.path == "/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main")
            return
        if self.path == "/static/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"console.log('demo');")
            return

        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Not found")

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        return


class WebBugbountyToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_scan_finds_expected_signals(self):
        report = scan_target(
            f"http://127.0.0.1:{self.port}/",
            max_depth=2,
            max_pages=10,
            timeout=3,
            enable_probing=True,
        )

        findings = json.dumps(report["findings"], ensure_ascii=False)
        endpoints = {entry["url"] for entry in report["interesting_endpoints"]}

        self.assertGreaterEqual(report["summary"]["pages_visited"], 4)
        self.assertIn("En-tête de sécurité manquant", findings)
        self.assertIn("sans protections complètes", findings)
        self.assertIn("Formulaire POST sans jeton CSRF détecté", findings)
        self.assertIn("Paramètre de redirection intéressant", findings)
        self.assertIn("Paramètre de fichier/chemin intéressant", findings)
        self.assertTrue(any(url.endswith("/.git/HEAD") for url in endpoints))

    def test_report_writers(self):
        report = scan_target(
            f"http://127.0.0.1:{self.port}/",
            max_depth=1,
            max_pages=5,
            timeout=3,
            enable_probing=False,
        )

        with TemporaryDirectory() as tmp_dir:
            json_path = Path(tmp_dir) / "report.json"
            markdown_path = Path(tmp_dir) / "report.md"

            write_json_report(report, str(json_path))
            write_markdown_report(report, str(markdown_path))

            self.assertTrue(json_path.exists())
            self.assertTrue(markdown_path.exists())
            self.assertIn("Rapport SafeBountyScanner", markdown_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
