import contextlib
import io
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import agent_commercial


class ContactHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        pages = {
            "/": """
                <html>
                  <body>
                    <a href="/contact">Contactez-nous</a>
                    <p>Email direct: support@example.test</p>
                  </body>
                </html>
            """,
            "/contact": """
                <html>
                  <body>
                    <a href="mailto:sales@example.test">Equipe commerciale</a>
                    <a href="tel:+22790123456">+227 90 12 34 56</a>
                    <p>Partenariat: partner [at] example [dot] test</p>
                  </body>
                </html>
            """,
        }
        body = pages.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return

        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        return


class AgentCommercialTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ContactHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=2)
        cls.server.server_close()

    def test_extract_contacts_from_text(self):
        result = agent_commercial.extract_contacts_from_text(
            "Contact: Info@Example.TEST ou +33 (0)1 23 45 67 89",
            "fixture",
        )

        self.assertEqual(result.emails, {"info@example.test"})
        self.assertEqual(result.phones, {"+330123456789"})

    def test_analyze_url_follows_internal_contact_link(self):
        result = agent_commercial.analyze_url(self.base_url, follow_contact_links=2)

        self.assertEqual(
            result.emails,
            {"support@example.test", "sales@example.test", "partner@example.test"},
        )
        self.assertEqual(result.phones, {"+22790123456"})

    def test_cli_json_output(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = agent_commercial.main([self.base_url, "--json"])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertIn("sales@example.test", payload["emails"])
        self.assertIn("+22790123456", payload["telephones"])


if __name__ == "__main__":
    unittest.main()
