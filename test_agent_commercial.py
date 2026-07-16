import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from agent_commercial import collect_contacts


class ContactHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - signature imposee
        pages = {
            "/": """
                <html>
                    <body>
                        <a href="/contact">Contact</a>
                    </body>
                </html>
            """,
            "/contact": """
                <html>
                    <body>
                        <p>Email principal: sales@example.com</p>
                        <p>Email alternatif: support [at] example [dot] com</p>
                        <p>Telephone: +33 (0)1 23 45 67 89</p>
                    </body>
                </html>
            """,
        }
        payload = pages.get(self.path, "<html><body>Not found</body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(payload.encode("utf-8"))

    def log_message(self, format, *args):  # noqa: A003
        return


class AgentCommercialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), ContactHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_collect_contacts_from_contact_page(self):
        url = f"http://127.0.0.1:{self.port}/"
        result = collect_contacts(url, max_pages=4, timeout=3)
        self.assertIn("sales@example.com", result["emails"])
        self.assertIn("support@example.com", result["emails"])
        self.assertIn("+330123456789", result["phones"])
        self.assertGreaterEqual(len(result["scanned_pages"]), 1)


if __name__ == "__main__":
    unittest.main()
