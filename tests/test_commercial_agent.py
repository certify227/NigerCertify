import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from commercial_agent import extract_contacts, extract_emails, extract_phones, normalize_start_url


class ContactSiteHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        pages = {
            "/": (
                "text/html",
                """
                <html>
                  <body>
                    <a href="/contact">Contact commercial</a>
                    <a href="mailto:sales@example.test">Email</a>
                  </body>
                </html>
                """,
            ),
            "/contact": (
                "text/html",
                """
                <html>
                  <body>
                    <p>Equipe commerciale: contact@example.test</p>
                    <a href="tel:+221771234567">Appeler</a>
                    <p>Fixe: +221 33 800 10 20</p>
                  </body>
                </html>
                """,
            ),
        }
        content_type, body = pages.get(self.path, ("text/html", "<html><body>Vide</body></html>"))
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        return


class CommercialAgentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ContactSiteHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_extract_contacts_from_site_and_contact_page(self):
        result = extract_contacts(self.base_url, max_pages=3)

        self.assertEqual(result.pages_scanned[0], self.base_url)
        self.assertIn("sales@example.test", result.emails)
        self.assertIn("contact@example.test", result.emails)
        self.assertIn("+221771234567", result.phones)
        self.assertIn("+221 33 800 10 20", result.phones)

    def test_extract_helpers(self):
        self.assertEqual(normalize_start_url("example.test"), "https://example.test")
        self.assertEqual(extract_emails("Contact: Admin@Example.TEST"), {"admin@example.test"})
        self.assertEqual(extract_phones("Tel: +33 1 42 68 53 00"), {"+33 1 42 68 53 00"})


if __name__ == "__main__":
    unittest.main()
