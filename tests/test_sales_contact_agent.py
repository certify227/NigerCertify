import json
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from sales_contact_agent import extract_contacts_from_url


class TestSalesContactAgent(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        site_dir = Path(cls.temp_dir.name)
        (site_dir / "index.html").write_text(
            textwrap.dedent(
                """
                <html>
                  <body>
                    <h1>Accueil</h1>
                    <a href="/contact.html">Contact</a>
                  </body>
                </html>
                """
            ).strip(),
            encoding="utf-8",
        )
        (site_dir / "contact.html").write_text(
            textwrap.dedent(
                """
                <html>
                  <body>
                    <h2>Contact</h2>
                    <a href="mailto:sales@example.com">sales@example.com</a>
                    <a href="tel:+33 1 23 45 67 89">+33 1 23 45 67 89</a>
                    <p>Support: support [at] example [dot] com</p>
                    <p>US line: +1 (415) 555-2671</p>
                  </body>
                </html>
                """
            ).strip(),
            encoding="utf-8",
        )

        handler = partial(SimpleHTTPRequestHandler, directory=cls.temp_dir.name)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_port}/index.html"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.server_thread.join(timeout=5)
        cls.temp_dir.cleanup()

    def test_extract_contacts_from_url_follows_contact_page(self) -> None:
        result = extract_contacts_from_url(self.base_url, max_pages=3, timeout=5)

        emails = {item["value"] for item in result["emails"]}
        phones = {item["value"] for item in result["phones"]}

        self.assertEqual(
            emails,
            {"sales@example.com", "support@example.com"},
        )
        self.assertIn("+33123456789", phones)
        self.assertIn("+14155552671", phones)
        self.assertEqual(len(result["visited_pages"]), 2)
        self.assertEqual(result["errors"], [])

    def test_cli_outputs_json(self) -> None:
        command = [
            sys.executable,
            str(Path(__file__).resolve().parent.parent / "sales_contact_agent.py"),
            self.base_url,
            "--max-pages",
            "3",
            "--timeout",
            "5",
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=True)
        payload = json.loads(completed.stdout)

        self.assertEqual(payload["normalized_url"], self.base_url)
        self.assertTrue(payload["emails"])
        self.assertTrue(payload["phones"])


if __name__ == "__main__":
    unittest.main()
