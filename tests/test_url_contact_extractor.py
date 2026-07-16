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


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scanners" / "url_contact_extractor.py"


class UrlContactExtractorCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        web_root = Path(self.temp_dir.name)

        (web_root / "index.html").write_text(
            textwrap.dedent(
                """
                <html>
                  <body>
                    <h1>ACME Sales</h1>
                    <p>Email principal: hello@example.test</p>
                    <a href="/contact.html">Contact</a>
                    <a href="/about.html">About us</a>
                  </body>
                </html>
                """
            ).strip(),
            encoding="utf-8",
        )
        (web_root / "contact.html").write_text(
            textwrap.dedent(
                """
                <html>
                  <body>
                    <h2>Contact</h2>
                    <p>Support: support@example.test</p>
                    <p>Call us: +33 6 12 34 56 78</p>
                    <a href="mailto:sales@example.test?subject=demo">sales@example.test</a>
                    <a href="tel:+33102030405">Telephone</a>
                  </body>
                </html>
                """
            ).strip(),
            encoding="utf-8",
        )
        (web_root / "about.html").write_text(
            textwrap.dedent(
                """
                <html>
                  <body>
                    <p>Our team can also be reached at team@example.test.</p>
                    <a href="https://external.example/contact">External link</a>
                  </body>
                </html>
                """
            ).strip(),
            encoding="utf-8",
        )

        handler = partial(SimpleHTTPRequestHandler, directory=self.temp_dir.name)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=5)
        self.temp_dir.cleanup()

    def test_cli_extracts_contacts_from_internal_pages(self) -> None:
        command = [
            sys.executable,
            str(SCRIPT_PATH),
            f"http://127.0.0.1:{self.port}/index.html",
            "--json",
            "--max-pages",
            "3",
        ]
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        payload = json.loads(completed.stdout)

        emails = {item["value"] for item in payload["emails"]}
        phones = {item["value"] for item in payload["phones"]}
        pages = set(payload["pages_scanned"])

        self.assertEqual(
            emails,
            {
                "hello@example.test",
                "sales@example.test",
                "support@example.test",
                "team@example.test",
            },
        )
        self.assertEqual(phones, {"+33102030405", "+33612345678"})
        self.assertEqual(
            pages,
            {
                f"http://127.0.0.1:{self.port}/index.html",
                f"http://127.0.0.1:{self.port}/contact.html",
                f"http://127.0.0.1:{self.port}/about.html",
            },
        )
        self.assertEqual(payload["errors"], [])


if __name__ == "__main__":
    unittest.main()
