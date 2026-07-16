"""WebSocket security scanner."""

from __future__ import annotations

import re

import requests

from .utils import Finding, get_base_url, normalize_url, safe_request

WS_PATHS = ["/ws", "/websocket", "/socket", "/socket.io/", "/api/ws", "/live", "/stream"]


class WebSocketScanner:
    """Teste la sécurité des WebSockets."""

    def __init__(self, target: str, session: requests.Session):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.findings: list[Finding] = []

    def run_full_scan(self) -> list[Finding]:
        self._discover_endpoints()
        self._test_origin_bypass()
        return self.findings

    def _discover_endpoints(self) -> None:
        resp = safe_request(self.session, "GET", self.target)
        if resp:
            ws_urls = re.findall(r'wss?://[^\s"\']+', resp.text)
            for ws_url in ws_urls[:5]:
                self.findings.append(
                    Finding(
                        title=f"WebSocket endpoint: {ws_url}",
                        severity="info",
                        category="WebSocket",
                        url=ws_url,
                        description="Endpoint WebSocket découvert dans le code",
                    )
                )

        scheme = "wss" if self.target.startswith("https") else "ws"
        host = self.base_url.replace("https://", "").replace("http://", "")
        for path in WS_PATHS:
            ws_url = f"{scheme}://{host}{path}"
            try:
                import socket
                import ssl as ssl_mod
                host_part = host.split(":")[0]
                port = 443 if scheme == "wss" else 80
                sock = socket.create_connection((host_part, port), timeout=5)
                if scheme == "wss":
                    ctx = ssl_mod.create_default_context()
                    sock = ctx.wrap_socket(sock, server_hostname=host_part)
                upgrade = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host_part}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                )
                sock.send(upgrade.encode())
                response = sock.recv(4096).decode(errors="ignore")
                sock.close()
                if "101" in response or "Switching Protocols" in response:
                    self.findings.append(
                        Finding(
                            title=f"WebSocket actif: {path}",
                            severity="info",
                            category="WebSocket",
                            url=ws_url,
                            description="Upgrade WebSocket accepté",
                            evidence=response[:200],
                        )
                    )
            except (OSError, ImportError):
                pass

    def _test_origin_bypass(self) -> None:
        """Teste si le serveur accepte des Origins arbitraires."""
        host = self.base_url.replace("https://", "").replace("http://", "").split("/")[0]
        host_part = host.split(":")[0]
        try:
            import socket
            sock = socket.create_connection((host_part, 443 if "https" in self.target else 80), timeout=5)
            upgrade = (
                f"GET /ws HTTP/1.1\r\n"
                f"Host: {host_part}\r\n"
                f"Origin: https://evil.com\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            sock.send(upgrade.encode())
            response = sock.recv(4096).decode(errors="ignore")
            sock.close()
            if "101" in response:
                self.findings.append(
                    Finding(
                        title="WebSocket accepte Origin arbitraire",
                        severity="high",
                        category="WebSocket",
                        url=self.target,
                        description="Origin https://evil.com accepté",
                        evidence=response[:200],
                        remediation="Valider l'header Origin",
                    )
                )
        except OSError:
            pass
