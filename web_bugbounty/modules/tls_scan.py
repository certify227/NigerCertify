"""Analyse TLS/SSL : certificat, expiration, versions de protocole."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import List
from urllib.parse import urlparse

from ..core.findings import Finding, Severity
from ..core.http_client import HttpClient


def _negotiated(host: str, port: int = 443, timeout: float = 8.0):
    """Retourne (version_protocole, suite_de_chiffrement) sans valider la chaîne."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.version(), ssock.cipher()


def run(client: HttpClient, url: str, ctx: dict | None = None) -> List[Finding]:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme != "https":
        return [
            Finding(
                title="Pas de HTTPS",
                severity=Severity.MEDIUM,
                target=url,
                module="tls",
                description="La cible n'utilise pas HTTPS ; le trafic peut être intercepté.",
                remediation="Servir le site en HTTPS et rediriger le HTTP vers HTTPS.",
            )
        ]

    host = parsed.hostname or ""
    port = parsed.port or 443
    findings: List[Finding] = []

    try:
        version, cipher = _negotiated(host, port)
    except Exception as exc:
        return [
            Finding(
                title="Connexion TLS impossible",
                severity=Severity.INFO,
                target=f"{host}:{port}",
                module="tls",
                description="Impossible d'établir une connexion TLS.",
                evidence=str(exc)[:200],
            )
        ]

    findings.append(
        Finding(
            title="Informations TLS",
            severity=Severity.INFO,
            target=f"{host}:{port}",
            module="tls",
            description="Protocole et suite de chiffrement négociés.",
            evidence=f"{version} · {cipher[0] if cipher else '?'}",
        )
    )

    if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append(
            Finding(
                title=f"Protocole TLS obsolète : {version}",
                severity=Severity.MEDIUM,
                target=f"{host}:{port}",
                module="tls",
                description="Un protocole TLS déprécié est accepté.",
                remediation="Désactiver TLS < 1.2 et privilégier TLS 1.3.",
            )
        )

    # Validation du certificat via contexte strict (nom d'hôte + chaîne).
    try:
        strict = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8.0) as sock:
            with strict.wrap_socket(sock, server_hostname=host) as ssock:
                validated = ssock.getpeercert()
        not_after = validated.get("notAfter") if validated else None
        if not_after:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (expires - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(
                    Finding(
                        title="Certificat TLS expiré",
                        severity=Severity.HIGH,
                        target=f"{host}:{port}",
                        module="tls",
                        description="Le certificat est expiré.",
                        evidence=f"Expiré depuis {-days_left} jours ({not_after}).",
                        remediation="Renouveler le certificat immédiatement.",
                    )
                )
            elif days_left < 15:
                findings.append(
                    Finding(
                        title="Certificat TLS proche de l'expiration",
                        severity=Severity.LOW,
                        target=f"{host}:{port}",
                        module="tls",
                        description="Le certificat expire bientôt.",
                        evidence=f"Expire dans {days_left} jours ({not_after}).",
                        remediation="Planifier le renouvellement.",
                    )
                )
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            Finding(
                title="Certificat TLS invalide",
                severity=Severity.MEDIUM,
                target=f"{host}:{port}",
                module="tls",
                description="La validation du certificat échoue (nom d'hôte ou chaîne).",
                evidence=str(exc)[:200],
                remediation="Installer un certificat valide couvrant le nom d'hôte, avec chaîne complète.",
            )
        )
    except Exception:
        pass

    return findings
