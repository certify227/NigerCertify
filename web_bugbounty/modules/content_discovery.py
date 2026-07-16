"""Découverte de contenu : fichiers sensibles et brute-force de chemins."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
from urllib.parse import urljoin, urlparse

from ..core.findings import Finding, Severity
from ..core.http_client import HttpClient

# Fichiers/dossiers sensibles fréquents avec sévérité associée.
SENSITIVE_PATHS: List[Tuple[str, Severity, str]] = [
    (".git/config", Severity.HIGH, "Dépôt Git exposé — code source récupérable."),
    (".git/HEAD", Severity.HIGH, "Dépôt Git exposé."),
    (".env", Severity.CRITICAL, "Fichier d'environnement — secrets/credentials probables."),
    (".env.local", Severity.CRITICAL, "Fichier d'environnement exposé."),
    (".env.production", Severity.CRITICAL, "Fichier d'environnement de production exposé."),
    ("config.php.bak", Severity.HIGH, "Sauvegarde de config exposée."),
    ("wp-config.php.bak", Severity.CRITICAL, "Sauvegarde wp-config exposée."),
    ("backup.zip", Severity.HIGH, "Archive de sauvegarde exposée."),
    ("backup.sql", Severity.CRITICAL, "Dump SQL exposé."),
    ("dump.sql", Severity.CRITICAL, "Dump SQL exposé."),
    ("db.sql", Severity.CRITICAL, "Dump SQL exposé."),
    (".DS_Store", Severity.LOW, "Fichier macOS révélant l'arborescence."),
    (".htaccess", Severity.MEDIUM, "Fichier de config Apache exposé."),
    ("phpinfo.php", Severity.MEDIUM, "phpinfo() expose la configuration serveur."),
    ("info.php", Severity.MEDIUM, "phpinfo() potentiel."),
    (".svn/entries", Severity.HIGH, "Dépôt SVN exposé."),
    ("docker-compose.yml", Severity.MEDIUM, "Compose Docker exposé (secrets possibles)."),
    ("Dockerfile", Severity.LOW, "Dockerfile exposé."),
    ("composer.json", Severity.LOW, "Dépendances PHP exposées."),
    ("package.json", Severity.LOW, "Dépendances Node exposées."),
    (".aws/credentials", Severity.CRITICAL, "Credentials AWS exposés."),
    ("id_rsa", Severity.CRITICAL, "Clé privée SSH exposée."),
    ("server-status", Severity.MEDIUM, "Apache server-status exposé."),
    ("actuator/health", Severity.LOW, "Spring Actuator exposé."),
    ("actuator/env", Severity.HIGH, "Spring Actuator /env expose la config."),
    (".well-known/security.txt", Severity.INFO, "security.txt présent."),
    ("swagger.json", Severity.LOW, "Spécification API Swagger exposée."),
    ("openapi.json", Severity.LOW, "Spécification OpenAPI exposée."),
    ("api/swagger.json", Severity.LOW, "Spécification API exposée."),
    ("admin/", Severity.INFO, "Interface d'administration potentielle."),
    ("login", Severity.INFO, "Page de connexion."),
]

# Signatures négatives : contenu typique de page 404 personnalisée.
def _looks_like_real_hit(resp, body: str) -> bool:
    if resp.status_code not in (200, 401, 403):
        return False
    # 401/403 = existe mais protégé (intéressant).
    if resp.status_code in (401, 403):
        return True
    # Évite les faux positifs des SPA qui renvoient 200 partout.
    if not body.strip():
        return True
    lowered = body.lower()
    if "<title>404" in lowered or "not found" in lowered and len(body) < 2000:
        return False
    return True


def _baseline_404(client: HttpClient, base: str) -> Tuple[int, int]:
    """Récupère la taille d'une réponse pour un chemin inexistant (anti-faux-positifs)."""
    import uuid

    probe = urljoin(base, f"bb-notexist-{uuid.uuid4().hex[:10]}")
    resp = client.get(probe)
    if resp is None:
        return (404, -1)
    return (resp.status_code, len(resp.content or b""))


def _load_wordlist(path: str | None) -> List[str]:
    if not path:
        return []
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def run(
    client: HttpClient,
    url: str,
    ctx: dict | None = None,
) -> List[Finding]:
    ctx = ctx or {}
    threads: int = ctx.get("threads", 20)
    wordlist_path: str | None = ctx.get("wordlist")

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}/"

    baseline_status, baseline_len = _baseline_404(client, base)

    tasks: List[Tuple[str, Severity, str]] = list(SENSITIVE_PATHS)
    for word in _load_wordlist(wordlist_path):
        tasks.append((word, Severity.INFO, "Chemin découvert via wordlist."))

    findings: List[Finding] = []

    def probe(item: Tuple[str, Severity, str]):
        path, severity, desc = item
        target = urljoin(base, path)
        resp = client.get(target, allow_redirects=False)
        if resp is None:
            return None
        body = resp.text if resp.status_code == 200 else ""
        # Rejette si identique à la baseline 404 (SPA / wildcard).
        if (
            resp.status_code == baseline_status
            and baseline_len >= 0
            and abs(len(resp.content or b"") - baseline_len) < 32
            and resp.status_code not in (401, 403)
        ):
            return None
        if _looks_like_real_hit(resp, body):
            return Finding(
                title=f"Ressource accessible : {path}",
                severity=severity,
                target=target,
                module="content_discovery",
                description=desc,
                evidence=f"HTTP {resp.status_code} · {len(resp.content or b'')} octets",
                remediation="Retirer/protéger les fichiers sensibles hors racine web ou via contrôle d'accès.",
            )
        return None

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = [pool.submit(probe, item) for item in tasks]
        for fut in as_completed(futures):
            result = fut.result()
            if result is not None:
                findings.append(result)
    return findings
