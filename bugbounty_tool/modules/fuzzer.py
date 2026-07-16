"""
Fuzzer de fichiers et répertoires sensibles.

Détecte automatiquement les faux positifs en calibrant sur un chemin aléatoire
(le serveur renvoie parfois 200 pour tout — motif « page 404 déguisée »).
"""

from __future__ import annotations

import concurrent.futures as cf
import random
import string
from pathlib import Path
from typing import List, Optional, Set
from urllib.parse import urljoin

from ..core import Finding, HttpClient, log_info, log_ok, log_warn


INTERESTING = {".env", ".git/config", ".git/HEAD", "wp-config.php",
                "config.php.bak", "backup.zip", "backup.sql", "dump.sql",
                "id_rsa", "credentials", "credentials.json", "actuator/env",
                "actuator/heapdump", "phpinfo.php", "server-status", "swagger.json"}


def _rand(n: int = 16) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _calibrate(http: HttpClient, base: str) -> Optional[int]:
    """Renvoie une taille de réponse typique des 404-comme-200, sinon None."""
    probe = urljoin(base + "/", f"ncscan-{_rand()}-{_rand()}")
    r = http.get(probe)
    if not r:
        return None
    if r.status_code == 200:
        return len(r.text or "")
    return None


def fuzz(
    http: HttpClient,
    base_url: str,
    wordlist_path: Path,
    threads: int = 20,
) -> List[Finding]:
    log_info(f"Fuzzing de {base_url} avec {wordlist_path.name}")
    if not wordlist_path.exists():
        log_warn(f"Wordlist introuvable : {wordlist_path}")
        return []

    words = [
        w.strip().lstrip("/")
        for w in wordlist_path.read_text().splitlines()
        if w.strip() and not w.startswith("#")
    ]
    calib_len = _calibrate(http, base_url)
    if calib_len is not None:
        log_warn(f"Le serveur renvoie 200 pour un chemin aléatoire ({calib_len} octets) — "
                 "filtrage par taille activé.")

    findings: List[Finding] = []
    seen: Set[str] = set()

    def _probe(word: str) -> Optional[Finding]:
        url = urljoin(base_url + "/", word)
        if url in seen:
            return None
        seen.add(url)
        r = http.get(url, allow_redirects=False)
        if not r:
            return None
        status = r.status_code
        length = len(r.content or b"")
        if calib_len is not None and status == 200 and abs(length - calib_len) < 50:
            return None
        if status in (200, 201, 204, 301, 302, 401, 403, 500):
            interesting = word in INTERESTING or any(word.endswith(x) for x in (".env", ".sql", ".bak", ".git/HEAD"))
            if status == 200 and interesting:
                sev = "high"
            elif status == 200:
                sev = "low"
            elif status in (301, 302):
                sev = "info"
            elif status in (401, 403):
                sev = "info"
            elif status == 500:
                sev = "low"
            else:
                sev = "info"
            title = "Fichier/chemin sensible exposé" if interesting and status == 200 else f"Chemin trouvé ({status})"
            return Finding(
                module="fuzzer",
                title=title,
                severity=sev,
                url=url,
                description=f"Réponse HTTP {status} ({length} octets).",
                evidence=f"HTTP {status}",
                remediation="Bloquer l'accès public ou supprimer les fichiers sensibles.",
            )
        return None

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for f in ex.map(_probe, words):
            if f:
                findings.append(f)
                log_ok(f"[{f.severity.upper()}] {f.url}")

    return findings
