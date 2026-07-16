# NCScan — Niger Certify Web Bug Bounty Toolkit

> Boîte à outils modulaire, rapide et lisible pour le **bug bounty d'applications web** :
> reconnaissance, crawling, scan de vulnérabilités actives, audit de configuration, fuzzing
> de fichiers sensibles et **rapports HTML/JSON** clés en main.

---

## ⚠️ Avertissement légal

Cet outil est **strictement destiné** à des cibles :
- pour lesquelles vous avez une **autorisation écrite** (mandat de pentest),
- que vous **possédez**,
- ou qui sont **inscrites à un programme de bug bounty** avec un scope explicite.

L'usage non autorisé est **illégal**. Vous êtes seul·e responsable de ce que vous en faites.
Une confirmation interactive est demandée au démarrage (option `-y` pour la CI).

---

## 🧩 Modules

| Module    | Contenu |
|-----------|---------|
| `recon`   | DNS (A/AAAA/MX/NS/TXT/CNAME), énumération de sous-domaines (crt.sh + bruteforce), fingerprinting technos, robots.txt & sitemap.xml |
| `crawl`   | Crawler concurrent (multi-threads), profondeur configurable, extraction de formulaires et paramètres |
| `scan`    | Reflected **XSS**, **SQLi** (error-based + boolean-based), **LFI**, **SSRF**, **Open Redirect**, **CRLF Injection**, directory listing |
| `headers` | Audit des en-têtes de sécurité (HSTS/CSP/XFO/XCTO/Referrer-Policy/Permissions-Policy), **CORS** (dont reflet d'Origin), **cookies** (Secure/HttpOnly/SameSite), HTTP en clair |
| `fuzz`    | Bruteforce de fichiers/répertoires sensibles (`.env`, `.git/`, `wp-config.php`, `actuator/*`, backups…), calibration anti-404-déguisée |
| `report`  | Génère un rapport **JSON** et un **HTML autonome** stylisé |

---

## 🚀 Installation

```bash
pip install -r bugbounty_tool/requirements.txt
```

Python ≥ 3.9 requis. `dnspython` est optionnel (fallback via `socket`).

---

## 🔧 Utilisation

Depuis la racine du dépôt :

```bash
# Scan par défaut : recon + crawl + headers + scan
python -m bugbounty_tool.main https://cible.tld

# Scan complet (inclut fuzzing)
python -m bugbounty_tool.main https://cible.tld --all

# Modules ciblés
python -m bugbounty_tool.main https://cible.tld --headers --scan --depth 3

# Derrière Burp
python -m bugbounty_tool.main https://cible.tld --all \
    --proxy http://127.0.0.1:8080 -k --threads 10 --rate 10

# Avec authentification
python -m bugbounty_tool.main https://cible.tld --scan \
    --cookie "session=abc123" --header "Authorization: Bearer eyJ..."
```

### Options principales

| Option                 | Description                                                |
|------------------------|------------------------------------------------------------|
| `--all`                | Active tous les modules                                    |
| `--recon` / `--crawl` / `--scan` / `--headers` / `--fuzz` | Modules individuels             |
| `--subdomains`         | Force l'énumération de sous-domaines                       |
| `--no-passive`         | Désactive `crt.sh`                                         |
| `--depth N`            | Profondeur max du crawl                                    |
| `--max-urls N`         | Nombre max d'URLs crawlées                                 |
| `--wordlist PATH`      | Wordlist du fuzzer                                         |
| `--sub-wordlist PATH`  | Wordlist des sous-domaines                                 |
| `--threads N`          | Threads concurrents                                        |
| `--rate FLOAT`         | Requêtes/seconde max (protège la cible)                    |
| `--proxy URL`          | Proxy HTTP/HTTPS (Burp, mitmproxy…)                        |
| `-k / --insecure`      | Ignore la validation TLS                                   |
| `--cookie K=V`         | Cookie(s), répétable                                       |
| `--header 'K: V'`      | En-tête custom, répétable                                  |
| `--out DIR`            | Dossier des rapports (défaut : `reports/`)                 |
| `-y / --yes`           | Accepte le rappel légal (non interactif)                   |
| `-v`                   | Verbose                                                    |

### Codes de sortie

- `0` : aucune vulnérabilité *high/critical* trouvée
- `1` : au moins une *high/critical*
- `2` : consentement refusé
- `3` : cible injoignable

Idéal pour intégrer dans une CI de bug bounty programmatique.

---

## 📄 Rapports

À la fin, deux fichiers sont créés dans `reports/` :

- `report-<id>.json` — machine-lisible, exploitable par d'autres outils
- `report-<id>.html` — rapport visuel autonome (aucune dépendance externe)

Chaque finding contient : `module`, `title`, `severity`, `url`, `description`,
`evidence`, `remediation`, `cwe`, `payload`.

---

## 🧠 Bonnes pratiques

- Toujours démarrer par un **scan lent** (`--rate 5 --threads 5`) sur des cibles inconnues.
- Utiliser `--proxy http://127.0.0.1:8080` pour rejouer les requêtes dans Burp.
- Les détections XSS/SQLi/LFI/SSRF sont **des suspicions** : valider manuellement.
- Combiner avec vos propres wordlists (`--wordlist` / `--sub-wordlist`) pour de meilleurs résultats.

---

## 🗂 Structure

```
bugbounty_tool/
├── main.py               # CLI orchestrateur
├── core.py               # HttpClient, Finding, logs
├── modules/
│   ├── recon.py          # DNS / subdomains / fingerprint / robots
│   ├── crawler.py        # crawler HTML
│   ├── scanner.py        # XSS / SQLi / LFI / SSRF / redirect / CRLF
│   ├── headers.py        # headers / CORS / cookies
│   ├── fuzzer.py         # bruteforce fichiers/répertoires
│   └── reporter.py       # rapport JSON + HTML
├── payloads/             # xss.txt, sqli.txt, lfi.txt, ssrf.txt, redirect.txt
├── wordlists/            # subdomains.txt, common.txt
└── requirements.txt
```

---

## 📜 Licence

Usage pédagogique — Niger Certify Offensive Lab.
