# web_bugbounty

Boîte à outils **modulaire** de reconnaissance et d'audit de sécurité des applications web,
conçue pour le **bug bounty** et le pentest **autorisé**.

> ⚠️ **Usage autorisé uniquement.** N'utilisez cet outil que sur des cibles pour lesquelles
> vous disposez d'une autorisation écrite explicite (programme de bug bounty en périmètre,
> mandat de pentest, ou vos propres systèmes). Tout usage non autorisé est illégal.

## Fonctionnalités

| Module        | Description |
|---------------|-------------|
| `recon`       | Empreinte technologique (en-têtes + contenu), `robots.txt`, `sitemap.xml`. |
| `headers`     | En-têtes de sécurité (CSP, HSTS, X-Frame-Options…), attributs de cookies, fuites d'info. |
| `tls`         | Version TLS négociée, protocoles obsolètes, validité/expiration du certificat. |
| `vulns`       | CORS permissif/reflété, open redirect, reflet non échappé (XSS), méthodes HTTP à risque. |
| `content`     | Découverte de fichiers/dossiers sensibles (`.git`, `.env`, dumps SQL, backups…) + wordlist. |
| `subdomains`  | Énumération passive (crt.sh) + brute-force DNS. |

Autres atouts :

- **Contrôle de périmètre (scope)** intégré pour ne jamais sortir des cibles autorisées.
- **Concurrence** (threads) + **rate limiting** configurable.
- **Rapports** : console colorée, JSON, Markdown, HTML.
- **Probes non destructifs** (aucune charge offensive réelle envoyée).
- Support **proxy** (Burp/ZAP), en-têtes et cookies personnalisés.

## Installation

```bash
pip install -r web_bugbounty/requirements.txt
```

`requests` suffit ; `dnspython` améliore l'énumération DNS (optionnel).

## Utilisation

```bash
# Scan par défaut (recon + headers + tls + vulns + content)
python -m web_bugbounty https://exemple.com --yes

# Tous les modules (inclut l'énumération de sous-domaines)
python -m web_bugbounty exemple.com --all --yes

# Modules ciblés + rapport HTML
python -m web_bugbounty https://exemple.com -m headers,vulns,tls -f html -o rapport.html --yes

# Via un proxy d'interception (Burp) et un cookie de session
python -m web_bugbounty https://exemple.com --proxy http://127.0.0.1:8080 \
    --cookie "session=abc123" -k --yes

# Liste de cibles + périmètre explicite + rate limiting
python -m web_bugbounty -l cibles.txt --scope exemple.com,exemple.net \
    --rate-limit 0.2 -f json -o resultats.json --yes
```

### Options principales

| Option | Rôle |
|--------|------|
| `-m, --modules` | Modules à exécuter (virgules). |
| `--all` | Tous les modules. |
| `-s, --scope` | Domaines autorisés (défaut : domaine racine de la cible). |
| `--exclude` | Domaines/hôtes exclus. |
| `-t, --threads` | Concurrence (défaut : 20). |
| `--rate-limit` | Délai min. entre requêtes (s). |
| `--proxy` | Proxy HTTP(S). |
| `-H, --header` | En-tête personnalisé (répétable). |
| `--cookie` | En-tête Cookie. |
| `-k, --insecure` | Ignorer la vérif. TLS. |
| `-w, --wordlist` | Wordlist de découverte de contenu. |
| `-f, --format` | `console` \| `json` \| `md` \| `html`. |
| `-o, --output` | Fichier de sortie. |
| `--min-severity` | Filtre de sévérité (`info`→`critical`). |
| `--yes` | Confirme l'autorisation sans invite. |

Le code de sortie vaut `1` si au moins un finding **High/Critical** est trouvé (pratique en CI).

## Architecture

```
web_bugbounty/
├── cli.py              # interface ligne de commande
├── scanner.py          # orchestrateur des modules
├── core/
│   ├── findings.py     # modèle Finding + sévérités
│   ├── http_client.py  # session HTTP (retries, rate limit, proxy)
│   ├── scope.py        # gestion du périmètre
│   └── reporter.py     # console / JSON / Markdown / HTML
├── modules/            # recon, headers, tls_scan, vulns, content_discovery, subdomains
└── wordlists/          # wordlists par défaut
```

Ajouter un module : créez `modules/mon_module.py` avec une fonction
`run(client, url, ctx) -> List[Finding]` puis enregistrez-la dans `scanner.MODULES`.
