# ⚡ BountyStrike v3.0

> **Strike First. Hunt Smart.**
>
> Outil offensif complet de bug bounty web — **Niger Certify Offensive Lab**

---

## Modules inclus (40+)

| Catégorie | Modules |
|-----------|---------|
| **Recon** | DNS, SSL, techno, robots.txt, crt.sh, Wayback, Shodan, sous-domaines, crawl |
| **Infra** | TLS avancé, SPF/DMARC, vhost discovery, WAF detection |
| **Cloud** | S3, GCS, Azure Blob, Firebase |
| **Scan** | Headers, CORS, cookies, XSS, SQLi, SSRF, fichiers sensibles |
| **Offensif** | LFI, SSTI, CMDi, XXE, IDOR, CRLF, cache poisoning, secrets |
| **Avancé** | XSS DOM/blind/stored, SQLi boolean/time, NoSQL, upload, OOB |
| **Auth** | JWT, OAuth, SAML, account takeover, password reset poisoning |
| **API** | GraphQL, OpenAPI/Swagger, WebSocket, SOAP hints |
| **Réseau** | SSRF cloud+bypass, HTTP smuggling CL.TE/TE.CL |
| **Logique** | Race conditions, prix négatif, manipulation |
| **Injection** | LDAP, prototype pollution, deserialization |
| **Source** | .git dump, clickjacking, CSP bypass |
| **Takeover** | 22 services (GitHub, S3, Vercel, Netlify...) |
| **Externe** | Nuclei, ffuf, dalfox, sqlmap |
| **Rapports** | HTML, JSON, HackerOne, Burp XML, diff, SQLite, dashboard |

---

## Installation

```bash
cd bugbounty
pip install -r requirements.txt

# Optionnel
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest
```

---

## Utilisation

```bash
# Mode brutal — absolument tout
python3 bountystrike.py -t https://cible.com --brutal

# Scan complet v3
python3 bountystrike.py -t https://cible.com --extended

# Multi-cibles
python3 bountystrike.py -l targets.txt --full

# Authentifié
python3 bountystrike.py -t https://cible.com --extended \
  --bearer TOKEN --cookie "session=abc123"

# OOB (Interactsh/Collaborator)
python3 bountystrike.py -t https://cible.com --extended \
  --oob-callback xyz.oast.fun

# Exports
python3 bountystrike.py -t https://cible.com --brutal \
  --export-h1 rapport_h1.md --export-burp rapport.xml

# Dashboard web
python3 bountystrike.py --dashboard --dashboard-port 8888

# Diff de scans
python3 bountystrike.py --diff old.json new.json
```

---

## Flags principaux

| Flag | Description |
|------|-------------|
| `--brutal` | Active TOUS les modules + outils externes |
| `--extended` | Tous les modules avancés v3 |
| `--full` | Scan complet standard |
| `-l FILE` | Fichier multi-cibles |
| `--scope-file` | Fichier de scope (*.domain.com) |
| `--shodan-key` | Clé API Shodan |
| `--external-tools` | ffuf, dalfox, sqlmap |

---

## Avertissement

Usage **éthique uniquement** — cibles autorisées seulement.
