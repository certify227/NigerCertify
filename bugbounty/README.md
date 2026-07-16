# ⚡ BountyStrike

> **Strike First. Hunt Smart.**
>
> Outil offensif de bug bounty web par **Niger Certify Offensive Lab**
>
> **Usage éthique uniquement** — cibles autorisées seulement (bug bounty, pentest, labs)

---

## Fonctionnalités

| Module | Flag | Capacités |
|--------|------|-----------|
| **Reconnaissance** | `--recon` | DNS, SSL, fingerprinting, sous-domaines, crawl |
| **Scan vulnérabilités** | `--scan` | Headers, CORS, XSS, SQLi, fichiers sensibles |
| **Scan agressif** | `--aggressive` | LFI, SSTI, CMDi, XXE, IDOR, secrets exposés |
| **SSRF avancé** | `--ssrf` | AWS/GCP/Azure metadata, bypass encoding, blind SSRF |
| **Subdomain Takeover** | `--takeover` | GitHub, Heroku, S3, Vercel, Netlify, Azure... |
| **JWT** | `--jwt` | alg:none, brute-force HMAC, claims sensibles |
| **GraphQL** | `--graphql` | Introspection, batching, DoS alias |
| **GraphQL Fuzz** | `--graphql-fuzz` | Injection SQL/SSTI, brute-force champs, batch mutations |
| **Nuclei** | `--nuclei` | Intégration Nuclei + 20 checks CVE intégrés |
| **Fuzzing** | `--fuzz` | Répertoires, paramètres, endpoints JS |

---

## Installation

```bash
cd bugbounty
pip install -r requirements.txt

# Optionnel — Nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

---

## Utilisation

### Mode brutal — tout activer

```bash
python3 bountystrike.py -t https://cible.com --brutal
```

### Scan complet

```bash
python3 bountystrike.py -t https://cible.com --full
```

### Modules ciblés

```bash
# SSRF cloud metadata + bypass
python3 bountystrike.py -t https://cible.com --ssrf

# Subdomain takeover
python3 bountystrike.py -t cible.com --takeover --recon

# Fuzzing GraphQL
python3 bountystrike.py -t https://cible.com --graphql --graphql-fuzz

# Combo offensive
python3 bountystrike.py -t https://cible.com --ssrf --takeover --aggressive --jwt
```

### Via Burp Suite

```bash
python3 bountystrike.py -t https://cible.com --brutal \
  --proxy http://127.0.0.1:8080 --no-ssl-verify -v
```

---

## Structure

```
bugbounty/
├── bountystrike.py         # Point d'entrée principal
├── webbounty.py            # Alias de compatibilité
├── modules/
│   ├── brand.py            # Branding BountyStrike
│   ├── recon.py
│   ├── scanner.py
│   ├── aggressive.py
│   ├── ssrf_scanner.py     # SSRF avancé
│   ├── takeover.py         # Subdomain takeover
│   ├── jwt_scanner.py
│   ├── graphql_scanner.py
│   ├── graphql_fuzzer.py   # Fuzzing GraphQL
│   ├── nuclei_scanner.py
│   ├── fuzzer.py
│   ├── reporter.py
│   └── utils.py
└── wordlists/
```

---

## Avertissement légal

Outil **pédagogique** pour la recherche en sécurité autorisée. Usage non autorisé = **illégal**.
