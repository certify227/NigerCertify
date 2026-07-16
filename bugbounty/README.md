# 🎯 WebBounty — Outil de Bug Bounty Web

> **Usage éthique uniquement** — N'utilisez cet outil que sur des cibles pour lesquelles vous disposez d'une autorisation explicite (programme de bug bounty, pentest contractuel, lab personnel type DVWA, HackTheBox, etc.)

---

## Fonctionnalités

| Module | Capacités |
|--------|-----------|
| **Reconnaissance** | DNS, SSL/TLS, fingerprinting, robots.txt, sitemap, sous-domaines, crawl, emails |
| **Scan vulnérabilités** | Headers, CORS, cookies, fichiers sensibles, XSS, SQLi, SSRF, open redirect, CSRF |
| **Scan agressif** | LFI, SSTI, CMDi, XXE, Host header injection, CRLF, IDOR, cache poisoning, secrets exposés |
| **JWT** | Extraction, décodage, alg:none, brute-force secret HMAC, claims sensibles, privilege escalation |
| **GraphQL** | Découverte endpoints, introspection, field suggestions, batching, DoS alias, mutations non auth |
| **Nuclei** | Intégration Nuclei (si installé) + 20 checks CVE intégrés (Spring, Docker, K8s, etc.) |
| **Fuzzing** | Répertoires, paramètres cachés, endpoints JS |
| **Rapports** | Export HTML + JSON |

---

## Installation

```bash
cd bugbounty
pip install -r requirements.txt

# Optionnel — Nuclei pour scans CVE avancés
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

---

## Utilisation

### Scan complet

```bash
python3 webbounty.py -t https://example.com --full
```

### Mode brutal (tout activer)

```bash
python3 webbounty.py -t https://target.com --brutal
```

Active : recon + scan + fuzz + aggressive + JWT + GraphQL + Nuclei

### Modules individuels

```bash
# Scan agressif (LFI, SSTI, CMDi, XXE, IDOR, secrets)
python3 webbounty.py -t https://target.com --aggressive

# Analyse JWT
python3 webbounty.py -t https://target.com --jwt

# Scan GraphQL
python3 webbounty.py -t https://target.com --graphql

# Nuclei / checks CVE
python3 webbounty.py -t https://target.com --nuclei

# Combinaison ciblée
python3 webbounty.py -t https://target.com --jwt --graphql --aggressive --nuclei
```

### Via Burp Suite

```bash
python3 webbounty.py -t https://target.com --brutal --proxy http://127.0.0.1:8080 --no-ssl-verify
```

### Options avancées

```bash
python3 webbounty.py -t https://target.com \
  --brutal \
  --threads 20 \
  --timeout 15 \
  --nuclei-templates /path/to/templates \
  --report rapport.html \
  -v
```

---

## Structure

```
bugbounty/
├── webbounty.py
├── modules/
│   ├── recon.py
│   ├── scanner.py
│   ├── aggressive.py      # LFI, SSTI, CMDi, XXE, IDOR...
│   ├── jwt_scanner.py     # Analyse et attaques JWT
│   ├── graphql_scanner.py # Scan GraphQL offensif
│   ├── nuclei_scanner.py  # Nuclei + CVE intégrés
│   ├── fuzzer.py
│   ├── reporter.py
│   └── utils.py
└── wordlists/
    ├── subdomains.txt
    ├── directories.txt
    ├── parameters.txt
    └── jwt_secrets.txt
```

---

## Tests couverts

| Catégorie | Sévérité | Module |
|-----------|----------|--------|
| LFI / Path Traversal | Critical | aggressive |
| SSTI | Critical | aggressive |
| Command Injection | Critical | aggressive |
| XXE | Critical | aggressive |
| JWT alg:none / secret faible | Critical | jwt |
| GraphQL introspection | High | graphql |
| IDOR | High | aggressive |
| Host Header Injection | High | aggressive |
| CRLF Injection | High | aggressive |
| Cache Poisoning | High | aggressive |
| Secrets exposés (AWS, Stripe, GitHub) | Critical | aggressive |
| CVE / misconfigurations | Critical-Info | nuclei |
| SQLi / XSS / SSRF | Critical-High | scanner |

---

## Avertissement légal

Cet outil est fourni à des fins **pédagogiques et de recherche en sécurité autorisée** uniquement. L'utilisation non autorisée contre des systèmes tiers est **illégale**.
