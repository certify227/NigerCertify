# 🎯 WebBounty — Outil de Bug Bounty Web

> **Usage éthique uniquement** — N'utilisez cet outil que sur des cibles pour lesquelles vous disposez d'une autorisation explicite (programme de bug bounty, pentest contractuel, lab personnel type DVWA, HackTheBox, etc.)

---

## Fonctionnalités

| Module | Capacités |
|--------|-----------|
| **Reconnaissance** | DNS, SSL/TLS, fingerprinting technologique, robots.txt, sitemap, énumération sous-domaines, crawl de liens, extraction d'emails |
| **Scan vulnérabilités** | En-têtes de sécurité, CORS, cookies, fichiers sensibles (.git, .env, backups), méthodes HTTP, XSS réfléchi, SQLi, open redirect, SSRF, CSRF |
| **Fuzzing** | Brute-force répertoires/fichiers, découverte de paramètres cachés, extraction d'endpoints depuis le JavaScript |
| **Rapports** | Export HTML (dashboard visuel) et JSON structuré |

---

## Installation

```bash
cd bugbounty
pip install -r requirements.txt
```

---

## Utilisation

### Scan complet (recommandé)

```bash
python webbounty.py -t https://example.com --full
```

### Reconnaissance seule

```bash
python webbounty.py -t example.com --recon
```

### Scan de vulnérabilités (mode agressif)

```bash
python webbounty.py -t https://target.com --scan --aggressive
```

### Fuzzing répertoires et paramètres

```bash
python webbounty.py -t https://target.com --fuzz
```

### Avec proxy Burp Suite

```bash
python webbounty.py -t https://target.com --full --proxy http://127.0.0.1:8080 --no-ssl-verify
```

### Options avancées

```bash
python webbounty.py -t https://target.com \
  --full \
  --threads 20 \
  --timeout 15 \
  --report mon_rapport.html \
  --json mon_rapport.json \
  -v
```

---

## Structure

```
bugbounty/
├── webbounty.py          # Point d'entrée CLI
├── requirements.txt
├── README.md
├── modules/
│   ├── recon.py          # Reconnaissance
│   ├── scanner.py        # Scan de vulnérabilités
│   ├── fuzzer.py         # Fuzzing
│   ├── reporter.py       # Génération de rapports
│   └── utils.py          # Utilitaires partagés
├── wordlists/
│   ├── subdomains.txt
│   ├── directories.txt
│   └── parameters.txt
└── reports/              # Rapports générés (auto-créé)
```

---

## Tests couverts

| Catégorie | Sévérité | Description |
|-----------|----------|-------------|
| Security Headers | Medium-Low | HSTS, CSP, X-Frame-Options, etc. |
| CORS Misconfiguration | Critical-High | Wildcard + credentials, origine réfléchie |
| Cookie Security | Medium-Low | Flags Secure, HttpOnly, SameSite |
| Sensitive File Exposure | Critical-Info | .git, .env, backups, phpinfo, actuator |
| XSS (Reflected) | High | Payloads réfléchis dans la réponse |
| SQL Injection | Critical | Erreurs SQL dans les réponses |
| Open Redirect | Medium | Redirection vers domaine externe |
| SSRF | Critical | Accès métadonnées cloud |
| CSRF | Low | Formulaires POST sans token |
| HTTP Methods | Medium-High | TRACE, PUT, DELETE autorisés |

---

## Avertissement légal

Cet outil est fourni à des fins **pédagogiques et de recherche en sécurité autorisée** uniquement. L'utilisation non autorisée contre des systèmes tiers est **illégale**. L'auteur décline toute responsabilité en cas de mauvaise utilisation.
