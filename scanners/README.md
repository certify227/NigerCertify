# 🐺 WebHunt — Boîte à outils bug bounty web

> Outil de **reconnaissance** et d'**audit de vulnérabilités** pour applications
> web, conçu pour le bug bounty et les tests d'intrusion **autorisés**.
> Fait partie du *Niger Certify Offensive Lab* — usage pédagogique et éthique.

---

## ⚠️ Avertissement légal

WebHunt ne doit être utilisé **QUE** sur des cibles pour lesquelles vous
disposez d'une **autorisation écrite explicite** :

- une cible **dans le périmètre** d'un programme de bug bounty,
- un **mandat de test d'intrusion**,
- votre **propre laboratoire** (DVWA, Juice Shop, VulnHub, etc.).

Tout accès non autorisé à un système informatique est **illégal**. Vous êtes
seul responsable de votre usage. Les checks « actifs » ne s'exécutent qu'après
confirmation d'autorisation (`--i-am-authorized` ou confirmation interactive).

---

## ✨ Fonctionnalités

| Phase | Capacités |
|-------|-----------|
| **Reconnaissance** | Résolution DNS/IP, empreinte technologique (serveur, framework, CMS), `robots.txt`, `sitemap.xml`, `security.txt`, détection de fichiers sensibles exposés (`.git`, `.env`, dumps SQL, sauvegardes…) |
| **Exploration** | Crawler BFS respectant strictement le périmètre, extraction d'URLs, paramètres GET et formulaires |
| **Audit passif** | En-têtes de sécurité manquants (CSP, HSTS, X-Frame-Options…), attributs de cookies (Secure/HttpOnly/SameSite), divulgation de versions, méthodes HTTP risquées, fuites d'informations / secrets / traces de pile |
| **Audit actif** | Redirection ouverte, XSS réfléchi (marqueurs non destructifs), CORS mal configuré (réflexion d'origine) |
| **Rapports** | Console colorée, **JSON** structuré, **HTML** autonome |

**Garde-fous intégrés :** périmètre strict (aucune requête hors scope),
limitation de débit (req/s), reprises automatiques, payloads non destructifs,
confirmation d'autorisation obligatoire pour le mode actif.

---

## 📦 Installation

```bash
cd scanners
python3 -m pip install -r requirements.txt
```

Aucune installation n'est strictement nécessaire : `requests` suffit.

---

## 🚀 Utilisation

```bash
# Audit passif (reconnaissance + checks non intrusifs)
python3 webhunt.py https://exemple.com

# Audit complet (checks actifs) — nécessite l'autorisation
python3 webhunt.py https://exemple.com --active --i-am-authorized

# Élargir le périmètre à plusieurs hôtes
python3 webhunt.py https://exemple.com --scope api.exemple.com --scope cdn.exemple.com

# Générer des rapports
python3 webhunt.py https://exemple.com --json rapport.json --html rapport.html

# Passer par Burp / mitmproxy
python3 webhunt.py https://exemple.com --proxy http://127.0.0.1:8080 --insecure

# Lancer uniquement certains checks
python3 webhunt.py https://exemple.com --only security-headers,cookies,cors
```

On peut aussi l'exécuter comme module :

```bash
python3 -m webhunt https://exemple.com
```

---

## 🔧 Options principales

| Option | Description |
|--------|-------------|
| `--active` | Active les checks actifs (payloads non destructifs) |
| `--i-am-authorized` | Confirme l'autorisation (requis en mode non interactif) |
| `--scope HOST` | Ajoute un hôte au périmètre (répétable) |
| `--no-subdomains` | N'inclut pas les sous-domaines dans le périmètre |
| `--rate N` | Limite à N requêtes/seconde (défaut : 5) |
| `--max-pages N` / `--max-depth N` | Limites du crawler |
| `--no-crawl` | Désactive le crawler |
| `--only LISTE` | Ne lance que les checks listés |
| `--min-severity` | Gravité minimale affichée |
| `--json` / `--html` | Fichiers de rapport |
| `--proxy` / `--insecure` / `--header` | Réseau |

Liste complète : `python3 webhunt.py --help`.

---

## 🧱 Architecture

```
webhunt/
├── cli.py            # orchestration et CLI
├── http_client.py    # client HTTP (scope, rate limit, retries)
├── scope.py          # garde-fou du périmètre
├── recon.py          # reconnaissance
├── crawler.py        # exploration
├── findings.py       # modèle de données
├── report.py         # rapports console/JSON/HTML
└── checks/           # modules de détection
    ├── security_headers.py
    ├── cookies.py
    ├── cors.py
    ├── info_disclosure.py
    ├── http_methods.py
    ├── open_redirect.py
    └── reflected_xss.py
```

Ajouter un check = créer une classe héritant de `checks.base.BaseCheck` puis
l'ajouter à `ALL_CHECKS` dans `checks/__init__.py`.

---

## 🧪 Cibles d'entraînement légales

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [DVWA](https://github.com/digininja/DVWA)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- `testphp.vulnweb.com`, `google-gruyere`, etc.
