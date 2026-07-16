# 🛠 Niger Certify Offensive Lab

> **Auteur :** Niger certify – Consultant & Formateur en Sécurité Informatique  
> **Public cible :** Étudiants, stagiaires, passionnés de cybersécurité  
> **Usage :** Pédagogique uniquement (machines vulnérables type DVWA, Metasploitable2, VulnHub, etc.)

---

## 🎯 Objectifs

Ce dépôt a pour but de fournir une collection d’**outils de post-exploitation** et de **webshells personnalisés** pour :

- comprendre les techniques de compromission via le web (RCE, upload),
- analyser et escalader les privilèges (privesc),
- renforcer la pratique en environnement de lab (CTF, formations CEH, OSCP, etc.),
- apprendre à coder des interfaces offensives web côté PHP/Bash.

---

## 📁 Structure du dépôt

| Dossier             | Contenu                                                                 |
|---------------------|-------------------------------------------------------------------------|
| `webshells/`        | Webshells basiques et avancés avec interface stylisée                   |
| `uploaders/`        | Scripts pour upload de fichiers (inclus bypass MIME type)               |
| `privesc/`          | Scripts pour énumération et élévation de privilèges                     |
| `scanners/`         | Outils de reconnaissance ou de détection d'ouvertures                   |
| `reverse_shell/`    | Générateur de shell inversé et fichiers de cheat sheet                  |
| `scripts/postex/`   | Scripts Bash pour la post-exploitation (hash dump, enum, SUID, etc.)    |

---

## 🧪 Exemples d’outils inclus

### 🔹 Webshell Avancé

![](https://raw.githubusercontent.com/TON_USER/webshell-it4u-lab/main/.images/webshell_interface.png)

- Interface propre en HTML/CSS
- Exécution de commandes via GET
- Upload de fichiers
- Menu de post-exploitation (SUID, sudo, cron, capabilities...)

### 🔹 Privesc rapide (PHP + Bash)

```php
find / -perm -4000 2>/dev/null
```

---

## 🆕 Scanner Bug Bounty Web (safe by design)

Un nouveau scanner CLI Python est disponible dans `scanners/web_bugbounty_tool.py`.

### Capacités

- crawl limité au même hôte avec profondeur configurable,
- extraction des liens, scripts, formulaires et paramètres d’URL,
- détection d’en-têtes de sécurité manquants,
- analyse des cookies (`Secure`, `HttpOnly`, `SameSite`),
- heuristique sur les formulaires POST sans jeton CSRF,
- sondage d’endpoints courants (`robots.txt`, `sitemap.xml`, `/.git/HEAD`, `swagger`, `graphql`, etc.),
- export des résultats en JSON et Markdown.

### Exemple d’utilisation

```bash
python3 scanners/web_bugbounty_tool.py https://example.com \
  --depth 2 \
  --max-pages 25 \
  --json report.json \
  --markdown report.md
```
