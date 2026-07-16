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

## 🕵️‍♂️ Nouvel outil bug bounty web

Le script `web_bugbounty_tool.py` ajoute un scanner orienté **applications web** :

- crawl intelligent (liens, scripts, formulaires),
- détection d'open redirect,
- détection de XSS réfléchi,
- détection de mauvaises configurations CORS,
- détection de méthodes HTTP dangereuses,
- détection de fichiers sensibles exposés,
- génération de rapports JSON + Markdown.

### Exécution rapide

```bash
python3 web_bugbounty_tool.py --url https://example.com --depth 2 --max-urls 200
```

### Tests

```bash
python3 -m unittest -v test_web_bugbounty_tool.py
```
