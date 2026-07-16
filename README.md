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

### 🔹 WebSentinel - scanner bug bounty web

`scanners/websentinel.py` est un scanner Python non destructif pour les tests bug bounty sur des cibles autorisees. Il realise un crawl limite au meme origin et signale notamment :

- en-tetes de securite manquants ou permissifs,
- cookies sans `Secure`, `HttpOnly` ou `SameSite`,
- formulaires POST sans jeton CSRF visible,
- formulaires de mot de passe servis sans HTTPS,
- CORS permissif,
- methodes HTTP sensibles annoncees,
- chemins exposes courants comme `/.git/HEAD`, `.env`, `robots.txt`,
- informations de fingerprinting et controles TLS de base.

Exemple :

```bash
python3 scanners/websentinel.py https://example.com --i-am-authorized --max-pages 20 --format json --output rapport.json
```

Le flag `--i-am-authorized` est volontairement obligatoire afin de rappeler que l'outil doit etre utilise uniquement sur vos propres labs, vos applications ou des programmes bug bounty qui vous autorisent explicitement.
