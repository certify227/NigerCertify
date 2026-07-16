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

### 🔹 Web Bug Bounty Scanner

`scanners/web_bugbounty_scanner.py` est un scanner web non destructif pour les programmes bug bounty et les labs autorises.

- crawl limite au domaine de scope ;
- detection des en-tetes de securite manquants ;
- analyse des cookies, formulaires, liens, ressources et chemins publics ;
- sondes actives optionnelles pour expositions evidentes et reflection avec canari inerte ;
- rapports JSON ou Markdown.

Exemple :

```bash
python3 scanners/web_bugbounty_scanner.py https://example.com \
  --i-have-authorization \
  --active-probes \
  --max-pages 25 \
  --format markdown \
  --output rapport_bug_bounty.md
```

> Utilisez cet outil uniquement sur des cibles que vous possedez ou qui sont explicitement incluses dans un programme bug bounty.
