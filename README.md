# web-bounty-audit

`web-bounty-audit` est un outil CLI d'audit **hors ligne** pour applications web.
Il analyse des captures HAR exportees depuis le navigateur ou un proxy afin de
mettre en evidence des problemes frequents de securite sans lancer de scan
actif contre une cible.

## Capacites

- Analyse des en-tetes de securite HTTP
- Verification des cookies (`Secure`, `HttpOnly`, `SameSite`)
- Detection des erreurs CORS courantes
- Extraction d'endpoints depuis HTML, JavaScript, `robots.txt` et XML
- Detection des mots de passe servis en HTTP et des source maps exposees
- Export des rapports en JSON et Markdown

## Installation

```bash
python3 -m pip install -e .
```

## Utilisation

```bash
web-bounty-audit tests/fixtures/sample.har --json report.json --markdown report.md
```

Ou sans installation:

```bash
PYTHONPATH=src python3 -m web_bounty_audit.cli tests/fixtures/sample.har
```

## Exemple de sortie

```text
Scanned inputs: 1
Requests analyzed: 3
Issues found: 13
Unique endpoints: 6
Risk score: 44
Top issues:
  [high] Wildcard CORS with credentials enabled
  [medium] Missing Content-Security-Policy header
  [medium] Session cookie missing Secure flag
```

## Usage responsable

Cet outil est concu pour l'audit defensif de ressources dont vous avez
l'autorisation d'analyser. Il travaille a partir de captures existantes afin de
rester compatible avec des revues de securite responsables.
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
