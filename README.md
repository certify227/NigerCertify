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

## 🆕 Outil agent commercial

Le dépôt inclut maintenant `sales_contact_agent.py`, un script CLI qui prend une URL, explore la page de départ puis quelques liens internes pertinents (`contact`, `about`, `support`, etc.) et retourne en JSON les emails et numéros de téléphone détectés.

### Utilisation

```bash
python3 sales_contact_agent.py https://exemple.com --max-pages 6
```

### Exemple de sortie

```json
{
  "input_url": "https://exemple.com",
  "normalized_url": "https://exemple.com",
  "visited_pages": ["https://exemple.com", "https://exemple.com/contact"],
  "emails": [{"value": "contact@exemple.com", "sources": ["https://exemple.com/contact"]}],
  "phones": [{"value": "+33123456789", "sources": ["https://exemple.com/contact"]}],
  "errors": []
}
```

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
