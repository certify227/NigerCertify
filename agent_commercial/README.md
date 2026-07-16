# Agent commercial — Extracteur de contacts

Outil en ligne de commande qui, à partir d'une (ou plusieurs) **URL(s)**,
récupère automatiquement les **adresses email** et **numéros de téléphone**
publiquement affichés sur un site (utile pour la prospection commerciale).

## Fonctionnalités

- Extraction des emails depuis le texte, les liens `mailto:` et le HTML.
- Extraction des téléphones depuis le texte et les liens `tel:` (normalisation + filtrage des faux positifs).
- Mode `--crawl` : explore aussi les pages internes utiles (`contact`, `mentions légales`, `à propos`…).
- Traitement en masse via une liste d'URLs (`--input urls.txt`).
- Export **JSON** et **CSV** pour intégrer les leads à un CRM.
- Respect de `robots.txt` par défaut et délai configurable entre requêtes.

## Installation

```bash
pip install -r requirements.txt
```

## Utilisation

```bash
# URL unique
python3 contact_scraper.py https://exemple.com

# Plusieurs URLs + exploration des pages contact
python3 contact_scraper.py https://a.com https://b.com --crawl

# Depuis un fichier + export CSV et JSON
python3 contact_scraper.py --input urls.txt --crawl --csv leads.csv --json leads.json
```

### Options principales

| Option | Description |
|--------|-------------|
| `urls` | Une ou plusieurs URLs à analyser |
| `-i, --input` | Fichier texte (une URL par ligne) |
| `--crawl` | Explore les pages internes (contact, mentions…) |
| `--max-pages` | Nombre max de pages par site en mode crawl (défaut 6) |
| `--delai` | Délai en secondes entre 2 requêtes (défaut 1.0) |
| `--timeout` | Timeout HTTP en secondes (défaut 15) |
| `--json` / `--csv` | Fichiers d'export |
| `--ignore-robots` | Ne pas vérifier `robots.txt` (à utiliser avec prudence) |

## Avertissement légal

Cet outil ne collecte que des informations **publiquement accessibles**.
Utilisez-le uniquement à des fins légitimes de prospection et dans le respect
des CGU des sites, du fichier `robots.txt` et de la réglementation applicable
(RGPD pour les données personnelles en Europe).
