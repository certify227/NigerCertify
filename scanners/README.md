# Scanners — Agent commercial

## Objectif

Outil de prospection B2B : vous donnez l’**URL** d’un site, l’agent récupère les
**emails** et **numéros de téléphone** (et un dossier prospect enrichi).

## Fichiers

| Fichier | Rôle |
|---------|------|
| `commercial_agent.py` | Agent CLI (crawl + extraction + score) |
| `agent_commercial_web.py` | Interface web (même moteur) |
| `offers.example.json` | Modèle d’offres pour le matching |
| `fixtures/demo_prospect.html` | Page de démo pour tests locaux |

## Utilisation rapide

```bash
# Contacts uniquement
python3 scanners/commercial_agent.py https://exemple.fr --contacts-only

# Interface web
python3 scanners/agent_commercial_web.py --host 0.0.0.0 --port 8765
```

Ouvrir ensuite `http://127.0.0.1:8765`, coller une URL, lancer l’analyse.

## Ce que l’agent détecte

- Liens `mailto:` / `tel:`
- Emails en clair et **obfusqués** (`contact [at] domaine [dot] fr`)
- Attributs `data-email` / `data-mail`
- Données JSON-LD (Organization)
- Pages contact / à propos / équipe liées depuis l’accueil
