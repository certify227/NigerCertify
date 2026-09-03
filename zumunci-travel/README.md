# ZumunciTravel — Transport sécurisé au Niger

**ZumunciTravel** est une marketplace de covoiturage / taxi brousse / bus conçue pour le Niger, avec un principe central :

> **Aucune mise en relation sans vérification d’identité.**  
> **Aucun contact (téléphone) avant paiement confirmé.**  
> **Usage transport uniquement — pas de relations déplacées.**

## Contrôles anti-arnaque (décisions pilote)

| Contrôle | Comportement |
|---|---|
| Couverture | **8 régions** du Niger (Agadez → Diffa → … → Niamey) |
| Charte de sécurité | Obligatoire |
| KYC | `pending` → admin → `verified` (≤ 24 h) |
| Cash | **Interdit en covoiturage** |
| Contact | Masqué puis téléphone + WhatsApp après paiement |
| Commission | **10 %** plateforme |
| Priorité femmes | Option sur les trajets |
| Signalement | Arnaque / harcèlement / hors plateforme |

Voir [`docs/PRODUCT_DECISIONS.md`](docs/PRODUCT_DECISIONS.md) et [`docs/TRUST_AND_SAFETY.md`](docs/TRUST_AND_SAFETY.md).

## Structure

```
zumunci-travel/
├── backend/          # FastAPI + SQLAlchemy
├── frontend/         # React + Vite (PWA)
├── docs/
└── docker-compose.yml
```

## Démarrage local

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# autre terminal
cd frontend
npm install && npm run dev
```

- App : http://127.0.0.1:5173  
- API docs : http://127.0.0.1:8000/docs  

## Comptes démo

| Rôle | Téléphone | Mot de passe |
|---|---|---|
| Conducteur vérifié | `90000001` | `zumunci123` |
| Voyageuse vérifiée | `90000002` | `zumunci123` |
| Non vérifié (blocage) | `90000004` | `zumunci123` |
| Admin KYC | `90000099` | `zumunci123` |

## Tests

```bash
cd backend && source .venv/bin/activate && pytest -q
```
