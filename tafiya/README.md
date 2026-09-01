# Tafiya — Marketplace de transport au Niger

**Tafiya** (*voyage* en haoussa) est un MVP type BlaBlaCar adapté au marché nigérien :

- covoiturage, taxi brousse, bus ;
- prix en **F CFA (XOF)** ;
- paiement **Orange Money / Airtel Money / Moov Money / cash** (mock branchable) ;
- PWA mobile-first en français ;
- villes du Niger préchargées (Niamey, Maradi, Zinder, Agadez…).

## Architecture rapide

```
tafiya/
├── backend/          # FastAPI + SQLAlchemy
├── frontend/         # React + Vite (PWA)
├── docs/             # Vision, architecture, roadmap Niger
└── docker-compose.yml
```

Voir :

- [`docs/VISION.md`](docs/VISION.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/ROADMAP_NIGER.md`](docs/ROADMAP_NIGER.md)

## Démarrage local (sans Docker)

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

API : http://127.0.0.1:8000/docs

### Frontend

```bash
cd frontend
npm install
npm run dev
```

App : http://127.0.0.1:5173

## Docker Compose

```bash
cd tafiya
docker compose up --build
```

- Web : http://127.0.0.1:8080  
- API : http://127.0.0.1:8000/docs  

## Comptes démo

| Rôle | Téléphone | Mot de passe |
|---|---|---|
| Conducteur | `90000001` ou `+22790000001` | `tafiya123` |
| Voyageuse | `90000002` | `tafiya123` |
| Taxi brousse | `90000003` | `tafiya123` |

## Parcours MVP couverts

1. Rechercher Niamey → Maradi  
2. Voir un trajet + prix XOF  
3. Se connecter / s’inscrire avec téléphone  
4. Réserver + confirmer Mobile Money (simulé)  
5. Publier un trajet  
6. Voir ses réservations / trajets  

## Tests

```bash
cd backend
source .venv/bin/activate
pytest -q
```

## Prochaines intégrations réelles

1. Agrégateur Mobile Money (Hub2, CinetPay, PayDunya…)  
2. OTP SMS  
3. WhatsApp click-to-chat conducteur  
4. Admin modération  
5. USSD / SMS pour zones bas débit  

---

Fait pour un déploiement réaliste au Niger : Android-first, XOF, opérateurs locaux, ops simple.
