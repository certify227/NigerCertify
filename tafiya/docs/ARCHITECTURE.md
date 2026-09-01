# Architecture technique — Tafiya

## Principes

1. **Mobile-first / bas débit** : pages légères, API JSON compacte, PWA installable.
2. **Franc CFA & Mobile Money** : abstractions de paiement plugables (Orange / Airtel / Moov).
3. **Simplicité ops** : un `docker compose up` pour démarrer en local ou VPS.
4. **Évolutif** : domain model prêt pour bus / multi-opérateur sans réécrire le cœur.

## Stack MVP

```
┌─────────────┐     HTTPS/JSON      ┌──────────────┐
│  PWA React  │ ──────────────────► │  FastAPI     │
│  (Vite)     │                     │  (Kairos-like│
└─────────────┘                     │   API layer) │
                                    └──────┬───────┘
                                           │
                          ┌────────────────┼────────────────┐
                          ▼                ▼                ▼
                     PostgreSQL        Redis (opt)     Mobile Money
                     (trajets,         (cache,         adapters
                      users,            OTP)            (mock → réel)
                      bookings)
```

| Couche | Choix | Pourquoi |
|---|---|---|
| Frontend | React + Vite + TypeScript | PWA rapide, écosystème riche |
| Backend | FastAPI + SQLAlchemy | Python répandu, OpenAPI auto |
| DB | PostgreSQL (SQLite en dev) | Fiable, simple à héberger |
| Auth | JWT + téléphone | Réaliste au Niger |
| Paiement | Interface `PaymentProvider` | Brancher Orange/Airtel sans refactor |
| Déploiement | Docker Compose | VPS Niamey / cloud AF |

## Domaines métier

- `User` — voyageur / conducteur / admin
- `City` — référentiel géographique Niger
- `Ride` — offre de trajet
- `Booking` — réservation d’une ou plusieurs places
- `Payment` — intention + statut Mobile Money
- `Rating` — note post-trajet

## APIs principales

| Méthode | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Inscription téléphone |
| POST | `/api/auth/login` | Connexion JWT |
| GET | `/api/cities` | Liste des villes |
| GET | `/api/rides` | Recherche (from, to, date) |
| POST | `/api/rides` | Publier un trajet |
| POST | `/api/rides/{id}/book` | Réserver |
| POST | `/api/payments/{id}/confirm` | Confirmer Mobile Money (mock) |
| GET | `/api/me/bookings` | Mes réservations |
| GET | `/api/me/rides` | Mes trajets publiés |

## Sécurité (MVP)

- Mots de passe hashés (bcrypt)
- JWT court (accès) 
- Validation stricte des entrées (Pydantic)
- CORS restreint
- Pas de secrets en clair dans le repo (`.env.example`)
- Rate limiting simple (phase 2)
- KYC progressif (phase 2)

## Hébergement recommandé (Niger / AF)

1. **Dev** : Docker local  
2. **Prod légère** : VPS (Contabo, Hetzner, ou opérateur local) + Nginx + Let's Encrypt  
3. **Prod scale** : Managed Postgres + object storage + CDN  

## Observabilité

- Logs structurés JSON
- Healthcheck `/api/health`
- Métriques Prometheus (phase 2)
