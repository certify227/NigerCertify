# Backend CodeLingo

API Django 5 + DRF + SimpleJWT + drf-spectacular.

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_content
python manage.py runserver 0.0.0.0:8000
```

## Applications

- `accounts/` — modèle `User` personnalisé (xp, hearts, streak, level) et endpoints
  `POST /api/v1/auth/register/`, `GET /api/v1/me/`, `GET /api/v1/leaderboard/`.
- `courses/` — `Course > Module > Lesson > Exercise > Choice`. Endpoints publics
  pour la liste et le détail des cours. Management command `seed_content` pour
  peupler la base.
- `progress/` — `LessonCompletion`, `ExerciseAttempt` et endpoint
  `POST /api/v1/lessons/<id>/submit/` qui corrige les réponses, met à jour XP,
  cœurs et série.

## Variables d'environnement

| Variable | Défaut | Description |
| --- | --- | --- |
| `DJANGO_SECRET_KEY` | valeur dev | À définir en production. |
| `DJANGO_DEBUG` | `1` | Mettre à `0` en production. |
| `DJANGO_ALLOWED_HOSTS` | `*` | Liste séparée par des virgules. |

## Documentation d'API

- Swagger UI : http://localhost:8000/api/docs/
- Schéma OpenAPI JSON/YAML : http://localhost:8000/api/schema/

## Authentification

L'API utilise **JWT** (SimpleJWT). Ajoute l'en-tête suivant sur les endpoints
protégés :

```
Authorization: Bearer <access_token>
```

Les tokens sont obtenus via `POST /api/v1/auth/token/` ou renvoyés
directement lors de l'inscription.
