# Backend ITLingo

API Django REST pour une application d'apprentissage informatique inspiree de Duolingo.

## Installation

```bash
cd backend
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py seed_learning
python manage.py runserver 127.0.0.1:8000
```

## Endpoints principaux

- `GET /api/health/` : verification de disponibilite.
- `GET /api/tracks/` : parcours avec unites et lecons.
- `GET /api/lessons/<id>/` : detail d'une lecon et ses defis.
- `POST /api/challenges/<id>/submit/` : soumission d'une reponse.
- `GET /api/me/progress/` : progression d'un utilisateur authentifie.

## Tests

```bash
cd backend
python manage.py test
```
