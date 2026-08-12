# DevLingo

MVP d'une application d'apprentissage de l'informatique inspiree de Duolingo, ciblee pour mobile et desktop avec `Flutter` en frontend et `Django REST` en backend.

## Vision produit

- parcours courts et progressifs autour de `Python`, `Git` et `Linux`
- gamification avec streak, XP, coeurs et objectif quotidien
- interface responsive exploitable sur mobile, web, Linux desktop et extensible vers Windows

## Structure

- `backend/` : API Django REST, modele de contenu et donnees de demo
- `frontend/` : application Flutter multiplateforme

## Lancer le backend

```bash
cd backend
python3 -m venv ../.venv
. ../.venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```

API disponible sur `http://127.0.0.1:8000/api/`.

## Lancer le frontend

Avec un SDK Flutter dans le `PATH` :

```bash
cd frontend
flutter pub get
flutter run -d web-server --web-port 3000 --dart-define=API_BASE_URL=http://127.0.0.1:8000/api
```

## Endpoints MVP

- `GET /api/health/`
- `GET /api/dashboard/`
- `GET /api/lessons/<slug>/`

## Prochaines evolutions utiles

1. authentification et profils reels
2. moteur de correction plus riche pour code et terminal
3. synchronisation offline-first
4. notifications de streak et classement
