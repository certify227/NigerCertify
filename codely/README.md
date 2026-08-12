# CodeQuest

Application d'apprentissage de l'informatique inspirée de Duolingo.

- **Frontend** : Flutter (Windows, Android, iOS)
- **Backend** : Django + Django REST Framework + JWT
- **Base de données** : SQLite (dev) ou PostgreSQL (production/Docker)

## Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| Parcours thématiques | Python, Réseaux, Cybersécurité |
| Exercices variés | QCM, vrai/faux, texte à trous, **défis code Python** |
| Sandbox Python | Exécution sécurisée côté serveur avec bouton « Exécuter » |
| Gamification | XP, niveaux, cœurs, séries, classement |
| Mode hors ligne | Cache local des parcours/leçons + file d'attente des réponses |
| Notifications | Rappels quotidiens pour maintenir la série |
| Admin enrichi | Tableau de bord, actions groupées, export JSON |
| Docker | Déploiement PostgreSQL + Gunicorn en un commande |

## Structure

```
codely/
├── backend/           # API Django
├── frontend/          # App Flutter
├── docker-compose.yml   # PostgreSQL + backend
└── .env.example
```

## Démarrage rapide (développement)

### Backend

```bash
cd codely/backend
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_demo_data
python manage.py seed_code_exercises
python manage.py runserver
```

**Compte démo** : `demo` / `demo1234`

### Frontend

```bash
cd codely/frontend
flutter pub get
flutter run -d windows    # Windows
flutter run -d android    # Android
```

## Déploiement Docker (PostgreSQL)

```bash
cd codely
docker compose up --build
```

- API : http://localhost:8000/api/
- Admin : http://localhost:8000/admin/ (admin / admin1234)
- Tableau de bord admin : http://localhost:8000/admin/dashboard/

## API principale

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/auth/token/` | Connexion JWT |
| POST | `/api/courses/sandbox/run/` | Exécuter du code Python (essai) |
| POST | `/api/courses/exercises/{id}/submit/` | Soumettre une réponse |
| PATCH | `/api/accounts/reminders/` | Configurer les rappels |
| GET | `/api/progress/dashboard/` | Tableau de bord |

## Commandes utiles

```bash
# Ajouter les exercices de code
python manage.py seed_code_exercises

# Exporter le contenu pédagogique
python manage.py export_content --output content_export.json
```

## Aspects implémentés

1. **Sandbox Python** — exécution sécurisée avec timeout et blocage des imports dangereux
2. **Mode hors ligne** — cache JSON local + synchronisation à la reconnexion
3. **Notifications** — rappels quotidiens configurables dans le profil
4. **Admin enrichi** — dashboard stats, filtres, recherche, export JSON
5. **Docker + PostgreSQL** — production-ready avec entrypoint automatique
