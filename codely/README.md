# CodeQuest

Application d'apprentissage de l'informatique inspirée de Duolingo.

- **Frontend** : Flutter (Windows, Android, iOS)
- **Backend** : Django + Django REST Framework + JWT

## Fonctionnalités

- Parcours thématiques (Python, Réseaux, Cybersécurité…)
- Leçons interactives avec exercices (QCM, vrai/faux, texte à trous)
- Gamification : XP, niveaux, cœurs, séries quotidiennes
- Classement des apprenants
- Compte démo préchargé

## Structure du projet

```
codely/
├── backend/          # API Django
│   ├── accounts/     # Utilisateurs & auth JWT
│   ├── courses/      # Parcours, leçons, exercices
│   └── progress/     # Progression & gamification
└── frontend/         # App Flutter multiplateforme
```

## Démarrage rapide

### Backend

```bash
cd codely/backend
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_demo_data
python manage.py runserver
```

L'API est disponible sur `http://127.0.0.1:8000/api/`.

**Compte démo** : `demo` / `demo1234`

### Frontend

```bash
cd codely/frontend
flutter pub get
flutter run -d windows    # Windows desktop
flutter run -d android    # Android
flutter run -d ios        # iOS (macOS requis)
```

Pour pointer vers un autre serveur :

```bash
flutter run --dart-define=API_URL=http://192.168.1.10:8000/api
```

## Endpoints API principaux

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/auth/token/` | Connexion (JWT) |
| POST | `/api/accounts/register/` | Inscription |
| GET | `/api/courses/tracks/` | Liste des parcours |
| GET | `/api/courses/tracks/{slug}/` | Détail d'un parcours |
| GET | `/api/courses/lessons/{id}/` | Leçon avec exercices |
| POST | `/api/courses/exercises/{id}/submit/` | Soumettre une réponse |
| GET | `/api/progress/dashboard/` | Tableau de bord utilisateur |
| GET | `/api/accounts/leaderboard/` | Classement |

## Prochaines étapes suggérées

- Exercices de code interactifs (sandbox Python)
- Notifications push pour les rappels de série
- Mode hors-ligne avec cache local
- Panel admin enrichi pour créer du contenu
- Déploiement (Docker, PostgreSQL, CI/CD)
