# CodeLingo 🦉

Une application de type **Duolingo** pour apprendre l'informatique, disponible sur
**Windows (desktop)**, **Android**, **iOS** et **Web**.

- **Backend** : Django + Django REST Framework (API REST + authentification JWT)
- **Frontend** : Flutter (une seule base de code pour desktop et mobile)

L'apprentissage est organisé en parcours thématiques (Python, Développement Web,
Réseaux, Linux, Bases de données, Cybersécurité), découpés en unités, leçons et
exercices interactifs. L'app reprend les mécaniques de gamification de Duolingo :
XP, série (streak), gemmes, vies (hearts) et classement.

```
codelingo/
├── backend/    # API Django REST Framework
└── frontend/   # Application Flutter (Windows + mobile + web)
```

## 1. Backend (Django)

### Prérequis
- Python 3.10+

### Installation & lancement

```bash
cd backend
python3 -m venv venv
source venv/bin/activate            # Windows : venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py seed               # charge les cours / leçons / exercices
python manage.py createsuperuser    # (optionnel) accès à /admin
python manage.py runserver 0.0.0.0:8000
```

L'API est disponible sur `http://127.0.0.1:8000/`.

### Principaux endpoints

| Méthode | URL | Description |
|--------|-----|-------------|
| POST | `/api/auth/register/` | Création de compte |
| POST | `/api/auth/login/` | Connexion (renvoie les tokens JWT) |
| POST | `/api/auth/refresh/` | Rafraîchit le token d'accès |
| GET  | `/api/auth/me/` | Profil de l'utilisateur connecté |
| GET  | `/api/courses/` | Liste des parcours |
| GET  | `/api/courses/<slug>/` | Détail d'un parcours (unités + leçons) |
| GET  | `/api/lessons/<id>/` | Exercices d'une leçon |
| POST | `/api/lessons/<id>/complete/` | Valide une leçon, attribue XP / série |
| GET  | `/api/me/progress/` | Progression de l'utilisateur |
| GET  | `/api/leaderboard/` | Classement par XP |

### Tests

```bash
cd backend
source venv/bin/activate
python manage.py test
```

## 2. Frontend (Flutter)

### Prérequis
- Flutter 3.x (stable)

### Lancement

```bash
cd frontend
flutter pub get

# Windows desktop
flutter run -d windows

# Android (émulateur ou appareil branché)
flutter run -d android

# Web (pour un aperçu rapide)
flutter run -d chrome
```

### Configuration de l'URL de l'API

Par défaut l'app pointe vers :
- `http://10.0.2.2:8000` sur émulateur Android (accès à l'hôte),
- `http://127.0.0.1:8000` ailleurs.

Pour cibler un autre serveur :

```bash
flutter run --dart-define=API_BASE_URL=http://mon-serveur:8000
```

### Tests

```bash
cd frontend
flutter test
```

## Contenu pédagogique

Le contenu (parcours, unités, leçons, exercices) est défini dans
`backend/learning/management/commands/seed.py`. Modifie ce fichier puis relance
`python manage.py seed` (ou `--flush` pour repartir de zéro) pour l'enrichir.
