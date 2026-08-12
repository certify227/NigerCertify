# CodeQuest 🦉

Une application d'apprentissage de l'informatique **inspirée de Duolingo**, pensée
pour le **desktop (Windows / Linux / macOS)** et le **mobile (Android / iOS)**.

- **Backend** : Django + Django REST Framework (API REST, authentification par token)
- **Frontend** : Flutter (une seule base de code pour desktop et mobile)

L'utilisateur progresse dans des **cours** d'informatique (Python, Réseaux, Linux,
Cybersécurité) découpés en **unités** puis en **leçons** composées d'**exercices**
(QCM, vrai/faux, texte à trous). Il gagne de l'**XP**, entretient une **série
(streak)** quotidienne, dispose de **vies (hearts)** et grimpe dans le **classement**.

```
codequest/
├── backend/     # API Django + DRF
└── frontend/    # Application Flutter (desktop + mobile)
```

## 1. Lancer le backend

Prérequis : Python 3.10+.

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate   # optionnel
pip install -r requirements.txt

python manage.py migrate
python manage.py seed_content          # charge le contenu pédagogique
python manage.py createsuperuser       # optionnel : accès à /admin
python manage.py runserver 0.0.0.0:8000
```

L'API est alors disponible sur `http://127.0.0.1:8000/api/`.

### Principaux endpoints

| Méthode | URL | Description | Auth |
|--------|-----|-------------|------|
| POST | `/api/auth/register/` | Créer un compte (renvoie un token) | non |
| POST | `/api/auth/login/` | Se connecter (renvoie un token) | non |
| GET | `/api/me/` | Profil (XP, série, vies, niveau) | token |
| GET | `/api/courses/` | Liste des cours | token |
| GET | `/api/courses/<slug>/` | Détail d'un cours (unités + leçons) | token |
| GET | `/api/lessons/<id>/` | Détail d'une leçon (exercices, sans réponses) | token |
| POST | `/api/lessons/<id>/submit/` | Corriger une leçon, mettre à jour XP/série | token |
| GET | `/api/leaderboard/` | Classement des joueurs | token |
| GET | `/api/health/` | Vérification de disponibilité | non |

L'authentification se fait via l'en-tête HTTP `Authorization: Token <token>`.

## 2. Lancer le frontend Flutter

Prérequis : Flutter 3.3+ (`flutter doctor`).

```bash
cd frontend
flutter pub get

# Desktop Windows
flutter run -d windows

# Desktop Linux
flutter run -d linux

# Mobile (émulateur/appareil connecté)
flutter run
```

### Configurer l'URL du backend

Par défaut l'app cible `http://127.0.0.1:8000` (et `http://10.0.2.2:8000` sur
l'émulateur Android). Pour pointer vers une autre machine :

```bash
flutter run --dart-define=API_BASE_URL=http://192.168.1.20:8000
```

## 3. Tests

```bash
# Backend
cd backend && python manage.py test

# Frontend
cd frontend && flutter analyze && flutter test
```

## Architecture

- **Modèles** (`backend/learning/models.py`) : `Course → Unit → Lesson → Exercise`,
  plus `Profile` (gamification) et `LessonProgress` (progression par leçon).
- **Correction côté serveur** : les réponses correctes ne sont jamais envoyées au
  client ; la note est calculée par l'API à la soumission.
- **Gamification** : XP attribué à la première réussite d'une leçon, série
  quotidienne mise à jour automatiquement, perte d'une vie en cas d'échec.
- **State management Flutter** : `provider` + persistance du token via
  `shared_preferences`.

## Contenu pédagogique

Le contenu de démonstration (commande `seed_content`) couvre : les bases de la
programmation en Python, les réseaux (TCP/IP, DNS, HTTP), Linux et la ligne de
commande, et les fondamentaux de la cybersécurité. Il est facilement extensible
en éditant `backend/learning/management/commands/seed_content.py` ou via l'admin
Django (`/admin`).
