# CodeLingo — apprendre l'informatique comme sur Duolingo

CodeLingo est un MVP d'application d'apprentissage de l'informatique inspirée
de Duolingo (leçons courtes, XP, série de jours, cœurs, classement) :

- **Backend** : Django 5 + Django REST Framework + SimpleJWT + drf-spectacular (`duolingo_it/backend`).
- **Frontend** : Flutter 3 multi-plateforme — Android, iOS, **Windows desktop**, macOS,
  Linux, Web (`duolingo_it/frontend`).

## Structure du dépôt

```
duolingo_it/
├── backend/                # API Django (REST + JWT)
│   ├── codelingo/          # projet Django (settings, urls, wsgi)
│   ├── accounts/           # User personnalisé (xp, streak, hearts) + register/me/leaderboard
│   ├── courses/            # Course > Module > Lesson > Exercise (+ management command seed_content)
│   ├── progress/           # Soumission d'exercices + LessonCompletion + ExerciseAttempt
│   └── requirements.txt
└── frontend/               # Application Flutter (lib/ uniquement, prête à `flutter create .`)
    ├── lib/
    │   ├── api/            # client HTTP + endpoints
    │   ├── models/         # DTOs
    │   ├── state/          # AuthState (Provider)
    │   ├── screens/        # écrans : Splash/Login/Register/Home/CourseDetail/Lesson/Result
    │   ├── widgets/        # StatsBar, ExerciseCard
    │   └── theme/          # thème inspiré de Duolingo
    └── pubspec.yaml
```

## Démarrage rapide

### 1) Backend

```bash
cd duolingo_it/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_content           # peuple ~5 cours, 10 leçons, 25 exercices
python manage.py createsuperuser        # optionnel, pour /admin/
python manage.py runserver 0.0.0.0:8000
```

Endpoints principaux :
- `POST /api/v1/auth/register/` — inscription (renvoie `access` + `refresh` + `user`)
- `POST /api/v1/auth/token/` — connexion (SimpleJWT)
- `POST /api/v1/auth/token/refresh/`
- `GET  /api/v1/me/` — profil courant
- `GET  /api/v1/courses/` — liste des cours
- `GET  /api/v1/courses/<slug>/` — détail (modules + leçons + progression)
- `GET  /api/v1/lessons/<id>/` — détail leçon + exercices (sans réponses correctes)
- `POST /api/v1/lessons/<id>/submit/` — soumet les réponses, met à jour XP/cœurs/série
- `GET  /api/v1/leaderboard/` — top 20 XP
- `GET  /api/docs/` — Swagger UI
- `GET  /api/schema/` — schéma OpenAPI

### 2) Frontend Flutter

Le dossier `frontend/` contient uniquement `lib/`, `pubspec.yaml`, `analysis_options.yaml`
et `test/`. Génère les cibles de plateformes une seule fois :

```bash
cd duolingo_it/frontend
flutter create .                       # crée android/ ios/ windows/ macos/ linux/ web/
flutter pub get
```

Puis lance l'app en pointant vers ton backend :

```bash
# Émulateur Android → 10.0.2.2 est déjà utilisé par défaut
flutter run

# iOS / desktop / web : préciser l'URL du backend
flutter run -d windows --dart-define=API_BASE_URL=http://127.0.0.1:8000
flutter run -d chrome  --dart-define=API_BASE_URL=http://127.0.0.1:8000
flutter run -d macos   --dart-define=API_BASE_URL=http://127.0.0.1:8000
```

Pour un build Windows en release :

```bash
flutter build windows --dart-define=API_BASE_URL=https://api.exemple.com
```

## Contenu pédagogique fourni

La commande `seed_content` crée 5 cours francophones :

1. 🐍 **Python : les bases** (variables, opérations, conditions, boucles)
2. 🐧 **Linux & terminal** (navigation, permissions)
3. 🌐 **Réseaux : bases TCP/IP** (OSI, IP)
4. 🔀 **Git & GitHub** (commandes essentielles)
5. 🛡️ **Cybersécurité : fondamentaux** (triangle CIA)

Chaque leçon contient plusieurs exercices de types :
- QCM (`mcq`)
- Vrai / Faux (`true_false`)
- Compléter (`fill_blank`)
- « Que renvoie ce code ? » (`code_output`)

## Gamification implémentée

- **XP** : la validation d'une leçon (0 ou 1 erreur) attribue `lesson.xp_reward`.
- **Série (streak)** : `+1` à chaque jour distinct où l'utilisateur valide une
  leçon, remise à 1 si la journée précédente est manquée.
- **Cœurs** : chaque mauvaise réponse fait perdre 1 cœur, jusqu'à 0.
- **Niveau** : dérivé du XP (`1 + xp // 100`).

## Roadmap

- Rafraîchissement automatique du token JWT côté client.
- Régénération périodique des cœurs.
- Exercices supplémentaires (drag-and-drop d'ordre, association).
- Notifications push (rappel de série).
- Éditeur de contenu dans l'admin Django amélioré.
- Système de ligues hebdomadaires.
