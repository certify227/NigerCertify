# CodeQuest

Application d'apprentissage de l'informatique inspirée de Duolingo.

- **Frontend** : Flutter (Windows, Android, iOS)
- **Backend** : Django + Django REST Framework + JWT
- **Base de données** : SQLite (dev) ou PostgreSQL (production/Docker)

## Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| Parcours thématiques | Python, Réseaux, Cybersécurité, Web, Linux, SQL, Git |
| Contenu | **10 parcours**, **53 leçons**, **243 exercices** (pédagogie enrichie : indices, analogies) |
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
python manage.py seed_full_content        # première fois
python manage.py seed_full_content --force  # recharger tout le contenu
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
# Charger tout le contenu (10 parcours, progression du débutant à l'avancé)
python manage.py seed_full_content --force

# Exporter le contenu pédagogique
python manage.py export_content --output content_export.json
```

## Parcours disponibles

| Parcours | Unités | Thèmes |
|----------|--------|--------|
| 🐍 Python Fondamentaux | 3 | Variables, boucles, listes — **39 exercices avec indices** |
| 🌐 Réseaux & TCP/IP | 2 | IPv4/IPv6, TCP/UDP, OSI — explications pas à pas |
| 🔒 Cybersécurité | 2 | OWASP, XSS, CSRF, crypto — analogies et bonnes pratiques |
| 🌍 Développement Web | 2 | HTML, CSS, JS, DOM — structure → style → interactivité |
| 🐧 Linux & Systèmes | 2 | Terminal, fichiers, permissions rwx |
| 🗄️ Bases de données SQL | 1 | SELECT, JOIN, relations |
| 📦 Git & Collaboration | 1 | init, commit, branches, merge |
| 🧠 Algorithmique & Logique | 3 | Algorithmes, recherche, tri, récursion |
| 🐳 Docker & Conteneurs | 3 | Images, run, Dockerfile, Compose |
| 📡 Réseaux Avancés | 4 | Routage, VLAN, VPN, diagnostic |

## Aspects implémentés

1. **Sandbox Python** — exécution sécurisée avec timeout et blocage des imports dangereux
2. **Mode hors ligne** — cache JSON local + synchronisation à la reconnexion
3. **Notifications** — rappels quotidiens configurables dans le profil
4. **Admin enrichi** — dashboard stats, filtres, recherche, export JSON
5. **Docker + PostgreSQL** — production-ready avec entrypoint automatique
