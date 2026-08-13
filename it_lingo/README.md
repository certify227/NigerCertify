# ItLingo

ItLingo est un MVP d'application d'apprentissage de l'informatique inspiree des mecaniques de Duolingo:

- micro-lecons rapides,
- progression par parcours,
- challenge du jour,
- UX mobile-first avec adaptation desktop,
- backend API separant contenu, progression et gamification.

## Cible produit

- `Mobile`: Android/iOS via Flutter.
- `Desktop`: Windows en priorite, avec le meme codebase Flutter.
- `Backend`: Django + Django REST Framework pour exposer les parcours, lessons et challenges.

## Fonctionnalites MVP deja posees

### Backend Django

- API `GET /api/v1/health/`
- API `GET /api/v1/dashboard/`
- API `GET /api/v1/tracks/`
- API `GET /api/v1/tracks/<slug>/`
- API `GET /api/v1/daily-challenge/`
- Modeles `Track`, `Module`, `Lesson`, `Challenge`
- commande `python manage.py seed_demo_data`

### Frontend Flutter

- tableau de bord responsive mobile/desktop,
- carte de challenge du jour,
- liste de parcours avec statistiques,
- mode de secours local si l'API Django n'est pas disponible.

## Structure

```text
it_lingo/
  backend/   # Django + DRF
  frontend/  # Flutter
```

## Lancer le backend

```bash
cd /workspace/it_lingo
. .venv/bin/activate
cd backend
python manage.py migrate
python manage.py seed_demo_data
python manage.py runserver 0.0.0.0:8000
```

Le client mobile pointe vers `http://192.168.137.135:8000/api/v1`.
Sur Windows, lance le backend en ecoute LAN pour que le telephone puisse joindre l'API.

## Lancer le frontend

Quand Flutter est installe localement:

```bash
cd /workspace/it_lingo/frontend
flutter pub get
flutter run -d windows
```

Pour mobile:

```bash
flutter run -d android
```

## Generer l'APK Android

```bash
cd /workspace/it_lingo/frontend
flutter build apk --release
```

L'APK est produit ici:

```text
frontend/build/app/outputs/flutter-apk/app-release.apk
```

Package: `com.itlingo.app`  
Label: `ItLingo`  
Version: `0.1.0`

Note: l'APK release est actuellement signe avec la cle debug Flutter (pratique pour tester). Pour une publication Play Store, il faudra une cle de signature de production.

## Prochaines etapes recommandees

1. Ajouter l'authentification et la progression utilisateur.
2. Enregistrer le score, la serie et les badges.
3. Integrer un mini-editeur de code avec execution securisee cote serveur.
4. Ajouter un moteur de revision espacee pour les notions ratees.
5. Brancher le catalogue a une interface admin pedagogique.
