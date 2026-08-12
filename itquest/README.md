# IT Quest

IT Quest est un MVP d'application d'apprentissage informatique inspiree de Duolingo.
Le backend Django expose les parcours, les lecons, les questions et le progres.
Le client Flutter cible mobile et desktop Windows avec le meme code applicatif.

## Structure

```text
itquest/
  backend/   API Django REST + SQLite pour le developpement
  mobile/    Application Flutter multiplateforme
```

## Backend Django

```bash
cd itquest/backend
python3 -m pip install -r requirements.txt
python3 manage.py migrate
python3 manage.py seed_itquest
python3 manage.py runserver 0.0.0.0:8000
```

Endpoints principaux :

- `GET /api/health/`
- `GET /api/tracks/`
- `GET /api/lessons/<id>/`
- `POST /api/lessons/<id>/submit/`
- `GET /api/progress/<username>/`

Exemple de soumission :

```json
{
  "username": "amina",
  "answers": [
    { "question_id": 1, "option_id": 2 }
  ]
}
```

## Application Flutter

L'environnement cloud courant ne contient pas Flutter. Sur une machine de
developpement avec Flutter installe :

```bash
cd itquest/mobile
flutter create . --platforms=android,ios,windows
flutter pub get
flutter run -d windows --dart-define=API_BASE_URL=http://127.0.0.1:8000/api
```

Pour Android Emulator, utilisez souvent :

```bash
flutter run -d emulator --dart-define=API_BASE_URL=http://10.0.2.2:8000/api
```

## Pistes produit apres le MVP

- comptes utilisateurs Django avec JWT,
- streak quotidien et ligues,
- boutique de coeurs/XP,
- parcours avances : Python, Linux, reseaux, cloud, cyber defense,
- mode enseignant avec groupes et suivi de classe.
