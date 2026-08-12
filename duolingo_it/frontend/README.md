# Frontend CodeLingo (Flutter)

Application Flutter multi-plateforme : **Android, iOS, Windows, macOS, Linux, Web**.

Ce dossier ne contient que le code applicatif portable (`lib/`, `pubspec.yaml`,
`analysis_options.yaml`, `test/`). Les projets natifs (`android/`, `ios/`,
`windows/`, etc.) sont générés par le SDK Flutter.

## Prérequis

- Flutter SDK ≥ 3.19 ([installation](https://docs.flutter.dev/get-started/install)).
- Pour un build Windows : Visual Studio 2022 avec le composant *Développement Desktop en C++*.
- Pour Android : Android Studio + un émulateur / appareil.
- Pour iOS : Xcode 15+.

## Premier lancement

```bash
cd duolingo_it/frontend
flutter create .       # crée android/ ios/ windows/ macos/ linux/ web/ SANS toucher à lib/ ni pubspec.yaml
flutter pub get
```

## Lancer l'application

Le backend doit tourner (`python manage.py runserver`, par défaut sur
`http://127.0.0.1:8000`).

```bash
# Android émulateur → 10.0.2.2 est utilisé automatiquement
flutter run

# Windows desktop
flutter run -d windows --dart-define=API_BASE_URL=http://127.0.0.1:8000

# Web (Chrome)
flutter run -d chrome --dart-define=API_BASE_URL=http://127.0.0.1:8000
```

Compte de test après `python manage.py seed_content` : crée-en un depuis l'écran
d'inscription, ou utilise le superuser Django.

## Architecture

- `lib/main.dart` — bootstrap `MultiProvider` (ApiClient + AuthState) + thème.
- `lib/api/` — client HTTP (`ApiClient`) et endpoints (`AuthApi`, `CoursesApi`).
- `lib/models/` — DTOs (`AppUser`, `Course`, `Module`, `LessonSummary`,
  `LessonDetail`, `Exercise`, `Choice`, `SubmissionResult`).
- `lib/state/auth_state.dart` — `ChangeNotifier` gérant l'auth JWT persistée
  via `SharedPreferences`.
- `lib/screens/` — Splash, Login, Register, Home (Cours / Classement / Profil),
  CourseDetail, Lesson, LessonResult.
- `lib/widgets/` — `StatsBar` (XP / streak / cœurs), `ExerciseCard` (rendu
  adaptatif selon `ExerciseKind`).
- `lib/theme/app_theme.dart` — palette et typographie inspirées de Duolingo
  (Nunito via `google_fonts`, vert `#58CC02`).

## Build de production

```bash
flutter build apk   --dart-define=API_BASE_URL=https://api.exemple.com
flutter build ipa   --dart-define=API_BASE_URL=https://api.exemple.com
flutter build windows --dart-define=API_BASE_URL=https://api.exemple.com
flutter build web   --dart-define=API_BASE_URL=https://api.exemple.com
```
