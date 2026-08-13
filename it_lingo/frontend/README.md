# Frontend Flutter ItLingo

Ce dossier contient un squelette Flutter concu pour:

- mobile portrait,
- desktop Windows,
- consommation de l'API Django exposee par `../backend`.

## Ecran actuellement fourni

- `DashboardScreen`: tableau de bord principal.

## Choix UX

- `NavigationBar` sur petits ecrans,
- `NavigationRail` sur desktop,
- cartes de progression inspirant une experience de micro-apprentissage,
- fallback local pour permettre la demo UI meme si l'API n'est pas joignable.

## API attendue

Le frontend consomme `http://192.168.137.135:8000/api/v1/dashboard/`.

## Commandes utiles

```bash
flutter pub get
flutter analyze
flutter run -d windows
```
