# ITLingo Flutter

Client Flutter pour mobile et desktop Windows.

## Preparation des plateformes

Le SDK Flutter n'est pas versionne dans ce depot. Une fois Flutter installe :

```bash
cd app
flutter create . --platforms=android,ios,windows
flutter pub get
```

## Lancement

Backend local sur Windows desktop :

```bash
flutter run -d windows --dart-define=API_BASE_URL=http://127.0.0.1:8000/api
```

Emulateur Android, quand le backend tourne sur la machine hote :

```bash
flutter run -d android --dart-define=API_BASE_URL=http://10.0.2.2:8000/api
```

iOS simulator :

```bash
flutter run -d ios --dart-define=API_BASE_URL=http://127.0.0.1:8000/api
```

## Tests

```bash
flutter test
```
