# WiFiZone Pro — App mobile (Expo)

Client React Native minimal pour l'API REST JWT.

## Prérequis

- Node.js 18+
- Expo CLI (`npx expo`)

## Configuration

```bash
cd wifizone/mobile
npm install
export EXPO_PUBLIC_API_URL=http://VOTRE_SERVEUR:8080/api/v1
npx expo start
```

## Fonctionnalités

- Connexion JWT (`/api/v1/auth/token/`)
- Dashboard live (`/api/v1/dashboard/live/`)
- Stockage token local (AsyncStorage)

Pas de paiement en ligne — gestion opérateur uniquement.
