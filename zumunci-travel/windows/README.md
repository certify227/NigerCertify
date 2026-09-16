# ZumunciTravel — instance Windows

Guide pour lancer l’app **en local sur Windows** (sans Docker).

## Prérequis

1. **Python 3.10+** — [python.org/downloads](https://www.python.org/downloads/)  
   Cochez **Add python.exe to PATH**.
2. **Node.js LTS** — [nodejs.org](https://nodejs.org/)

Vérification dans `cmd` :

```bat
py -3 --version
node -v
npm -v
```

## Démarrage en 2 clics

| Fichier | Rôle |
|---|---|
| `..\INSTALLER.bat` (via `windows\INSTALLER.bat`) | Première installation (venv + npm) |
| `..\DEMARRER.bat` | Démarre API + frontend + ouvre le navigateur |
| `..\ARRETER.bat` | Arrête les services (ports 8000 / 5173) |

### Première fois

1. Ouvrez le dossier `zumunci-travel`
2. Double-cliquez `windows\INSTALLER.bat` (ou laissez `DEMARRER.bat` l’appeler)
3. Double-cliquez `DEMARRER.bat`

### Ensuite

Double-cliquez uniquement **`DEMARRER.bat`**.

## URLs

- Application : http://127.0.0.1:5173  
- API docs : http://127.0.0.1:8000/docs  
- Santé API : http://127.0.0.1:8000/api/health  

## Comptes démo

| Rôle | Téléphone | Mot de passe |
|---|---|---|
| Voyageuse vérifiée | `90000002` | `zumunci123` |
| Conducteur | `90000001` | `zumunci123` |
| Admin KYC | `90000099` | `zumunci123` |

## Architecture des fenêtres

`DEMARRER.bat` ouvre **2 fenêtres** :

1. `ZumunciTravel-API` — uvicorn FastAPI  
2. `ZumunciTravel-WEB` — Vite React  

Ne fermez pas ces fenêtres tant que vous utilisez l’app.  
Pour tout stopper : `ARRETER.bat`.

## Dépannage

| Problème | Solution |
|---|---|
| `Python introuvable` | Réinstallez Python avec PATH, rouvrez `cmd` |
| `Node introuvable` | Installez Node LTS, rouvrez `cmd` |
| Port 8000 / 5173 déjà pris | Lancez `ARRETER.bat` puis `DEMARRER.bat` |
| Page blanche / API error | Vérifiez la fenêtre API ; attendez le message `Uvicorn running` |
| Pare-feu Windows | Autorisez Python / Node pour le réseau privé local |

## Fichiers générés localement (ignorés / locaux)

- `backend\.venv\`
- `backend\.env` (copié depuis `env.backend.example`)
- `backend\zumunci.db`
- `frontend\node_modules\`
- `frontend\.env.development` (`VITE_API_URL=/api`)
