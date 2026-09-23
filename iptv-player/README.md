# Aureon

Aureon est un lecteur IPTV de bureau. L'application ne contient aucune liste de chaînes : l'utilisateur y connecte ensuite ses propres sources autorisées.

Cette première phase pose l'architecture, l'outillage et l'interface de navigation. Le parseur M3U, la lecture HLS, les favoris persistants, le guide XMLTV et SQLite arriveront dans les phases suivantes.

## Prérequis

- Node.js 22.14 ou plus récent
- npm 10

## Installation

```bash
cd iptv-player
npm install
```

Copier `.env.example` vers `.env` seulement si vous voulez changer le niveau de log ou le nom affiché. Ne placez aucun identifiant IPTV dans ce fichier.

## Lancement en développement

Application Electron :

```bash
npm run dev
```

Interface seule, dans le navigateur :

```bash
npm run dev:web
```

Puis ouvrir `http://127.0.0.1:5173`.

## Build de production

```bash
npm run build
```

Le résultat est écrit dans `out/`. Le fichier `electron-builder.yml` prépare l'installeur, qui sera produit lors de la phase de packaging.

## Configuration

| Variable               | Rôle                                                         |
| ---------------------- | ------------------------------------------------------------ |
| `VITE_LOG_LEVEL`       | Niveau de log du renderer : `debug`, `info`, `warn`, `error` |
| `VITE_APP_NAME`        | Nom affiché. Valeur d'exemple : `Aureon`                     |
| `AUREON_LOG_LEVEL`     | Niveau de log du processus Electron                          |
| `AUREON_OPEN_DEVTOOLS` | `1` pour ouvrir les outils de développement                  |

En développement, l'absence de niveau équivaut à `debug`.

## Architecture

```text
electron/          processus principal et preload isolé
shared/            journaux, redaction, validation d'URL, contrat IPC
src/               interface React
  components/      éléments visuels réutilisables
  pages/           écrans
  layouts/         coque de l'application
  features/        contrats métier, sans implémentation IPTV pour l'instant
  hooks/           raccourcis, thème, informations d'exécution
  services/        accès aux services du renderer
  stores/          état d'interface Zustand
  database/        contrat des tables SQLite
  types/           modèles partagés
src/               reste le renderer, pour garder la structure demandée
```

Le bureau utilise Electron 44 avec `contextIsolation`, `sandbox` et `nodeIntegration` désactivé. Le preload expose un pont typé. Les opérations privilégiées passeront par ce pont, pas par un serveur HTTP local : un port ouvert sur la machine élargirait la surface d'attaque. Les modules de `src/features` restent indépendants d'Electron, afin d'ajouter plus tard un adaptateur web, Android ou TV sans réécrire le métier.

Vite 7 est utilisé parce qu'electron-vite 5 ne prend pas encore en charge Vite 8. TypeScript 5.9 est utilisé parce que typescript-eslint ne couvre pas encore TypeScript 7.

SQLite et Video.js ne sont pas installés dans cette phase. Le schéma et le contrat du moteur de lecture sont déjà définis pour les phases dédiées.

## Tests

```bash
npm test
npm run lint
npm run typecheck
```

Les tests de bout en bout avec Playwright sont prévus lorsque les parcours playlist et favoris existeront.

## Dépannage

- Fenêtre blanche : relancer `npm run dev` et vérifier que `out/` n'est pas un build interrompu.
- Le menu ne se réduit pas : utiliser Ctrl+B, ou ⌘B sur macOS.
- Erreur de version Node : installer Node.js 22.14 ou plus récent.
- Les journaux ne doivent jamais contenir de mot de passe. Le helper `shared/redact.ts` masque les clés sensibles et les identifiants présents dans une URL.
