# Creator Pack — plugin Photoshop 2025

Plugin **UXP** (pas CEP) pour Photoshop 26+. Trois modules dans un panneau :

1. **Social Canvas** — décline le visuel master en artboards (IG 4:5 / Story / TikTok / YouTube…)
2. **Type Rhythm** — injecte Hook / Preuve / CTA, auto-fit, scrim de contraste
3. **Storyboard Frames** — duplique le master en frames narratives (PAS, avant/après, Reels…)

Tout reste éditable. Les calques gérés portent le préfixe `CP_`.

## Installation (Photoshop 2025 / 2026)

### 1. Mode développeur

Photoshop → **Préférences → Modules externes** → activer **Mode développeur**  
(ou Creative Cloud → Préférences → Mode développeur).

Redémarrer Photoshop.

### 2. Charger le plugin (recommandé)

1. Installer [UXP Developer Tool](https://developer.adobe.com/console/en/servicesandapis) (Adobe UDT).
2. **Add Plugin** → sélectionner `photoshop-creator-pack/plugin/manifest.json`.
3. **Load** / **Watch**.
4. Dans Photoshop : **Plugins → Creator Pack**.

Le dossier à pointer est **`plugin/`**, celui qui contient `manifest.json`.

### 3. Copie locale (sans UDT)

Copier tout le dossier `plugin/` vers :

- macOS : `~/Library/Application Support/Adobe/UXP/Plugins/External/com.creatorpack.photoshop/`
- Windows : `%APPDATA%\Adobe\UXP\Plugins\External\com.creatorpack.photoshop\`

Le fichier `dist/CreatorPack-1.0.0.ccx` est un zip du même dossier. Tu peux le décompresser dans `Plugins/External/` ; l’installation Marketplace (signée) n’est pas requise en mode développeur.

### Versions

| App | `minVersion` |
|---|---|
| Photoshop 2025 | 26.0.0 |
| Photoshop 2026 | 27.x (compatible) |

UXP 7+, panneau **modeless** (pas de `showModal`) pour rester compatible avec les gardes batchPlay 2026.

## Usage express

1. Ouvre un visuel (RGB, idéalement 1080×1350 ou plus).
2. **Canvas** → *Définir CP_MASTER* → coche les formats → *Générer les artboards*.
3. Optionnel : *Détecter le sujet* (Select Subject → calque `CP_SUBJECT`).
4. **Type** → colle un brief (3 phrases) → *Découper* → *Appliquer la typo*.
5. **Story** → template PAS → *Générer les frames*.
6. *Exporter le pack* → dossier de PNG sRGB + `manifest.json`.

Cmd/Ctrl+Z annule chaque action plugin d’un coup (`suspendHistory`).

## Contrat de calques

```
CP_MASTER                 artboard source
  CP_BG                   fond (smart object de préférence)
  CP_SUBJECT              sujet détouré
  CP_TXT_HOOK             texte
  CP_TXT_PROOF            texte
  CP_TXT_CTA              texte
  CP_META / CP_SAFEZONE_* overlays, exclus de l’export
  CP_NOTE                 beat storyboard, exclus de l’export

CP_AB_ig_feed_45          déclinaisons Canvas
CP_AB_ig_story
CP_FR_01 … CP_FR_05       frames Story
```

Les calques sans préfixe `CP_` ne sont pas touchés.

## Développement

```bash
cd photoshop-creator-pack
npm test
node tests/visualize.js
npm run pack    # dist/CreatorPack-1.0.0.ccx
```

Pas de bundler : HTML / CSS / CommonJS, chargeables tels quels par UDT.

## Permissions

- `localFileSystem: fullAccess` — export PNG vers le dossier choisi (`nativePath` requis par Quick Export).
- `clipboard` — coller un brief.

Aucune requête réseau (pas de LLM dans cette version).
