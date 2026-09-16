# Creator Pack 1.1 — plugin Photoshop 2025

Plugin **UXP** (pas CEP) pour Photoshop 26+. Trois modules dans un panneau :

1. **Social Canvas** — décline le visuel master en artboards (IG 4:5 / Story / TikTok / YouTube…)
2. **Type Rhythm** — injecte Hook / Preuve / CTA, auto-fit, scrim de contraste
3. **Storyboard Frames** — duplique le format source en frames narratives (PAS, avant/après, Reels…)

Tout reste éditable. Les calques gérés portent le préfixe `CP_`.

## Qu’est-ce qui a été corrigé en 1.1

- Pipeline Canvas : plus de scale/translate approximatif sur l’artboard. Chaque format est construit via **document dupliqué → recadrage master → resize → crop/letterbox → transfert**.
- Historique : `executeAsModal` + `hostControl.suspendHistory` (plus de `suspendHistory` imbriqué, source d’erreurs 2026).
- Typo : le texte des champs n’est plus raccourci en silence ; les chips restent des suggestions.
- Story : le **format source** (4:5 / 9:16) est vraiment utilisé ; la typo est appliquée **avant** duplication, puis les beats masquent Hook/Preuve/CTA.
- Export : `saveAs.png` par artboard en priorité (Quick Export seulement en secours) ; overlays `CP_NOTE` / safe zones exclus ; master optionnel.
- UI : Tout/Aucun, remplacer les artboards existants, pas d’alert bloquante, annulation d’export silencieuse.
- Fonts : plus de dépendance dure à Myriad Pro.

## Installation (Photoshop 2025 / 2026)

### 1. Mode développeur

Photoshop → **Préférences → Modules externes** → activer **Mode développeur**. Redémarrer Photoshop.

### 2. Charger le plugin (recommandé)

1. Installer [UXP Developer Tool](https://developer.adobe.com/console/en/servicesandapis).
2. **Add Plugin** → `photoshop-creator-pack/plugin/manifest.json`.
3. **Load**.
4. Photoshop → **Plugins → Creator Pack**.

Le dossier à pointer est **`plugin/`** (celui qui contient `manifest.json`).

### 3. Copie locale

- macOS : `~/Library/Application Support/Adobe/UXP/Plugins/External/com.creatorpack.photoshop/`
- Windows : `%APPDATA%\Adobe\UXP\Plugins\External\com.creatorpack.photoshop\`

Le fichier `dist/CreatorPack-1.1.0.ccx` est le zip du même dossier.

| App | `minVersion` |
|---|---|
| Photoshop 2025 | 26.0.0 |
| Photoshop 2026 | 27.x |

Panneau **modeless** uniquement (compatible batchPlay 2026).

## Usage express

1. Ouvre un visuel RGB (idéalement 1080×1350 ou plus).
2. **Canvas** → *Définir CP_MASTER* → formats → *Générer les artboards*.
3. Optionnel : *Détecter le sujet* pour ancrer le crop.
4. **Type** → brief 3 phrases → *Découper* → *Appliquer la typo*.
5. **Story** → template + format source → *Générer les frames*.
6. *Exporter le pack* → PNG sRGB + `manifest.json`.

Cmd/Ctrl+Z annule chaque action plugin d’un coup.

## Contrat de calques

```
CP_MASTER                 artboard source
  CP_SUBJECT              sujet (Select Subject)
  CP_TXT_HOOK / _PROOF / _CTA
  CP_SAFEZONE_* / CP_NOTE / CP_SCRIM   exclus de l’export

CP_AB_ig_feed_45          déclinaisons Canvas
CP_FR_01 … CP_FR_05       frames Story
```

Les calques sans préfixe `CP_` ne sont pas renommés.

## Développement

```bash
cd photoshop-creator-pack
npm test
npm run pack    # dist/CreatorPack-1.1.0.ccx
```
