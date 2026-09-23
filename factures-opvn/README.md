# Facture proforma OPVN — restylage

Facture proforma de **E.I. Boubacar Adamou Moustapha** pour l'OPVN
(confection de tenues avec logo OPVN), remise en forme dans deux styles au
choix. Le contenu et les montants sont identiques au document d'origine
(`Facture_Proforma_OPVN_Boubacar_Adamou_Moustapha.docx`) : seule la
présentation change.

## Les deux styles

| Style | Couleurs | Typographie | Esprit |
|---|---|---|---|
| `moderne` | bleu nuit `#12263F` + turquoise `#0E9AA7` | Calibri / Noto Sans | bandeau pleine largeur, tableau aéré sans filets verticaux, bandeau « net à payer » |
| `elegante` | anthracite `#23272B` + bronze `#A9762F` | Georgia / Noto Serif pour les titres | filets fins, titre centré, beaucoup de blanc |

Chaque style est produit en deux formats : **PDF** (à envoyer / imprimer) et
**DOCX** (modifiable dans Word).

## Générer les fichiers

```bash
pip install reportlab python-docx
cd factures-opvn

python3 generer_pdf.py             # les deux styles en PDF
python3 generer_docx.py            # les deux styles en DOCX
python3 generer_pdf.py moderne     # un seul style
```

Les fichiers sont écrits dans `/opt/cursor/artifacts` par défaut ; changez la
destination avec la variable d'environnement `SORTIE_FACTURES` :

```bash
SORTIE_FACTURES=./sorties python3 generer_docx.py
```

## Modifier le contenu

Tout le contenu est centralisé dans `donnees_facture.py` : coordonnées du
fournisseur, numéro et dates de la facture, lignes facturées, conditions,
note. Les totaux sont recalculés automatiquement à partir des quantités et
des prix unitaires.

Le montant en lettres (`TOTAL_EN_LETTRES`) est saisi à la main : pensez à le
corriger si vous changez une quantité ou un prix.

## Contrôle des DOCX

Word refuse d'ouvrir un `.docx` dont les propriétés de mise en forme ne
suivent pas l'ordre imposé par le schéma WordprocessingML, là où LibreOffice
reste tolérant. Ce contrôle évite de livrer un fichier « illisible » :

```bash
python3 verifier_docx.py /chemin/vers/Facture_Proforma_OPVN_style_moderne.docx
```

## Fichiers

| Fichier | Rôle |
|---|---|
| `donnees_facture.py` | contenu de la facture et calcul des totaux |
| `generer_pdf.py` | rendu PDF (ReportLab) |
| `generer_docx.py` | rendu DOCX (python-docx) |
| `verifier_docx.py` | contrôle de conformité OOXML des DOCX générés |
| `sorties/` | les quatre fichiers déjà générés |
