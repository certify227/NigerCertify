# Template d’évaluation SIEM & NAC (3 offres)

Fichier prêt à l’emploi : `Evaluation_SIEM_NAC_3_offres.xlsx`

## Contenu

| Feuille | Usage |
|---------|--------|
| `01_Instructions` | Mode d’emploi et échelle de notes 0–5 |
| `02_Contexte` | Identification des offres, périmètre, **pondérations** |
| `03_SIEM_Critères` | Grille technique SIEM (conformité + note + commentaire) |
| `04_NAC_Critères` | Grille technique NAC |
| `05_TCO` | Coûts sur 3 ans (€ HT) |
| `06_Scores` | Scores pondérés **automatiques** |
| `07_Synthese` | Tableau de bord, recommandation, validation |
| `08_Checklist_PoC` | Scénarios de pilote / PoC |

## Utilisation

1. Ouvrir le `.xlsx` dans Excel ou LibreOffice Calc.
2. Remplir les cellules **jaunes** uniquement.
3. Ajuster les poids (%) dans `02_Contexte` (totaux = 100).
4. Lire le classement dans `06_Scores` / `07_Synthese`.

## Régénérer le fichier

```bash
python3 templates/generer_template_siem_nac.py
```
