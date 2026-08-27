# Examens blancs CCNA 200-301 — Niger Certify

**Propriétaire :** Niger Certify  
**Référentiel :** Cisco CCNA 200-301 v1.1  
**Usage :** pédagogique interne (sessions, évaluations de promo)  
**Reproduction :** interdite sans autorisation écrite

## Documents

| Fichier | Public | Contenu |
|---|---|---|
| `pdf/NigerCertify-CCNA-200-301-Examen-Blanc-A-Enonce.pdf` | Candidats | Énoncé version A (50 questions + mini-lab + feuille-réponses) |
| `pdf/NigerCertify-CCNA-200-301-Examen-Blanc-B-Enonce.pdf` | Candidats | Énoncé version B (sujet parallèle, mêmes pondérations) |
| `pdf/NigerCertify-CCNA-200-301-Examen-Blanc-AB-Corrige-FORMATEUR.pdf` | Formateurs uniquement | Corrigé A + B — **ne pas distribuer** |

Les versions A et B sont **non interchangeables question par question** : même blueprint, items différents (anti-copie salle).

## Conduite d'épreuve

- Durée : **120 minutes**
- Barème : **58 points** (Q1–36 = 1 pt ; Q37–44 = 2 pts tout-ou-rien ; Q45–50 = 2 pts)
- Seuil indicatif « prêt examen Cisco » : **80 % (47/58)**
- Aucun document. Brouillon centre uniquement.
- Mini-lab papier : hors barème, bonus formateur jusqu'à +10 pts

## Régénérer les PDF

```bash
python3 -m pip install reportlab
cd formations/ccna-200-301
python3 build_examens.py
```

Polices requises : DejaVu (`/usr/share/fonts/truetype/dejavu/`).

© Niger Certify — Tous droits réservés.
