# Examens blancs Linux Essentials (LPI 010-160) — Niger Certify

**Propriétaire :** Niger Certify  
**Référentiel :** LPI Linux Essentials 010-160, objectifs v1.6  
**Usage :** pédagogique interne (sessions, évaluations de promo)  
**Reproduction :** interdite sans autorisation écrite

## Documents

| Fichier | Public | Contenu |
|---|---|---|
| `pdf/NigerCertify-Linux-Essentials-010-160-Examen-Blanc-A-Enonce.pdf` | Candidats | Énoncé version A (40 questions + mini-lab + feuille-réponses) |
| `pdf/NigerCertify-Linux-Essentials-010-160-Examen-Blanc-B-Enonce.pdf` | Candidats | Énoncé version B (sujet parallèle, mêmes pondérations) |
| `pdf/NigerCertify-Linux-Essentials-010-160-Examen-Blanc-AB-Corrige-FORMATEUR.pdf` | Formateurs uniquement | Corrigé A + B — **ne pas distribuer** |

Les versions A et B sont **non interchangeables question par question** : même blueprint LPI, items différents (anti-copie salle).

## Conduite d'épreuve

- Durée : **60 minutes** (format officiel LPI)
- Barème : **52 points** (Q1–28 = 1 pt ; Q29–34 = 2 pts tout-ou-rien ; Q35–40 = 2 pts)
- Seuil indicatif « prêt examen LPI » : **67 % (35/52)**
- Aucun document. Brouillon centre uniquement.
- Mini-lab papier : hors barème, bonus formateur jusqu'à +10 pts

## Régénérer les PDF

```bash
python3 -m pip install reportlab
cd formations/linux-essentials
python3 build_examens.py
```

Polices requises : DejaVu (`/usr/share/fonts/truetype/dejavu/`).  
Le moteur visuel est partagé avec `formations/ccna-200-301/pdf_engine.py`.

© Niger Certify — Tous droits réservés.
