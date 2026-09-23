# -*- coding: utf-8 -*-
"""Contenu de la facture proforma OPVN — E.I. Boubacar Adamou Moustapha.

Source : Facture_Proforma_OPVN_Boubacar_Adamou_Moustapha.docx
Les montants sont en francs CFA (FCFA).
"""

FOURNISSEUR = {
    "sigle": "E.I.",
    "activite": "COMMERCE GÉNÉRAL",
    "nom": "BOUBACAR ADAMOU MOUSTAPHA",
    "forme": "Entreprise Individuelle — Commerce Général",
    "adresse": "Quartier Boukoki, CUN II, Niamey",
    "tel": "+227 80 91 86 06",
    "nif": "78708/P — Centre des Impôts Tourakou",
}

FACTURE = {
    "numero": "PF-2026-0915-007",
    "date": "15/09/2026",
    "validite": "15/10/2026",
    "client": "OPVN — Office des Produits Vivriers du Niger",
    "objet": "Confection de tenues avec logo OPVN",
}

# (n°, désignation, détail, quantité, prix unitaire)
LIGNES = [
    (1,
     "Ensemble T-shirt + Pantalon + Casquette avec logo OPVN",
     "Planton : vert + noir + casquette noire  •  Manœuvre : vert + noir + "
     "casquette noire  •  Chauffeur : orange + noir + casquette noire  •  "
     "Gardiens : bleu marine + noir",
     200, 32000),
    (2,
     "Contre-veste marron avec logo OPVN",
     "Planton (2ème complet) + Gardiens (2ème complet)",
     108, 38500),
    (3,
     "Bleu de travail mécanicien avec logo OPVN (les deux complets bleus)",
     "Manœuvre + Mécaniciens",
     24, 24500),
    (4,
     "Jalabia kaki / Ensemble à poches avec logo OPVN",
     "Chauffeurs (jalabia kaki) + Chauffeurs et Graisseurs",
     80, 31300),
]

TOTAL_EN_LETTRES = "Treize millions six cent cinquante mille francs CFA"

CONDITIONS = [
    ("TVA", "—"),
    ("Paiement", "Espèces / virement / chèque"),
    ("Délai de confection", "À convenir"),
]

NOTE = ("Plantons, manœuvres, chauffeurs, gardiens, mécaniciens et graisseurs "
        "— tous les articles brodés avec le logo OPVN.")


def total():
    return sum(qte * pu for _, _, _, qte, pu in LIGNES)


def total_quantite():
    return sum(qte for _, _, _, qte, _ in LIGNES)


def montant(valeur, devise=True):
    """Formate un entier à la française : 13 650 000 FCFA."""
    texte = f"{valeur:,.0f}".replace(",", "\u00a0")
    return texte + (" FCFA" if devise else "")
