#!/usr/bin/env python3
"""Génération de la facture proforma OPVN (tenues de travail) en FCFA."""

from datetime import date

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUTPUT = "facture_proforma_opvn.pdf"

BLEU = colors.HexColor("#0B4F6C")
BLEU_CLAIR = colors.HexColor("#DDEBF3")
GRIS = colors.HexColor("#444444")


def fcfa(montant: int) -> str:
    """Formatte un entier en FCFA avec séparateur d'espace insécable."""
    return f"{montant:,.0f}".replace(",", "\u00a0") + " FCFA"


# --- Données de la facture -------------------------------------------------

LIGNES = [
    (
        "Tenue complète avec casquette (T-shirt + pantalon + casquette, logo OPVN)",
        "Plantons, manœuvres, gardiens, chauffeurs — 1er complet",
        200,
        30_000,
    ),
    (
        "Complément contre-veste (logo OPVN)",
        "Plantons et gardiens — 2e complet avec contre-veste marron",
        108,
        35_000,
    ),
    (
        "Bleu de travail mécanicien (les deux complets, logo OPVN)",
        "Mécaniciens — tenue bleue intégrale",
        24,
        20_000,
    ),
    (
        "Tenue à poches (T-shirt + pantalon à poches, logo OPVN)",
        "Chauffeurs et graisseurs",
        80,
        27_000,
    ),
]

DETAIL_TENUES = [
    ("Planton", "T-shirt vert, pantalon noir, casquette noire, contre-veste marron"),
    ("Manœuvre", "T-shirt vert, pantalon noir, casquette noire et bleue (type mécanicien)"),
    ("Chauffeur", "T-shirt orange, pantalon noir, casquette noire — 2e complet : jalabia khaki"),
    ("Gardien", "T-shirt bleu marine, pantalon noir — 2e complet : contre-veste marron"),
    ("Mécanicien", "Bleu de travail sur les deux complets"),
]


def construire():
    doc = SimpleDocTemplate(
        OUTPUT,
        pagesize=A4,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        title="Facture proforma OPVN",
    )

    styles = getSampleStyleSheet()
    st_titre = ParagraphStyle(
        "Titre", parent=styles["Title"], textColor=BLEU, fontSize=22, spaceAfter=2
    )
    st_sous = ParagraphStyle(
        "Sous", parent=styles["Normal"], textColor=GRIS, fontSize=10
    )
    st_h = ParagraphStyle(
        "H", parent=styles["Heading2"], textColor=BLEU, fontSize=12, spaceBefore=8
    )
    st_cell = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=9, leading=12)
    st_cell_b = ParagraphStyle("CellB", parent=st_cell, fontName="Helvetica-Bold")
    st_small = ParagraphStyle(
        "Small", parent=styles["Normal"], fontSize=8, textColor=GRIS, leading=11
    )

    elems = []

    # En-tête
    entete = Table(
        [[
            Paragraph("<b>FACTURE PROFORMA</b>", st_titre),
            Paragraph(
                "N° <b>PRO-OPVN-2026-001</b><br/>"
                f"Date : <b>{date.today().strftime('%d/%m/%Y')}</b><br/>"
                "Devise : <b>FCFA (XOF)</b><br/>"
                "Validité : 30 jours",
                st_sous,
            ),
        ]],
        colWidths=[100 * mm, 78 * mm],
    )
    entete.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    elems.append(entete)
    elems.append(Spacer(1, 6 * mm))

    # Émetteur / Client
    parties = Table(
        [[
            Paragraph("<b>ÉMETTEUR</b><br/>Fournisseur de tenues professionnelles<br/>"
                      "Confection & marquage logo<br/>Niamey, Niger", st_small),
            Paragraph("<b>CLIENT</b><br/>OPVN — Office des Produits Vivriers du Niger<br/>"
                      "Commande de tenues de travail<br/>Niamey, Niger", st_small),
        ]],
        colWidths=[89 * mm, 89 * mm],
    )
    parties.setStyle(TableStyle([
        ("BOX", (0, 0), (0, 0), 0.5, colors.lightgrey),
        ("BOX", (1, 0), (1, 0), 0.5, colors.lightgrey),
        ("BACKGROUND", (0, 0), (-1, -1), BLEU_CLAIR),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elems.append(parties)
    elems.append(Spacer(1, 6 * mm))

    # Tableau des lignes
    data = [[
        Paragraph("<b>Désignation</b>", st_cell_b),
        Paragraph("<b>Bénéficiaires</b>", st_cell_b),
        Paragraph("<b>Qté</b>", st_cell_b),
        Paragraph("<b>P.U.</b>", st_cell_b),
        Paragraph("<b>Total</b>", st_cell_b),
    ]]

    total_general = 0
    total_qte = 0
    for design, benef, qte, pu in LIGNES:
        montant = qte * pu
        total_general += montant
        total_qte += qte
        data.append([
            Paragraph(design, st_cell),
            Paragraph(benef, st_cell),
            Paragraph(str(qte), st_cell),
            Paragraph(fcfa(pu), st_cell),
            Paragraph(fcfa(montant), st_cell),
        ])

    data.append([
        Paragraph("<b>TOTAL GÉNÉRAL</b>", st_cell_b),
        "",
        Paragraph(f"<b>{total_qte}</b>", st_cell_b),
        "",
        Paragraph(f"<b>{fcfa(total_general)}</b>", st_cell_b),
    ])

    tbl = Table(
        data,
        colWidths=[62 * mm, 55 * mm, 12 * mm, 24 * mm, 25 * mm],
        repeatRows=1,
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BLEU),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (2, 0), (4, -1), "RIGHT"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, BLEU_CLAIR]),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#F3C623")),
        ("SPAN", (0, -1), (1, -1)),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    elems.append(tbl)
    elems.append(Spacer(1, 4 * mm))

    montant_lettres = (
        "Arrêtée la présente facture proforma à la somme de "
        "<b>douze millions quatre cent vingt mille (12 420 000) FCFA</b>."
    )
    elems.append(Paragraph(montant_lettres, st_small))
    elems.append(Spacer(1, 6 * mm))

    # Détail des tenues par catégorie
    elems.append(Paragraph("Détail des tenues par catégorie de personnel", st_h))
    det = [[Paragraph("<b>Catégorie</b>", st_cell_b), Paragraph("<b>Composition de la tenue</b>", st_cell_b)]]
    for cat, comp in DETAIL_TENUES:
        det.append([Paragraph(cat, st_cell_b), Paragraph(comp, st_cell)])
    det_tbl = Table(det, colWidths=[35 * mm, 143 * mm])
    det_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BLEU),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BLEU_CLAIR]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    elems.append(det_tbl)
    elems.append(Spacer(1, 6 * mm))

    notes = (
        "<b>Notes :</b><br/>"
        "• Toutes les tenues sont fournies avec le <b>logo OPVN</b>.<br/>"
        "• Facture proforma non contractuelle, établie à titre indicatif pour devis.<br/>"
        "• Montants exprimés en FCFA (XOF), hors éventuelles taxes applicables.<br/>"
        "• Délai de livraison et modalités de paiement à convenir à la commande."
    )
    elems.append(Paragraph(notes, st_small))
    elems.append(Spacer(1, 12 * mm))

    sign = Table(
        [[Paragraph("Cachet & signature de l'émetteur", st_small),
          Paragraph("Bon pour accord — le client", st_small)]],
        colWidths=[89 * mm, 89 * mm],
    )
    sign.setStyle(TableStyle([
        ("LINEABOVE", (0, 0), (0, 0), 0.5, GRIS),
        ("LINEABOVE", (1, 0), (1, 0), 0.5, GRIS),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    elems.append(sign)

    doc.build(elems)
    print(f"PDF généré : {OUTPUT}  | Total : {fcfa(total_general)}")


if __name__ == "__main__":
    construire()
