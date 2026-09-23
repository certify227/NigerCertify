# -*- coding: utf-8 -*-
"""Génère la facture proforma OPVN en PDF, dans deux styles au choix.

    python3 generer_pdf.py            # les deux styles
    python3 generer_pdf.py moderne    # un seul style

Styles :
  • moderne  — bleu nuit / turquoise, sans-serif, bandeau pleine largeur
  • elegante — anthracite / bronze, titres serif, filets fins, très aéré
"""

import os
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

import donnees_facture as D

SORTIE = os.environ.get("SORTIE_FACTURES", "/opt/cursor/artifacts")

NOTO = "/usr/share/fonts/truetype/noto"


def enregistrer_polices():
    paires = [
        ("Sans", f"{NOTO}/NotoSans-Regular.ttf"),
        ("Sans-Bold", f"{NOTO}/NotoSans-Bold.ttf"),
        ("Sans-Italic", f"{NOTO}/NotoSans-Italic.ttf"),
        ("Serif", f"{NOTO}/NotoSerif-Regular.ttf"),
        ("Serif-Bold", f"{NOTO}/NotoSerif-Bold.ttf"),
    ]
    for nom, chemin in paires:
        pdfmetrics.registerFont(TTFont(nom, chemin))
    pdfmetrics.registerFontFamily(
        "Sans", normal="Sans", bold="Sans-Bold", italic="Sans-Italic",
        boldItalic="Sans-Bold")
    pdfmetrics.registerFontFamily(
        "Serif", normal="Serif", bold="Serif-Bold", italic="Serif",
        boldItalic="Serif-Bold")


# --------------------------------------------------------------------------
# Thèmes
# --------------------------------------------------------------------------

THEMES = {
    "moderne": {
        "libelle": "Moderne",
        "encre": colors.HexColor("#12263F"),
        "accent": colors.HexColor("#0E9AA7"),
        "doux": colors.HexColor("#EEF4F8"),
        "gris": colors.HexColor("#6B7A8C"),
        "filet": colors.HexColor("#DCE4EC"),
        "titre_police": "Sans-Bold",
        "corps_police": "Sans",
    },
    "elegante": {
        "libelle": "Élégante",
        "encre": colors.HexColor("#23272B"),
        "accent": colors.HexColor("#A9762F"),
        "doux": colors.HexColor("#FAF6EF"),
        "gris": colors.HexColor("#77706A"),
        "filet": colors.HexColor("#E2DCD2"),
        "titre_police": "Serif-Bold",
        "corps_police": "Sans",
    },
}


def styles_pour(t):
    """Construit les styles de paragraphe du thème."""
    s = {}
    s["corps"] = ParagraphStyle(
        "corps", fontName=t["corps_police"], fontSize=8.6, leading=11.6,
        textColor=t["encre"])
    s["corps_blanc"] = ParagraphStyle(
        "corps_blanc", parent=s["corps"], textColor=colors.white)
    s["petit"] = ParagraphStyle(
        "petit", parent=s["corps"], fontSize=7.4, leading=10,
        textColor=t["gris"])
    s["petit_blanc"] = ParagraphStyle(
        "petit_blanc", parent=s["petit"],
        textColor=colors.Color(1, 1, 1, alpha=0.75))
    s["etiquette"] = ParagraphStyle(
        "etiquette", fontName="Sans-Bold", fontSize=6.6, leading=9,
        textColor=t["gris"])
    s["etiquette_accent"] = ParagraphStyle(
        "etiquette_accent", parent=s["etiquette"], textColor=t["accent"])
    s["valeur"] = ParagraphStyle(
        "valeur", fontName="Sans-Bold", fontSize=9.4, leading=12,
        textColor=t["encre"])
    s["section"] = ParagraphStyle(
        "section", fontName=t["titre_police"], fontSize=10, leading=13,
        textColor=t["encre"], spaceBefore=0, spaceAfter=4)
    s["article"] = ParagraphStyle(
        "article", fontName="Sans-Bold", fontSize=8.8, leading=11.6,
        textColor=t["encre"])
    s["detail"] = ParagraphStyle(
        "detail", fontName=t["corps_police"], fontSize=7.4, leading=10,
        textColor=t["gris"])
    s["nombre"] = ParagraphStyle(
        "nombre", fontName="Sans", fontSize=9, leading=12,
        textColor=t["encre"], alignment=TA_RIGHT)
    s["nombre_fort"] = ParagraphStyle(
        "nombre_fort", parent=s["nombre"], fontName="Sans-Bold")
    s["entete_tab"] = ParagraphStyle(
        "entete_tab", fontName="Sans-Bold", fontSize=7.2, leading=9.5,
        textColor=colors.white)
    s["entete_tab_d"] = ParagraphStyle(
        "entete_tab_d", parent=s["entete_tab"], alignment=TA_RIGHT)
    s["centre"] = ParagraphStyle(
        "centre", parent=s["corps"], alignment=TA_CENTER)
    return s


# --------------------------------------------------------------------------
# Briques communes
# --------------------------------------------------------------------------

LARGEUR_UTILE = 174 * mm


def bloc_info(t, s):
    """Quatre « pastilles » : n°, date, validité, devise."""
    items = [
        ("FACTURE N°", D.FACTURE["numero"]),
        ("DATE D'ÉMISSION", D.FACTURE["date"]),
        ("VALABLE JUSQU'AU", D.FACTURE["validite"]),
        ("DEVISE", "Franc CFA (FCFA)"),
    ]
    cellules = [[
        [Paragraph(lib, s["etiquette"]), Spacer(1, 1.4 * mm),
         Paragraph(val, s["valeur"])]
        for lib, val in items
    ]]
    largeur = LARGEUR_UTILE / 4
    tbl = Table(cellules, colWidths=[largeur] * 4)
    tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), t["doux"]),
        ("LINEAFTER", (0, 0), (-2, -1), 0.6, colors.white),
        ("LINEABOVE", (0, 0), (-1, 0), 1.6, t["accent"]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return tbl


def bloc_client(t, s):
    """Client / objet, côte à côte, avec barre d'accent à gauche."""
    gauche = [
        Paragraph("CLIENT", s["etiquette_accent"]),
        Spacer(1, 1.6 * mm),
        Paragraph(f"<b>{D.FACTURE['client']}</b>", s["corps"]),
    ]
    droite = [
        Paragraph("OBJET", s["etiquette_accent"]),
        Spacer(1, 1.6 * mm),
        Paragraph(D.FACTURE["objet"], s["corps"]),
    ]
    tbl = Table([[gauche, droite]],
                colWidths=[LARGEUR_UTILE * 0.52, LARGEUR_UTILE * 0.48])
    tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBEFORE", (0, 0), (0, 0), 2, t["accent"]),
        ("LINEBEFORE", (1, 0), (1, 0), 2, t["filet"]),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return tbl


def tableau_lignes(t, s):
    """Tableau des articles : pas de filets verticaux, lignes aérées."""
    data = [[
        Paragraph("N°", s["entete_tab"]),
        Paragraph("DÉSIGNATION", s["entete_tab"]),
        Paragraph("QTÉ", s["entete_tab_d"]),
        Paragraph("PRIX UNIT.", s["entete_tab_d"]),
        Paragraph("MONTANT", s["entete_tab_d"]),
    ]]
    for num, titre, detail, qte, pu in D.LIGNES:
        data.append([
            Paragraph(f"{num:02d}", s["nombre"]),
            [Paragraph(titre, s["article"]), Spacer(1, 1 * mm),
             Paragraph(detail, s["detail"])],
            Paragraph(str(qte), s["nombre"]),
            Paragraph(D.montant(pu, devise=False), s["nombre"]),
            Paragraph(D.montant(qte * pu, devise=False), s["nombre_fort"]),
        ])

    data.append([
        "",
        Paragraph("Total des articles", s["article"]),
        Paragraph(f"<b>{D.total_quantite()}</b>", s["nombre_fort"]),
        "",
        Paragraph(D.montant(D.total(), devise=False), s["nombre_fort"]),
    ])

    tbl = Table(
        data,
        colWidths=[10 * mm, 94 * mm, 14 * mm, 24 * mm, 32 * mm],
        repeatRows=1,
    )
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), t["encre"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
        ("VALIGN", (0, -1), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        # filets horizontaux seulement
        ("LINEBELOW", (0, 1), (-1, -3), 0.4, t["filet"]),
        ("LINEABOVE", (0, -1), (-1, -1), 1.2, t["encre"]),
        ("BACKGROUND", (0, -1), (-1, -1), t["doux"]),
    ]
    for i in range(1, len(D.LIGNES) + 1):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i),
                          colors.HexColor("#FBFCFD")))
    tbl.setStyle(TableStyle(style))
    return tbl


def carte_total(t, s):
    """Bandeau du net à payer + montant en lettres."""
    gauche = [
        Paragraph("NET À PAYER", ParagraphStyle(
            "np", parent=s["etiquette"],
            textColor=colors.Color(1, 1, 1, alpha=0.8))),
        Spacer(1, 2 * mm),
        Paragraph(D.montant(D.total()), ParagraphStyle(
            "montant", fontName="Sans-Bold", fontSize=19, leading=22,
            textColor=colors.white)),
        Spacer(1, 1.4 * mm),
        Paragraph(D.TOTAL_EN_LETTRES, s["petit_blanc"]),
    ]
    droite = []
    for lib, val in D.CONDITIONS:
        droite.append(Paragraph(
            f'<font color="#FFFFFF"><b>{lib}</b></font>'
            f'<font color="#B9C4D0"> — {val}</font>', s["petit_blanc"]))
        droite.append(Spacer(1, 1.6 * mm))

    tbl = Table([[gauche, droite]],
                colWidths=[LARGEUR_UTILE * 0.58, LARGEUR_UTILE * 0.42])
    tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
        ("VALIGN", (1, 0), (1, 0), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, -1), t["encre"]),
        ("LINEBEFORE", (1, 0), (1, 0), 0.6,
         colors.Color(1, 1, 1, alpha=0.25)),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return tbl


def bloc_note(t, s):
    tbl = Table([[
        [Paragraph("NOTE", s["etiquette_accent"]), Spacer(1, 1.2 * mm),
         Paragraph(D.NOTE, s["corps"])]
    ]], colWidths=[LARGEUR_UTILE])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), t["doux"]),
        ("LINEBEFORE", (0, 0), (0, 0), 2, t["accent"]),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return tbl


def bloc_signatures(t, s):
    gauche = [
        Paragraph("LE FOURNISSEUR", s["etiquette"]),
        Spacer(1, 1.2 * mm),
        Paragraph(f"E.I. {D.FOURNISSEUR['nom'].title()}", s["corps"]),
    ]
    droite = [
        Paragraph("LE CLIENT (OPVN)", s["etiquette"]),
        Spacer(1, 1.2 * mm),
        Paragraph("Lu et approuvé", s["corps"]),
    ]
    tbl = Table(
        [["", ""], [gauche, droite]],
        colWidths=[LARGEUR_UTILE / 2, LARGEUR_UTILE / 2],
        rowHeights=[20 * mm, None],
    )
    tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (0, 0), 0.7, t["gris"]),
        ("LINEBELOW", (1, 0), (1, 0), 0.7, t["gris"]),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
        ("LEFTPADDING", (1, 0), (1, -1), 14),
        ("RIGHTPADDING", (0, 0), (0, -1), 14),
        ("RIGHTPADDING", (1, 0), (1, -1), 0),
        ("TOPPADDING", (0, 1), (-1, 1), 4),
    ]))
    return tbl


# --------------------------------------------------------------------------
# Habillage de page (bandeau + pied), propre à chaque style
# --------------------------------------------------------------------------

def dessiner_moderne(canevas, doc, t):
    L, H = A4
    canevas.saveState()

    # bandeau supérieur pleine largeur
    haut = 34 * mm
    canevas.setFillColor(t["encre"])
    canevas.rect(0, H - haut, L, haut, stroke=0, fill=1)
    canevas.setFillColor(t["accent"])
    canevas.rect(0, H - haut - 2.6 * mm, L, 2.6 * mm, stroke=0, fill=1)

    marge = 18 * mm
    # identité à gauche
    canevas.setFillColor(colors.white)
    canevas.setFont("Sans-Bold", 15)
    canevas.drawString(marge, H - 15 * mm, D.FOURNISSEUR["nom"])
    canevas.setFont("Sans", 7.6)
    canevas.setFillColor(colors.HexColor("#B9C4D0"))
    canevas.drawString(marge, H - 20 * mm, D.FOURNISSEUR["forme"])
    canevas.drawString(
        marge, H - 24 * mm,
        f"{D.FOURNISSEUR['adresse']}  ·  Tél {D.FOURNISSEUR['tel']}")
    canevas.drawString(marge, H - 28 * mm,
                       f"NIF {D.FOURNISSEUR['nif']}")

    # intitulé à droite
    canevas.setFillColor(t["accent"])
    canevas.setFont("Sans-Bold", 8)
    canevas.drawRightString(L - marge, H - 13 * mm, "PROFORMA")
    canevas.setFillColor(colors.white)
    canevas.setFont("Sans-Bold", 20)
    canevas.drawRightString(L - marge, H - 21 * mm, "FACTURE")
    canevas.setFont("Sans", 8)
    canevas.setFillColor(colors.HexColor("#B9C4D0"))
    canevas.drawRightString(L - marge, H - 27 * mm,
                            f"N° {D.FACTURE['numero']}")

    pied(canevas, doc, t)
    canevas.restoreState()


def dessiner_elegante(canevas, doc, t):
    L, H = A4
    canevas.saveState()
    marge = 20 * mm

    # double filet supérieur
    y = H - 20 * mm
    canevas.setStrokeColor(t["encre"])
    canevas.setLineWidth(1.4)
    canevas.line(marge, y, L - marge, y)
    canevas.setLineWidth(0.4)
    canevas.line(marge, y - 1.6 * mm, L - marge, y - 1.6 * mm)

    # identité centrée, serif espacé
    canevas.setFillColor(t["encre"])
    canevas.setFont("Serif-Bold", 14)
    canevas.drawCentredString(L / 2, y - 9 * mm, D.FOURNISSEUR["nom"])
    canevas.setFillColor(t["gris"])
    canevas.setFont("Sans", 7.4)
    canevas.drawCentredString(L / 2, y - 13.6 * mm, D.FOURNISSEUR["forme"])
    canevas.drawCentredString(
        L / 2, y - 17.4 * mm,
        f"{D.FOURNISSEUR['adresse']}  ·  Tél {D.FOURNISSEUR['tel']}  ·  "
        f"NIF {D.FOURNISSEUR['nif']}")

    # titre encadré de filets
    yt = y - 27 * mm
    canevas.setStrokeColor(t["accent"])
    canevas.setLineWidth(0.7)
    canevas.line(marge, yt + 6.4 * mm, L - marge, yt + 6.4 * mm)
    canevas.setFillColor(t["encre"])
    canevas.setFont("Serif-Bold", 17)
    canevas.drawCentredString(L / 2, yt, "FACTURE PROFORMA")
    canevas.setStrokeColor(t["accent"])
    canevas.line(marge, yt - 4 * mm, L - marge, yt - 4 * mm)

    pied(canevas, doc, t)
    canevas.restoreState()


def pied(canevas, doc, t):
    L, _ = A4
    marge = 18 * mm
    canevas.setStrokeColor(t["filet"])
    canevas.setLineWidth(0.5)
    canevas.line(marge, 13 * mm, L - marge, 13 * mm)
    canevas.setFont("Sans", 6.8)
    canevas.setFillColor(t["gris"])
    canevas.drawString(
        marge, 9.6 * mm,
        f"E.I. {D.FOURNISSEUR['nom'].title()}  ·  NIF {D.FOURNISSEUR['nif']}")
    canevas.drawRightString(
        L - marge, 9.6 * mm,
        f"{D.FACTURE['numero']}  ·  {D.montant(D.total())}  ·  page "
        f"{canevas.getPageNumber()}")


# --------------------------------------------------------------------------
# Assemblage
# --------------------------------------------------------------------------

def construire(style):
    t = THEMES[style]
    s = styles_pour(t)

    chemin = os.path.join(
        SORTIE, f"Facture_Proforma_OPVN_style_{style}.pdf")
    haut = 44 * mm if style == "moderne" else 58 * mm
    doc = SimpleDocTemplate(
        chemin, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=haut, bottomMargin=18 * mm,
        title=f"Facture proforma {D.FACTURE['numero']} — OPVN",
        author=f"E.I. {D.FOURNISSEUR['nom'].title()}",
        subject="Confection de tenues avec logo OPVN",
    )

    histoire = [
        bloc_info(t, s),
        Spacer(1, 6 * mm),
        bloc_client(t, s),
        Spacer(1, 7 * mm),
        Paragraph("Détail de la prestation", s["section"]),
        Spacer(1, 1 * mm),
        tableau_lignes(t, s),
        Spacer(1, 6 * mm),
        carte_total(t, s),
        Spacer(1, 5 * mm),
        bloc_note(t, s),
        Spacer(1, 8 * mm),
        bloc_signatures(t, s),
    ]

    dessin = dessiner_moderne if style == "moderne" else dessiner_elegante
    doc.build(histoire,
              onFirstPage=lambda c, d: dessin(c, d, t),
              onLaterPages=lambda c, d: pied(c, d, t))
    return chemin


def main():
    enregistrer_polices()
    os.makedirs(SORTIE, exist_ok=True)
    demandes = sys.argv[1:] or list(THEMES)
    for style in demandes:
        if style not in THEMES:
            raise SystemExit(
                f"Style inconnu : {style} (choix : {', '.join(THEMES)})")
        print("PDF généré :", construire(style))


if __name__ == "__main__":
    main()
