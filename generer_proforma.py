#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Génération facture proforma OPVN en FCFA"""
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, HRFlowable, Image)
from reportlab.lib.colors import HexColor
import datetime

OUTPUT = "/workspace/Facture_Proforma_OPVN_FCFA.pdf"

BLEU_FONCE = HexColor("#0F2A44")
VERT = HexColor("#1B7A3D")
ORANGE = HexColor("#E67E22")
GRIS_CLAIR = HexColor("#F2F4F7")
GRIS_BORD = HexColor("#D5DCE5")
BLEU_ACCENT = HexColor("#1474C4")

styles = getSampleStyleSheet()
s_title = ParagraphStyle("Title2", parent=styles["Title"], fontSize=22, textColor=BLEU_FONCE, alignment=TA_CENTER, spaceAfter=2*mm, fontName="Helvetica-Bold")
s_sub = ParagraphStyle("Sub", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#5A6C7D"), alignment=TA_CENTER, spaceAfter=4*mm)
s_normal = ParagraphStyle("N", parent=styles["Normal"], fontSize=9, leading=12, textColor=colors.black, fontName="Helvetica")
s_small = ParagraphStyle("S", parent=styles["Normal"], fontSize=8, leading=10.5, textColor=colors.HexColor("#344054"), fontName="Helvetica")
s_bold = ParagraphStyle("B", parent=s_normal, fontName="Helvetica-Bold")
s_cell = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=8.2, leading=10.5, fontName="Helvetica", textColor=colors.black)
s_cell_b = ParagraphStyle("CellB", parent=s_cell, fontName="Helvetica-Bold")
s_cell_center = ParagraphStyle("CellC", parent=s_cell, alignment=TA_CENTER)
s_cell_right = ParagraphStyle("CellR", parent=s_cell, alignment=TA_RIGHT)
s_h = ParagraphStyle("H", parent=styles["Normal"], fontSize=8.5, leading=10.5, fontName="Helvetica-Bold", textColor=colors.white, alignment=TA_CENTER)

date_jour = datetime.date(2026, 9, 16)
date_validite = datetime.date(2026, 10, 16)
numero = "PF-2026-0916-001"

def fmt(n):
    return f"{n:,}".replace(",", " ")

lignes = [
    {
        "des": """<b>Ensemble T-shirt + Pantalon + Casquette avec logo OPVN</b><br/>
        <font size=7 color="#344054">Planton : T-shirt vert + pantalon noir + casquette noire<br/>
        Manœuvre : T-shirt vert + pantalon noir + casquette noire<br/>
        Chauffeur (1er complet) : T-shirt orange + pantalon noir + casquette noire<br/>
        Gardiens (1er complet) : T-shirt bleu marine + pantalon noir</font>""",
        "qte": 200, "pu": 30000,
    },
    {
        "des": """<b>Contre-veste marron avec logo OPVN</b><br/>
        <font size=7 color="#344054">Planton (2ème complet) + Gardiens (2ème complet)</font>""",
        "qte": 108, "pu": 35000,
    },
    {
        "des": """<b>Bleu de travail mécanicien avec logo OPVN (les deux complets bleus)</b><br/>
        <font size=7 color="#344054">Manœuvre : bleu comme mécanicien (2ème tenue) + Mécaniciens : bleu / bleu</font>""",
        "qte": 24, "pu": 20000,
    },
    {
        "des": """<b>Jalabia kaki / Ensemble à poches avec logo OPVN</b><br/>
        <font size=7 color="#344054">Chauffeurs (2ème complet : jalabia kaki) + Chauffeurs et Graisseurs : ensemble à poches</font>""",
        "qte": 80, "pu": 27000,
    },
]

total = sum(l["qte"]*l["pu"] for l in lignes)

doc = SimpleDocTemplate(OUTPUT, pagesize=A4, leftMargin=15*mm, rightMargin=15*mm, topMargin=12*mm, bottomMargin=15*mm,
                        title="Facture Proforma OPVN", author="Fournisseur")

story = []

# Bandeau haut
header_data = [
    [Paragraph("<b><font size=11 color=\"#0F2A44\">[Nom de votre entreprise]</font></b><br/><font size=8 color=\"#5A6C7D\">Confection &amp; Fourniture de tenues professionnelles<br/>Adresse : [Quartier, Ville] — Tél : [+227 XX XX XX XX]<br/>E-mail : [contact@entreprise.ne] — NIF : [XXXXX]</font>", s_normal),
     Paragraph("<font size=9 color=\"#1474C4\"><b>FACTURE PROFORMA</b></font><br/><font size=8><b>N° : %s</b><br/>Date : %s<br/>Validité : %s (30 jours)</font>" % (numero, date_jour.strftime("%d/%m/%Y"), date_validite.strftime("%d/%m/%Y")), s_cell_right)]
]
ht = Table(header_data, colWidths=[95*mm, 85*mm])
ht.setStyle(TableStyle([
    ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ("LEFTPADDING", (0,0), (-1,-1), 4),
    ("RIGHTPADDING", (0,0), (-1,-1), 4),
    ("BOX", (1,0), (1,0), 1, BLEU_ACCENT),
    ("INNERPADDING", (1,0), (1,0), 6),
]))
story.append(ht)
story.append(Spacer(1, 4*mm))
story.append(HRFlowable(width="100%", thickness=1, color=BLEU_ACCENT))
story.append(Spacer(1, 4*mm))

story.append(Paragraph("FACTURE PROFORMA — TENUES DE TRAVAIL AVEC LOGO OPVN", s_title))
story.append(Paragraph("Établie en Francs CFA (FCFA) — Tous les articles avec logo OPVN", s_sub))

# Client / Objet
info_data = [
    [Paragraph("<b>Client :</b> OPVN<br/><font size=8>Office des Produits Vivriers du Niger<br/>Niamey — Niger</font>", s_small),
     Paragraph("<b>Objet :</b> Confection et fourniture de tenues de travail<br/><font size=8>Plantons, Manœuvres, Chauffeurs, Gardiens,<br/>Mécaniciens et Graisseurs — avec logo OPVN</font>", s_small)]
]
it = Table(info_data, colWidths=[90*mm, 90*mm])
it.setStyle(TableStyle([
    ("BACKGROUND", (0,0), (-1,0), GRIS_CLAIR),
    ("BOX", (0,0), (-1,-1), 0.7, GRIS_BORD),
    ("INNERGRID", (0,0), (-1,-1), 0.5, GRIS_BORD),
    ("LEFTPADDING", (0,0), (-1,-1), 6),
    ("RIGHTPADDING", (0,0), (-1,-1), 6),
    ("TOPPADDING", (0,0), (-1,-1), 6),
    ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ("VALIGN", (0,0), (-1,-1), "TOP"),
]))
story.append(it)
story.append(Spacer(1, 5*mm))

# Tableau articles
thead = [Paragraph("N°", s_h), Paragraph("DÉSIGNATION", s_h), Paragraph("QTÉ", s_h), Paragraph("P.U. (FCFA)", s_h), Paragraph("MONTANT (FCFA)", s_h)]
rows = [thead]
for i, l in enumerate(lignes, start=1):
    montant = l["qte"]*l["pu"]
    rows.append([
        Paragraph(str(i), s_cell_center),
        Paragraph(l["des"], s_cell),
        Paragraph(str(l["qte"]), s_cell_center),
        Paragraph(fmt(l["pu"]), s_cell_right),
        Paragraph(fmt(montant), s_cell_right),
    ])

t = Table(rows, colWidths=[10*mm, 90*mm, 15*mm, 30*mm, 35*mm], repeatRows=1)
style_cmds = [
    ("BACKGROUND", (0,0), (-1,0), BLEU_FONCE),
    ("TEXTCOLOR", (0,0), (-1,0), colors.white),
    ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ("GRID", (0,0), (-1,-1), 0.6, GRIS_BORD),
    ("LEFTPADDING", (0,0), (-1,-1), 4),
    ("RIGHTPADDING", (0,0), (-1,-1), 4),
    ("TOPPADDING", (0,0), (-1,-1), 5),
    ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, HexColor("#F8FAFC")]),
]
t.setStyle(TableStyle(style_cmds))
story.append(t)
story.append(Spacer(1, 4*mm))

# Totaux
tot_data = [
    [Paragraph("Total HT (FCFA)", s_cell_right), Paragraph(f"<b>{fmt(total)}</b>", s_cell_right)],
    [Paragraph("TVA", s_cell_right), Paragraph("—", s_cell_right)],
    [Paragraph("<b>Total TTC / Net à payer (FCFA)</b>", s_cell_b), Paragraph(f"<b>{fmt(total)}</b>", s_cell_right)],
]
tt = Table(tot_data, colWidths=[135*mm, 45*mm])
tt.setStyle(TableStyle([
    ("BOX", (0,0), (-1,-1), 0.7, GRIS_BORD),
    ("INNERGRID", (0,0), (-1,-1), 0.5, GRIS_BORD),
    ("BACKGROUND", (0,2), (-1,2), HexColor("#E8F0FE")),
    ("LEFTPADDING", (0,0), (-1,-1), 6),
    ("RIGHTPADDING", (0,0), (-1,-1), 6),
    ("TOPPADDING", (0,0), (-1,-1), 5),
    ("BOTTOMPADDING", (0,0), (-1,-1), 5),
]))
story.append(tt)
story.append(Spacer(1, 3*mm))
story.append(Paragraph("Arrêté la présente facture proforma à la somme de : <b>Douze millions quatre cent vingt mille (12 420 000) francs CFA.</b>", s_small))
story.append(Spacer(1, 3*mm))

# Détail / NB
story.append(Paragraph("<b>Détail des répartitions :</b>", s_small))
story.append(Paragraph(
    "• <b>Planton :</b> T-shirt vert + pantalon noir + casquette noire, + contre-veste marron (2ème complet). &nbsp; "
    "• <b>Manœuvre :</b> T-shirt vert + pantalon noir + casquette noire, + bleu comme mécaniciens.<br/>"
    "• <b>Chauffeur :</b> T-shirt orange + pantalon noir + casquette noire, + jalabia kaki / ensemble à poches (2ème complet). &nbsp; "
    "• <b>Gardiens :</b> T-shirt bleu marine + pantalon noir, + contre-veste marron (2ème complet).<br/>"
    "• <b>Mécaniciens :</b> bleu / bleu (les deux complets). &nbsp; "
    "• <b>NB :</b> Tous les articles avec le logo de l’OPVN.", s_small))
story.append(Spacer(1, 3*mm))
story.append(Paragraph("<b>Conditions :</b> Prix en FCFA. Validité de l’offre : 30 jours. Délai de confection à convenir. Paiement : à préciser (espèces / virement / chèque).", s_small))
story.append(Spacer(1, 6*mm))

# Signatures
sig_data = [
    [Paragraph("Le Fournisseur<br/><br/><br/>Signature &amp; Cachet", s_cell_center),
     Paragraph("Le Client — OPVN<br/><font size=7>Lu et approuvé, Bon pour accord</font><br/><br/><br/>Signature &amp; Cachet", s_cell_center)]
]
sg = Table(sig_data, colWidths=[90*mm, 90*mm])
sg.setStyle(TableStyle([
    ("VALIGN", (0,0), (-1,-1), "TOP"),
    ("LEFTPADDING", (0,0), (-1,-1), 6),
]))
story.append(sg)
story.append(Spacer(1, 6*mm))
story.append(HRFlowable(width="100%", thickness=0.6, color=GRIS_BORD))
story.append(Spacer(1, 2*mm))
story.append(Paragraph("Document établi à titre proforma — ne tient pas lieu de facture définitive. Merci de nous retourner un exemplaire signé.", s_small))
story.append(Paragraph("[Nom entreprise] — [Adresse] — Tél : [+227 XX XX XX XX] — Page 1/1", ParagraphStyle("foot", parent=s_small, alignment=TA_CENTER, fontSize=7, textColor=HexColor("#667085"))))

def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(HexColor("#667085"))
    canvas.drawCentredString(A4[0]/2, 12*mm, f"Proforma N° {numero} — {fmt(total)} FCFA — OPVN — Tenues avec logo")
    canvas.restoreState()

doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(f"OK -> {OUTPUT} total={total}")
