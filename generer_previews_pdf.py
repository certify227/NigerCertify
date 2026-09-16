#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Previews PDF des 2 concurrentes (mêmes prix que les DOCX) pour visualisation."""
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.colors import HexColor

def fmt(n): return f"{n:,}".replace(",", " ")

def build(output, theme, entreprise, numero, dj, dv, lignes, total_lettres):
    primary = HexColor(theme["primary"])
    light = HexColor(theme["light"])
    styles = getSampleStyleSheet()
    s_n = ParagraphStyle("n", parent=styles["Normal"], fontSize=9, leading=12, fontName="Helvetica")
    s_s = ParagraphStyle("s", parent=styles["Normal"], fontSize=8, leading=10.5, fontName="Helvetica", textColor=HexColor("#344054"))
    s_h = ParagraphStyle("h", parent=styles["Normal"], fontSize=8.5, leading=10.5, fontName="Helvetica-Bold", textColor=colors.white, alignment=TA_CENTER)
    s_c = ParagraphStyle("c", parent=styles["Normal"], fontSize=8.2, leading=10.5, fontName="Helvetica")
    s_cc = ParagraphStyle("cc", parent=s_c, alignment=TA_CENTER)
    s_cr = ParagraphStyle("cr", parent=s_c, alignment=TA_RIGHT)
    doc = SimpleDocTemplate(output, pagesize=A4, leftMargin=15*mm, rightMargin=15*mm, topMargin=12*mm, bottomMargin=15*mm, title=f"Concurrent {numero}")
    story = []
    # bandeau entreprise
    story.append(Table([[Paragraph(f"<b><font size=12>{entreprise['nom']}</font></b><br/><font size=8>{entreprise['lignes']}</font>", s_n)]],
                       colWidths=[180*mm], style=TableStyle([("BACKGROUND",(0,0),(-1,-1),primary),("TEXTCOLOR",(0,0),(-1,-1),colors.white),("LEFTPADDING",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8)])))
    story.append(Spacer(1,4*mm))
    story.append(Table([[Paragraph(f"<b>FACTURE PROFORMA N° {numero}</b><br/>Date : {dj} — Validité : {dv} (30 jours)<br/>Client : OPVN — Tenues avec logo OPVN", ParagraphStyle("r",parent=s_s,alignment=TA_RIGHT))]], colWidths=[180*mm]))
    story.append(Spacer(1,3*mm)); story.append(HRFlowable(width="100%", thickness=1, color=primary)); story.append(Spacer(1,4*mm))
    rows = [[Paragraph("N°",s_h),Paragraph("DÉSIGNATION",s_h),Paragraph("QTÉ",s_h),Paragraph("P.U. (FCFA)",s_h),Paragraph("MONTANT (FCFA)",s_h)]]
    for i,(des,qte,pu) in enumerate(lignes,1):
        rows.append([Paragraph(str(i),s_cc),Paragraph(des,s_c),Paragraph(str(qte),s_cc),Paragraph(fmt(pu),s_cr),Paragraph(fmt(qte*pu),s_cr)])
    t = Table(rows, colWidths=[10*mm,90*mm,15*mm,30*mm,35*mm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),primary),("GRID",(0,0),(-1,-1),0.6,HexColor("#D5DCE5")),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("LEFTPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,light])]))
    story.append(t); story.append(Spacer(1,4*mm))
    total = sum(q*pu for _,q,pu in lignes)
    tt = Table([[Paragraph("<b>Total TTC / Net à payer (FCFA)</b>",s_n),Paragraph(f"<b>{fmt(total)}</b>",s_cr)]], colWidths=[135*mm,45*mm])
    tt.setStyle(TableStyle([("BOX",(0,0),(-1,-1),0.7,HexColor("#D5DCE5")),("BACKGROUND",(0,0),(-1,-1),light),("LEFTPADDING",(0,0),(-1,-1),6),("RIGHTPADDING",(0,0),(-1,-1),6),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
    story.append(tt); story.append(Spacer(1,3*mm))
    story.append(Paragraph(f"Arrêté à : <b>{total_lettres} ({fmt(total)}) francs CFA.</b>", s_s))
    story.append(Spacer(1,3*mm))
    story.append(Paragraph("Planton vert/noir/casquette + contre-veste marron • Manœuvre vert/noir/casquette + bleu • Chauffeur orange/noir/casquette + jalabia/poches • Gardiens bleu marine/noir + contre-veste marron • Mécaniciens bleu/bleu • Tous avec logo OPVN.", s_s))
    story.append(Spacer(1,6*mm))
    story.append(Table([[Paragraph("Fournisseur<br/><br/>Signature & Cachet",s_cc),Paragraph("OPVN — Bon pour accord<br/><br/>Signature & Cachet",s_cc)]], colWidths=[90*mm,90*mm]))
    doc.build(story)
    print(f"OK -> {output} {total}")

D1="Ensemble T-shirt + Pantalon + Casquette, logo OPVN"; D2="Contre-veste marron, logo OPVN"; D3="Bleu mécanicien, logo OPVN"; D4="Jalabia kaki / Ensemble à poches, logo OPVN"
build("/workspace/Facture_Proforma_OPVN_Concurrent_A.pdf", {"primary":"#1B7A3D","light":"#EAF5EC"},
      {"nom":"ETS SAHEL CONFECTION & SERVICES","lignes":"Lazaret, Niamey — +227 90 12 34 56 — NIF 45210/S"},
      "PF-2026-0914-002","14/09/2026","14/10/2026",
      [(D1,200,32500),(D2,108,37500),(D3,24,22500),(D4,80,29500)], "Treize millions quatre cent cinquante mille")
build("/workspace/Facture_Proforma_OPVN_Concurrent_B.pdf", {"primary":"#7A1C1C","light":"#FDF0F0"},
      {"nom":"NIGER TEXTILE PRO – NTP","lignes":"Av. de l'Indépendance, Niamey — +227 96 78 45 12 — NIF 38902/R"},
      "PF-2026-0915-007","15/09/2026","15/10/2026",
      [(D1,200,31500),(D2,108,38000),(D3,24,23000),(D4,80,30000)], "Treize millions trois cent cinquante-six mille")
