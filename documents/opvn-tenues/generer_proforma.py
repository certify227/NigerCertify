#!/usr/bin/env python3
"""Génère la facture pro forma OPVN — tenues de travail (FCFA)."""

from __future__ import annotations

from pathlib import Path

from reportlab.lib.colors import HexColor, white
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Flowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "Facture_Proforma_OPVN_Tenues_Travail.pdf"

pdfmetrics.registerFont(TTFont("Inter", "/usr/share/fonts/truetype/macos/Inter-Regular.ttf"))
pdfmetrics.registerFont(TTFont("Inter-Md", "/usr/share/fonts/truetype/macos/Inter-Medium.ttf"))
pdfmetrics.registerFont(TTFont("Inter-Bd", "/usr/share/fonts/truetype/macos/Inter-Bold.ttf"))

NAVY = HexColor("#0F2744")
NAVY_DEEP = HexColor("#0A1B30")
GREEN = HexColor("#1B7A3D")
GOLD = HexColor("#C9A227")
SAND = HexColor("#F4EFE4")
IVORY = HexColor("#FAF8F3")
LINE = HexColor("#D9D2C5")
MUTED = HexColor("#5C6570")
ROW_ALT = HexColor("#F7F3EA")
TOTAL_BG = HexColor("#0F2744")
ORANGE = HexColor("#E07A2F")

W, H = A4
GRAND_TOTAL = 12_420_000


def fcfa(n: int) -> str:
    return f"{n:,}".replace(",", " ") + " F CFA"


class ColoredRule(Flowable):
    def __init__(self, width, color=GOLD, thickness=1.4):
        super().__init__()
        self.width = width
        self.color = color
        self.thickness = thickness
        self.height = thickness

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, 0, self.width, 0)


def draw_header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY_DEEP)
    canvas.rect(0, H - 34 * mm, W, 34 * mm, fill=1, stroke=0)
    canvas.setFillColor(GREEN)
    canvas.rect(0, H - 36 * mm, W, 2 * mm, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, H - 37 * mm, W, 1 * mm, fill=1, stroke=0)
    canvas.setFillColor(ORANGE)
    canvas.rect(0, H - 37.8 * mm, 40 * mm, 0.8 * mm, fill=1, stroke=0)

    cx, cy, r = 20 * mm, H - 17.5 * mm, 10 * mm
    canvas.setFillColor(GOLD)
    canvas.circle(cx, cy, r, fill=1, stroke=0)
    canvas.setFillColor(NAVY_DEEP)
    canvas.circle(cx, cy, r - 2, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.setFont("Inter-Bd", 7.5)
    canvas.drawCentredString(cx, cy + 1, "OPVN")
    canvas.setFont("Inter", 4.4)
    canvas.setFillColor(HexColor("#E8D48A"))
    canvas.drawCentredString(cx, cy - 6.2, "NIGER")

    canvas.setFillColor(white)
    canvas.setFont("Inter-Bd", 12.5)
    canvas.drawString(34 * mm, H - 14 * mm, "FACTURE PRO FORMA")
    canvas.setFont("Inter", 7.6)
    canvas.setFillColor(HexColor("#C9D4E3"))
    canvas.drawString(34 * mm, H - 20 * mm, "Tenues de travail personnalisées — logo OPVN sur chaque pièce")
    canvas.drawString(34 * mm, H - 25.5 * mm, "Réf. commande interne : habillage du personnel — 14/09/2026")

    canvas.setFillColor(GOLD)
    canvas.setFont("Inter-Bd", 8)
    canvas.drawRightString(W - 15 * mm, H - 13.5 * mm, "N° FP-2026-001")
    canvas.setFillColor(HexColor("#C9D4E3"))
    canvas.setFont("Inter", 7.6)
    canvas.drawRightString(W - 15 * mm, H - 19.5 * mm, "Date : 16 septembre 2026")
    canvas.drawRightString(W - 15 * mm, H - 25 * mm, "Validité : 16 octobre 2026  ·  XOF")

    canvas.setFillColor(NAVY_DEEP)
    canvas.rect(0, 0, W, 12 * mm, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, 12 * mm, W, 0.8 * mm, fill=1, stroke=0)
    canvas.setFillColor(HexColor("#C9D4E3"))
    canvas.setFont("Inter", 6.8)
    canvas.drawString(
        15 * mm,
        5.2 * mm,
        "Document non fiscal — facture pro forma. N'ouvre pas droit à déduction de TVA.",
    )
    canvas.drawRightString(W - 15 * mm, 5.2 * mm, f"Page {doc.page} / 2")
    canvas.restoreState()


def styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H", fontName="Inter-Bd", fontSize=9, textColor=NAVY, spaceAfter=2.2 * mm, spaceBefore=2 * mm, leading=12))
    ss.add(ParagraphStyle("Body", fontName="Inter", fontSize=8, textColor=NAVY_DEEP, leading=11.2, alignment=TA_JUSTIFY))
    ss.add(ParagraphStyle("Small", fontName="Inter", fontSize=7, textColor=MUTED, leading=9.6))
    ss.add(ParagraphStyle("Cell", fontName="Inter", fontSize=7.5, textColor=NAVY_DEEP, leading=10.2))
    ss.add(ParagraphStyle("CellBd", fontName="Inter-Bd", fontSize=7.6, textColor=NAVY_DEEP, leading=10.2))
    ss.add(ParagraphStyle("Th", fontName="Inter-Bd", fontSize=6.8, textColor=white, leading=9, alignment=TA_CENTER))
    ss.add(ParagraphStyle("Right", fontName="Inter", fontSize=7.5, textColor=NAVY_DEEP, alignment=TA_RIGHT, leading=10.2))
    ss.add(ParagraphStyle("RightBd", fontName="Inter-Bd", fontSize=7.5, textColor=NAVY_DEEP, alignment=TA_RIGHT, leading=10.2))
    ss.add(ParagraphStyle("Center", fontName="Inter", fontSize=7.6, textColor=NAVY_DEEP, alignment=TA_CENTER, leading=10.2))
    ss.add(ParagraphStyle("CenterW", fontName="Inter-Bd", fontSize=7.6, textColor=white, alignment=TA_CENTER, leading=10.2))
    ss.add(ParagraphStyle("PartyTitle", fontName="Inter-Bd", fontSize=6.6, textColor=GOLD, leading=9, spaceAfter=0.8 * mm))
    ss.add(ParagraphStyle("PartyName", fontName="Inter-Bd", fontSize=8.6, textColor=NAVY, leading=11, spaceAfter=0.6 * mm))
    ss.add(ParagraphStyle("PartyBody", fontName="Inter", fontSize=7.3, textColor=NAVY_DEEP, leading=10.2))
    ss.add(ParagraphStyle("Note", fontName="Inter", fontSize=7.1, textColor=MUTED, leading=10, alignment=TA_JUSTIFY))
    ss.add(ParagraphStyle("TotalWords", fontName="Inter-Md", fontSize=8, textColor=NAVY, leading=11.2))
    ss.add(ParagraphStyle("Sig", fontName="Inter", fontSize=7.6, textColor=NAVY_DEEP, alignment=TA_CENTER, leading=10.5))
    return ss


def party_box(title, name, body, s):
    data = [
        [Paragraph(title, s["PartyTitle"])],
        [Paragraph(name, s["PartyName"])],
        [Paragraph(body, s["PartyBody"])],
    ]
    t = Table(data, colWidths=[84 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), SAND),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (0, 0), 6),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (0, 0), (-1, -1), 0.4, LINE),
            ]
        )
    )
    return t


def build():
    s = styles()
    doc = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=42 * mm,
        bottomMargin=16 * mm,
        title="Facture pro forma FP-2026-001 — Tenues de travail OPVN",
        author="Abou Sayabou SAMAILA ALASSANE",
        subject="Fourniture de tenues de travail avec logo OPVN",
    )

    story = []

    emetteur = party_box(
        "ÉMETTEUR",
        "Abou Sayabou SAMAILA ALASSANE",
        "Confection &amp; fourniture de tenues professionnelles<br/>Niamey — République du Niger<br/>E-mail : abousayabou92@gmail.com<br/>NIF / RCCM : à renseigner sur la facture définitive",
        s,
    )
    client = party_box(
        "CLIENT / DESTINATAIRE",
        "Office des Produits Vivriers du Niger (OPVN)",
        "Établissement public à caractère industriel et commercial<br/>BP 474 — Niamey, République du Niger<br/>Tél. : +227 20 73 23 16 / 20 73 51 68<br/>Objet : habillage du personnel (logo OPVN)",
        s,
    )
    parties = Table([[emetteur, client]], colWidths=[90 * mm, 90 * mm])
    parties.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (0, 0), 4 * mm),
                ("LEFTPADDING", (1, 0), (1, 0), 4 * mm),
                ("RIGHTPADDING", (1, 0), (1, 0), 0),
            ]
        )
    )
    story.append(parties)
    story.append(Spacer(1, 3.2 * mm))
    story.append(
        Paragraph(
            "Proposition commerciale pour la confection et la livraison de tenues de travail du personnel de l'OPVN. "
            "<b>Toutes les pièces portent le logo OPVN</b> (broderie ou sérigraphie selon le support). "
            "Prix unitaires communiqués le 14 septembre 2026.",
            s["Body"],
        )
    )
    story.append(Paragraph("1. Désignation des fournitures", s["H"]))
    story.append(ColoredRule(180 * mm))
    story.append(Spacer(1, 1.8 * mm))

    lines = [
        (
            "01",
            "Tenue de base : T-shirt + pantalon + casquette, logo OPVN",
            "Plantons, manœuvres, chauffeurs et gardiens — coloris selon fonction (page 2).",
            200,
            30_000,
        ),
        (
            "02",
            "Contre-veste marron, logo OPVN",
            "Second complet des plantons et des gardiens.",
            108,
            35_000,
        ),
        (
            "03",
            "Bleu de mécanicien (complet), logo OPVN",
            "Effectif communiqué pour les bleus de mécanicien (24). Complément manœuvres à confirmer.",
            24,
            20_000,
        ),
        (
            "04",
            "Complet jalabiya khaki, logo OPVN",
            "Chauffeurs (2e complet) et graisseurs — dénommé « poches » dans la demande.",
            80,
            27_000,
        ),
    ]

    header = [
        Paragraph("N°", s["Th"]),
        Paragraph("DÉSIGNATION", s["Th"]),
        Paragraph("QTÉ", s["Th"]),
        Paragraph("P.U.", s["Th"]),
        Paragraph("MONTANT", s["Th"]),
    ]
    data = [header]
    for num, title, detail, qty, pu in lines:
        montant = qty * pu
        data.append(
            [
                Paragraph(num, s["Center"]),
                [Paragraph(title, s["CellBd"]), Paragraph(detail, s["Small"])],
                Paragraph(str(qty), s["Center"]),
                Paragraph(fcfa(pu), s["Right"]),
                Paragraph(fcfa(montant), s["RightBd"]),
            ]
        )

    table = Table(data, colWidths=[12 * mm, 90 * mm, 16 * mm, 31 * mm, 31 * mm], repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, 0), 5),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
        ("TOPPADDING", (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.3, LINE),
        ("BOX", (0, 0), (-1, -1), 0.7, NAVY),
    ]
    for i in range(1, len(data)):
        style_cmds.append(("BACKGROUND", (0, i), (-1, i), IVORY if i % 2 else ROW_ALT))
    table.setStyle(TableStyle(style_cmds))
    story.append(table)
    story.append(Spacer(1, 2.8 * mm))

    recap = Table(
        [
            [Paragraph("Sous-total", s["Cell"]), Paragraph(fcfa(GRAND_TOTAL), s["RightBd"])],
            [Paragraph("Remise", s["Cell"]), Paragraph("0 F CFA", s["Right"])],
            [Paragraph("TVA (à confirmer)*", s["Cell"]), Paragraph("Non ventilée", s["Right"])],
            [
                Paragraph("NET À PAYER", ParagraphStyle("tw", parent=s["CellBd"], textColor=white, fontSize=8.4)),
                Paragraph(fcfa(GRAND_TOTAL), ParagraphStyle("tr", parent=s["RightBd"], textColor=GOLD, fontSize=9.2)),
            ],
        ],
        colWidths=[48 * mm, 42 * mm],
        hAlign="RIGHT",
    )
    recap.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 2), SAND),
                ("BACKGROUND", (0, 3), (-1, 3), TOTAL_BG),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, 2), 3.5),
                ("BOTTOMPADDING", (0, 0), (-1, 2), 3.5),
                ("TOPPADDING", (0, 3), (-1, 3), 6),
                ("BOTTOMPADDING", (0, 3), (-1, 3), 6),
                ("BOX", (0, 0), (-1, -1), 0.5, NAVY),
                ("LINEBELOW", (0, 0), (-1, 2), 0.25, LINE),
            ]
        )
    )
    story.append(recap)
    story.append(Spacer(1, 2.6 * mm))
    story.append(
        Paragraph(
            "Arrêtée la présente facture pro forma à la somme de : "
            "<b>DOUZE MILLIONS QUATRE CENT VINGT MILLE (12 420 000) FRANCS CFA</b>.",
            s["TotalWords"],
        )
    )
    story.append(Spacer(1, 1.4 * mm))
    story.append(
        Paragraph(
            "* Prix unitaires du 14/09/2026, exprimés en FCFA. La TVA nigérienne (19 %) sera ventilée "
            "sur la facture définitive si l'émetteur y est assujetti ; sinon le net à payer reste 12 420 000 F CFA.",
            s["Note"],
        )
    )
    story.append(Paragraph("2. Conditions commerciales", s["H"]))
    story.append(ColoredRule(180 * mm))
    story.append(Spacer(1, 1.6 * mm))

    conditions = [
        ["Validité", "30 jours à compter du 16 septembre 2026"],
        ["Délai", "15 à 21 jours ouvrés après tailles, logo et acompte"],
        ["Marquage", "Logo OPVN sur toutes les pièces"],
        ["Acompte", "50 % à la commande — 6 210 000 F CFA"],
        ["Solde", "50 % à la livraison à Niamey — 6 210 000 F CFA"],
        ["Livraison", "Siège OPVN Niamey, franco de port"],
        ["Tailles", "Grille S à 4XL à fournir par l'OPVN avant production"],
        ["Retouches", "Ajustements mineurs inclus sous 7 jours"],
    ]
    # 2 colonnes de 4 lignes
    paired = []
    for i in range(0, 8, 2):
        paired.append(
            [
                Paragraph(conditions[i][0], s["CellBd"]),
                Paragraph(conditions[i][1], s["Cell"]),
                Paragraph(conditions[i + 1][0], s["CellBd"]),
                Paragraph(conditions[i + 1][1], s["Cell"]),
            ]
        )
    cond = Table(paired, colWidths=[22 * mm, 68 * mm, 24 * mm, 66 * mm])
    cond.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), SAND),
                ("BACKGROUND", (2, 0), (2, -1), SAND),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.3, LINE),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3.6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3.6),
            ]
        )
    )
    story.append(cond)
    story.append(Spacer(1, 4 * mm))

    sig = Table(
        [
            [
                Paragraph("Pour le client — OPVN<br/><font color='#5C6570' size='7'>Lu et accepté, date et cachet</font>", s["Sig"]),
                Paragraph("Pour l'émetteur<br/><font color='#5C6570' size='7'>Abou Sayabou SAMAILA ALASSANE</font>", s["Sig"]),
            ],
            [
                Paragraph("<br/><br/>______________________________", s["Sig"]),
                Paragraph("<br/><br/>______________________________", s["Sig"]),
            ],
        ],
        colWidths=[90 * mm, 90 * mm],
    )
    sig.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (0, 0), (0, -1), 0.4, LINE),
                ("BOX", (1, 0), (1, -1), 0.4, LINE),
                ("BACKGROUND", (0, 0), (-1, -1), IVORY),
                ("TOPPADDING", (0, 0), (-1, 0), 6),
                ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(sig)

    # PAGE 2
    story.append(PageBreak())
    story.append(Paragraph("3. Cahier des spécifications par fonction", s["H"]))
    story.append(ColoredRule(180 * mm))
    story.append(Spacer(1, 1.6 * mm))
    story.append(
        Paragraph(
            "Chaque agent reçoit les pièces décrites ci-dessous. Les coloris sont ceux du donneur d'ordre. "
            "<b>Le logo OPVN est apposé sur l'ensemble des articles.</b> Les quantités facturées (lignes 01 à 04) "
            "suivent les effectifs communiqués, et non un décompte nominatif par service.",
            s["Body"],
        )
    )
    story.append(Spacer(1, 3 * mm))

    spec_header = [
        Paragraph("FONCTION", s["Th"]),
        Paragraph("1er COMPLET", s["Th"]),
        Paragraph("2e COMPLET / COMPLÉMENT", s["Th"]),
        Paragraph("LIGNES", s["Th"]),
    ]
    specs = [
        ["Planton", "T-shirt <b>vert</b>, pantalon <b>noir</b>, casquette <b>noire</b>", "Contre-veste <b>marron</b>", "01 + 02"],
        ["Manœuvre", "T-shirt <b>vert</b>, pantalon <b>noir</b>, casquette <b>noire</b>", "Bleu de mécanicien", "01 + 03"],
        ["Chauffeur", "T-shirt <b>orange</b>, pantalon <b>noir</b>, casquette <b>noire</b>", "Jalabiya <b>khaki</b>", "01 + 04"],
        ["Gardien", "T-shirt <b>bleu marine</b>, pantalon <b>noir</b>", "Contre-veste <b>marron</b>", "01 + 02"],
        ["Mécanicien", "Bleu de travail", "Bleu de travail (2e complet identique)", "03"],
        ["Graisseur", "—", "Jalabiya <b>khaki</b> (dénommé « poches »)", "04"],
    ]
    spec_data = [spec_header]
    for row in specs:
        spec_data.append([Paragraph(c, s["Cell"] if i else s["CellBd"]) for i, c in enumerate(row)])

    spec_style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.3, LINE),
        ("BOX", (0, 0), (-1, -1), 0.7, NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN", (3, 1), (3, -1), "CENTER"),
    ]
    accents = [GREEN, HexColor("#2E7D4F"), ORANGE, NAVY, HexColor("#1E4D8C"), HexColor("#8B6914")]
    for i, color in enumerate(accents, start=1):
        spec_style.append(("BACKGROUND", (0, i), (-1, i), IVORY if i % 2 else ROW_ALT))
        spec_style.append(("BACKGROUND", (0, i), (0, i), color))
        spec_style.append(("TEXTCOLOR", (0, i), (0, i), white))
        spec_data[i][0] = Paragraph(
            specs[i - 1][0].upper(),
            ParagraphStyle(f"fn{i}", parent=s["CenterW"], fontSize=7.2),
        )
    spec_t = Table(spec_data, colWidths=[32 * mm, 62 * mm, 62 * mm, 24 * mm])
    spec_t.setStyle(TableStyle(spec_style))
    story.append(spec_t)
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("4. Récapitulatif des effectifs facturés", s["H"]))
    story.append(ColoredRule(180 * mm))
    story.append(Spacer(1, 1.8 * mm))

    recap_head = [
        Paragraph("FAMILLE D'ARTICLES", s["Th"]),
        Paragraph("EFFECTIF", s["Th"]),
        Paragraph("P.U.", s["Th"]),
        Paragraph("MONTANT", s["Th"]),
        Paragraph("%", s["Th"]),
    ]
    recap_src = [
        ("Casquette + T-shirt + pantalon", 200, 30_000),
        ("Contre-vestes marron", 108, 35_000),
        ("Bleus de mécanicien", 24, 20_000),
        ("Jalabiyas khaki (chauffeurs &amp; graisseurs)", 80, 27_000),
    ]
    recap_rows = [recap_head]
    for label, qty, pu in recap_src:
        m = qty * pu
        recap_rows.append(
            [
                Paragraph(label, s["Cell"]),
                Paragraph(str(qty), s["Center"]),
                Paragraph(fcfa(pu), s["Right"]),
                Paragraph(fcfa(m), s["RightBd"]),
                Paragraph(f"{m / GRAND_TOTAL * 100:.1f} %", s["Center"]),
            ]
        )
    recap_rows.append(
        [
            Paragraph("TOTAL GÉNÉRAL", s["CellBd"]),
            Paragraph("412 unités", s["Center"]),
            Paragraph("—", s["Center"]),
            Paragraph(fcfa(GRAND_TOTAL), s["RightBd"]),
            Paragraph("100 %", s["Center"]),
        ]
    )
    recap_t = Table(recap_rows, colWidths=[72 * mm, 26 * mm, 32 * mm, 34 * mm, 16 * mm])
    recap_style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("BACKGROUND", (0, -1), (-1, -1), SAND),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.3, LINE),
        ("BOX", (0, 0), (-1, -1), 0.7, NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i in range(1, len(recap_rows) - 1):
        recap_style.append(("BACKGROUND", (0, i), (-1, i), IVORY if i % 2 else ROW_ALT))
    recap_t.setStyle(TableStyle(recap_style))
    story.append(recap_t)
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("5. Notes de lecture", s["H"]))
    story.append(ColoredRule(180 * mm))
    story.append(Spacer(1, 1.8 * mm))
    notes = [
        "<b>Cohérence des effectifs.</b> 412 unités = 200 + 108 + 24 + 80. Un même agent peut figurer sur plusieurs lignes s'il reçoit une tenue de base et un second complet.",
        "<b>Plantons et manœuvres</b> : même 1er complet (T-shirt vert, pantalon noir, casquette noire). Différence au 2e complet : contre-veste marron (planton) vs bleu de mécanicien (manœuvre). Si les manœuvres doivent aussi recevoir un bleu, un complément d'effectif sera à chiffrer : la ligne 03 ne couvre que 24 bleus.",
        "<b>Gardiens</b> : T-shirt bleu marine et pantalon noir ; second complet en contre-veste marron (casquette non mentionnée pour cette fonction).",
        "<b>Mécaniciens</b> : bleu de travail pour les deux complets. Effectif facturé : 24 bleus à 20 000 F CFA.",
        "<b>Chauffeurs et graisseurs</b> : jalabiya khaki (80 unités à 27 000 F CFA). Les chauffeurs ont en plus la tenue T-shirt orange / pantalon noir / casquette noire.",
        "<b>Logo.</b> Reproduction conforme du logo officiel de l'OPVN, fichier vectoriel à transmettre par le client avant production.",
        "<b>État nominatif.</b> Un listing par service (nom, fonction, tailles) est recommandé à la commande pour figer la production.",
    ]
    for n in notes:
        story.append(Paragraph("• " + n, s["Note"]))
        story.append(Spacer(1, 1.4 * mm))

    story.append(Spacer(1, 3 * mm))
    story.append(
        Paragraph(
            "Fait à Niamey, le 16 septembre 2026. Cette pro forma est une offre de prix, non une facture définitive. "
            "L'acceptation par bon de commande, paraphe ou ordre de service de l'OPVN vaut engagement aux conditions ci-dessus.",
            s["Body"],
        )
    )

    doc.build(story, onFirstPage=draw_header_footer, onLaterPages=draw_header_footer)
    return OUTPUT


if __name__ == "__main__":
    path = build()
    print(f"PDF généré : {path}")
    print("Net à payer : 12 420 000 FCFA")
