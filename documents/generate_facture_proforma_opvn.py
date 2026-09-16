#!/usr/bin/env python3
"""Génère la facture proforma OPVN au format PDF."""

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


OUTPUT = Path(__file__).with_name("facture_proforma_opvn.pdf")
GREEN = colors.HexColor("#166534")
DARK_GREEN = colors.HexColor("#14532D")
LIGHT_GREEN = colors.HexColor("#ECFDF5")
ORANGE = colors.HexColor("#EA580C")
BROWN = colors.HexColor("#7C2D12")
NAVY = colors.HexColor("#172554")
INK = colors.HexColor("#1F2937")
MUTED = colors.HexColor("#6B7280")
LINE = colors.HexColor("#D1D5DB")
PALE = colors.HexColor("#F8FAFC")


pdfmetrics.registerFont(
    TTFont("NotoSans", "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf")
)
pdfmetrics.registerFont(
    TTFont("NotoSans-Bold", "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf")
)


styles = getSampleStyleSheet()
styles.add(
    ParagraphStyle(
        name="BodyNoto",
        fontName="NotoSans",
        fontSize=8.5,
        leading=12,
        textColor=INK,
    )
)
styles.add(
    ParagraphStyle(
        name="SmallNoto",
        parent=styles["BodyNoto"],
        fontSize=7.4,
        leading=10,
        textColor=MUTED,
    )
)
styles.add(
    ParagraphStyle(
        name="SectionNoto",
        fontName="NotoSans-Bold",
        fontSize=11,
        leading=14,
        textColor=DARK_GREEN,
        spaceAfter=6,
    )
)
styles.add(
    ParagraphStyle(
        name="TitleNoto",
        fontName="NotoSans-Bold",
        fontSize=20,
        leading=23,
        textColor=DARK_GREEN,
        alignment=TA_RIGHT,
    )
)
styles.add(
    ParagraphStyle(
        name="RightNoto",
        parent=styles["BodyNoto"],
        alignment=TA_RIGHT,
    )
)
styles.add(
    ParagraphStyle(
        name="CenterNoto",
        parent=styles["BodyNoto"],
        alignment=TA_CENTER,
    )
)


def p(text: str, style: str = "BodyNoto") -> Paragraph:
    return Paragraph(text, styles[style])


def money(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def page_chrome(canvas, doc) -> None:
    canvas.saveState()
    width, height = A4
    canvas.setStrokeColor(GREEN)
    canvas.setLineWidth(1.5)
    canvas.line(18 * mm, height - 13 * mm, width - 18 * mm, height - 13 * mm)
    canvas.setFont("NotoSans", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "Facture proforma — Fourniture de tenues professionnelles OPVN")
    canvas.drawRightString(
        width - 18 * mm, 10 * mm, f"Page {doc.page} / 2"
    )
    canvas.restoreState()


def build_pdf() -> None:
    doc = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=17 * mm,
        title="Facture proforma OPVN",
        author="Fournisseur à compléter",
        subject="Fourniture de tenues professionnelles avec logo OPVN",
    )

    story = []

    identity = Table(
        [
            [
                p(
                    "<font color='#166534' size='18'><b>OPVN</b></font><br/>"
                    "<font color='#6B7280' size='7'>TENUES PROFESSIONNELLES</font>"
                ),
                p("FACTURE<br/>PROFORMA", "TitleNoto"),
            ]
        ],
        colWidths=[82 * mm, 92 * mm],
    )
    identity.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.extend([identity, Spacer(1, 5 * mm)])

    supplier = (
        "<b>FOURNISSEUR</b><br/>"
        "Raison sociale : <b>À compléter</b><br/>"
        "Adresse / téléphone : À compléter<br/>"
        "NIF / RCCM : À compléter"
    )
    client = (
        "<b>DESTINATAIRE</b><br/>"
        "<b>Office des Produits Vivriers du Niger (OPVN)</b><br/>"
        "Adresse : À compléter<br/>"
        "Référence client : À compléter"
    )
    parties = Table(
        [[p(supplier), p(client)]],
        colWidths=[85 * mm, 85 * mm],
        hAlign="LEFT",
    )
    parties.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PALE),
                ("BOX", (0, 0), (-1, -1), 0.7, LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.7, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.extend([parties, Spacer(1, 5 * mm)])

    meta = Table(
        [
            [p("<b>N° PROFORMA</b>"), p("FP-OPVN-2026-0916-001")],
            [p("<b>Date d’émission</b>"), p("16 septembre 2026")],
            [p("<b>Validité de l’offre</b>"), p("À compléter")],
            [p("<b>Devise</b>"), p("Franc CFA (FCFA)")],
        ],
        colWidths=[48 * mm, 122 * mm],
    )
    meta.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.7, LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_GREEN),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend(
        [
            meta,
            Spacer(1, 5 * mm),
            p("OBJET DE L’OFFRE", "SectionNoto"),
            p(
                "Fourniture de tenues professionnelles personnalisées avec le "
                "<b>logo de l’OPVN</b>, conformément aux profils et coloris détaillés "
                "dans la présente proforma."
            ),
            Spacer(1, 5 * mm),
        ]
    )

    quantities = [200, 108, 24, 80]
    unit_prices = [30_000, 35_000, 20_000, 27_000]
    descriptions = [
        "<b>Lot casquette, T-shirt et pantalon</b><br/>"
        "<font size='7' color='#6B7280'>Tenue par personne, coloris selon profil</font>",
        "<b>Lot avec contre-veste</b><br/>"
        "<font size='7' color='#6B7280'>Contre-veste marron selon profil concerné</font>",
        "<b>Bleu de travail mécanicien</b><br/>"
        "<font size='7' color='#6B7280'>Deux complets mentionnés par mécanicien ; détail à confirmer</font>",
        "<b>Tenue avec poches</b><br/>"
        "<font size='7' color='#6B7280'>Chauffeurs et graisseurs ; composition finale à confirmer</font>",
    ]
    rows = [
        [
            p("<font color='white'><b>DÉSIGNATION</b></font>", "CenterNoto"),
            p("<font color='white'><b>QTÉ</b></font>", "CenterNoto"),
            p("<font color='white'><b>UNITÉ</b></font>", "CenterNoto"),
            p("<font color='white'><b>PU (FCFA)</b></font>", "CenterNoto"),
            p("<font color='white'><b>MONTANT (FCFA)</b></font>", "CenterNoto"),
        ]
    ]
    for description, quantity, unit_price in zip(
        descriptions, quantities, unit_prices
    ):
        rows.append(
            [
                p(description),
                p(str(quantity), "CenterNoto"),
                p("personne", "CenterNoto"),
                p(money(unit_price), "RightNoto"),
                p(money(quantity * unit_price), "RightNoto"),
            ]
        )

    items = Table(
        rows,
        colWidths=[75 * mm, 15 * mm, 22 * mm, 27 * mm, 35 * mm],
        repeatRows=1,
    )
    items.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), DARK_GREEN),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.7, LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("BACKGROUND", (0, 2), (-1, 2), PALE),
                ("BACKGROUND", (0, 4), (-1, 4), PALE),
            ]
        )
    )
    story.extend([items, Spacer(1, 5 * mm)])

    total = sum(q * price for q, price in zip(quantities, unit_prices))
    totals = Table(
        [
            [p("<b>Sous-total</b>"), p(f"<b>{money(total)} FCFA</b>", "RightNoto")],
            [p("TVA / régime fiscal"), p("À compléter", "RightNoto")],
            [
                p("<font color='white'><b>MONTANT TOTAL PROPOSÉ</b></font>"),
                p(
                    f"<font color='white'><b>{money(total)} FCFA</b></font>",
                    "RightNoto",
                ),
            ],
        ],
        colWidths=[87 * mm, 45 * mm],
        hAlign="RIGHT",
    )
    totals.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.7, LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
                ("BACKGROUND", (0, 2), (-1, 2), DARK_GREEN),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.extend(
        [
            totals,
            Spacer(1, 4 * mm),
            KeepTogether(
                [
                    p(
                        "<b>Arrêtée la présente proforma à la somme de :</b> "
                        "douze millions quatre cent vingt mille francs CFA."
                    ),
                    Spacer(1, 2 * mm),
                    p(
                        "Le montant ci-dessus résulte strictement des quantités et prix "
                        "unitaires communiqués. La TVA n’étant pas renseignée, elle n’est "
                        "ni ajoutée ni réputée incluse.",
                        "SmallNoto",
                    ),
                ]
            ),
        ]
    )

    story.append(PageBreak())
    story.extend(
        [
            p("SPÉCIFICATIONS DES TENUES", "SectionNoto"),
            p(
                "Les compositions suivantes reprennent les besoins transmis. "
                "Les tailles, matières, techniques de marquage et répartitions exactes "
                "seront validées avant production.",
                "SmallNoto",
            ),
            Spacer(1, 5 * mm),
        ]
    )

    specs = [
        (
            "PLANTONS",
            GREEN,
            "T-shirt vert, pantalon noir, casquette noire et contre-veste marron.",
        ),
        (
            "MANŒUVRES",
            GREEN,
            "T-shirt vert, pantalon noir, casquette noire ; bleu de travail type "
            "mécanicien mentionné dans le besoin, à confirmer.",
        ),
        (
            "CHAUFFEURS",
            ORANGE,
            "T-shirt orange, pantalon noir et casquette noire. Deuxième complet : "
            "jalabia khaki.",
        ),
        (
            "GARDIENS",
            NAVY,
            "T-shirt bleu marine et pantalon noir. Deuxième complet : contre-veste marron.",
        ),
        (
            "MÉCANICIENS",
            colors.HexColor("#1D4ED8"),
            "Bleu de travail pour les deux complets.",
        ),
        (
            "GRAISSEURS",
            BROWN,
            "Tenue avec poches, comprise dans le lot chauffeurs et graisseurs ; "
            "composition et coloris à confirmer.",
        ),
    ]

    spec_rows = []
    for label, color, description in specs:
        spec_rows.append(
            [
                Table(
                    [[""]],
                    colWidths=[5 * mm],
                    rowHeights=[12 * mm],
                    style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), color)]),
                ),
                p(f"<b>{label}</b><br/>{description}"),
            ]
        )

    spec_table = Table(spec_rows, colWidths=[9 * mm, 161 * mm])
    spec_table.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.7, LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("BACKGROUND", (0, 1), (-1, 1), PALE),
                ("BACKGROUND", (0, 3), (-1, 3), PALE),
                ("BACKGROUND", (0, 5), (-1, 5), PALE),
            ]
        )
    )
    story.extend(
        [
            spec_table,
            Spacer(1, 6 * mm),
            p("MARQUAGE COMMUN", "SectionNoto"),
            Table(
                [
                    [
                        p(
                            "<b>Logo OPVN inclus sur toutes les tenues.</b><br/>"
                            "Emplacement, dimensions, couleurs et technique "
                            "(broderie, sérigraphie ou transfert) à valider sur un bon à tirer."
                        )
                    ]
                ],
                colWidths=[170 * mm],
                style=TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREEN),
                        ("BOX", (0, 0), (-1, -1), 1, GREEN),
                        ("LEFTPADDING", (0, 0), (-1, -1), 10),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                        ("TOPPADDING", (0, 0), (-1, -1), 9),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                    ]
                ),
            ),
            Spacer(1, 6 * mm),
            p("POINTS À CONFIRMER AVANT COMMANDE", "SectionNoto"),
        ]
    )

    confirmations = [
        "Coordonnées légales et bancaires du fournisseur.",
        "Répartition des 200, 108, 24 et 80 bénéficiaires par profil et par taille.",
        "Nombre exact de pièces par personne, notamment pour les deuxièmes complets.",
        "Composition précise du lot « tenue avec poches » pour chauffeurs et graisseurs.",
        "Matières, grammages, finitions, échantillons et technique de pose du logo.",
        "Régime fiscal, délai et lieu de livraison, modalités de paiement et validité de l’offre.",
    ]
    for index, item in enumerate(confirmations, 1):
        story.append(p(f"<b>{index}.</b>&nbsp;&nbsp;{item}"))
        story.append(Spacer(1, 1.4 * mm))

    story.extend(
        [
            Spacer(1, 4 * mm),
            p("ACCEPTATION DE L’OFFRE", "SectionNoto"),
            Table(
                [
                    [
                        p("<b>Pour le fournisseur</b><br/><br/><br/>Nom, cachet et signature"),
                        p("<b>Bon pour accord — OPVN</b><br/><br/><br/>Nom, date, cachet et signature"),
                    ]
                ],
                colWidths=[85 * mm, 85 * mm],
                rowHeights=[31 * mm],
                style=TableStyle(
                    [
                        ("BOX", (0, 0), (-1, -1), 0.7, LINE),
                        ("INNERGRID", (0, 0), (-1, -1), 0.7, LINE),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 9),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                        ("TOPPADDING", (0, 0), (-1, -1), 9),
                    ]
                ),
            ),
            Spacer(1, 4 * mm),
            p(
                "Document commercial indicatif, non constitutif d’une facture définitive. "
                "La commande devient ferme après validation écrite des spécifications et conditions.",
                "SmallNoto",
            ),
        ]
    )

    doc.build(story, onFirstPage=page_chrome, onLaterPages=page_chrome)


if __name__ == "__main__":
    build_pdf()
    print(OUTPUT)
