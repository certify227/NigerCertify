#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Moteur PDF — examens blancs Niger Certify (document propriétaire)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from reportlab.lib.colors import Color, HexColor, white, black
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    ListFlowable,
    ListItem,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)

# Couleurs inspirées du drapeau du Niger
ORANGE = HexColor("#E05206")
ORANGE_DARK = HexColor("#B33D00")
GREEN = HexColor("#0A8A3A")
GREEN_DARK = HexColor("#066B2C")
NAVY = HexColor("#1A2332")
SLATE = HexColor("#3D4A5C")
CREAM = HexColor("#FFF8F2")
PALE_ORANGE = HexColor("#FDE8D8")
PALE_GREEN = HexColor("#E7F6EC")
CODE_BG = HexColor("#F4F1EC")
LINE = HexColor("#D9D0C7")
WATERMARK = Color(0.88, 0.32, 0.02, alpha=0.055)

FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")
YEAR = date.today().year
OWNER = "Niger Certify"
COPYRIGHT = (
    f"© {YEAR} {OWNER} — Document propriétaire — Reproduction, diffusion "
    "ou revente interdites sans autorisation écrite."
)


def register_fonts() -> None:
    pdfmetrics.registerFont(TTFont("NC", str(FONT_DIR / "DejaVuSans.ttf")))
    pdfmetrics.registerFont(TTFont("NC-Bold", str(FONT_DIR / "DejaVuSans-Bold.ttf")))
    pdfmetrics.registerFont(TTFont("NC-Mono", str(FONT_DIR / "DejaVuSansMono.ttf")))
    pdfmetrics.registerFont(
        TTFont("NC-Mono-Bold", str(FONT_DIR / "DejaVuSansMono-Bold.ttf"))
    )


def esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def styles() -> dict[str, ParagraphStyle]:
    return {
        "cover_kicker": ParagraphStyle(
            "cover_kicker",
            fontName="NC-Bold",
            fontSize=9,
            textColor=ORANGE_DARK,
            alignment=TA_CENTER,
            letterSpacing=1.4,
            spaceAfter=4,
        ),
        "cover_brand": ParagraphStyle(
            "cover_brand",
            fontName="NC-Bold",
            fontSize=26,
            textColor=NAVY,
            alignment=TA_CENTER,
            leading=30,
            spaceAfter=2,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            fontName="NC",
            fontSize=10.5,
            textColor=SLATE,
            alignment=TA_CENTER,
            leading=14,
            spaceAfter=6,
        ),
        "cover_title": ParagraphStyle(
            "cover_title",
            fontName="NC-Bold",
            fontSize=20,
            textColor=white,
            alignment=TA_CENTER,
            leading=24,
        ),
        "cover_title2": ParagraphStyle(
            "cover_title2",
            fontName="NC",
            fontSize=12,
            textColor=white,
            alignment=TA_CENTER,
            leading=16,
        ),
        "h1": ParagraphStyle(
            "h1",
            fontName="NC-Bold",
            fontSize=13,
            textColor=GREEN_DARK,
            spaceBefore=8,
            spaceAfter=6,
            leading=16,
        ),
        "h2": ParagraphStyle(
            "h2",
            fontName="NC-Bold",
            fontSize=11,
            textColor=ORANGE_DARK,
            spaceBefore=8,
            spaceAfter=4,
            leading=14,
        ),
        "body": ParagraphStyle(
            "body",
            fontName="NC",
            fontSize=9.5,
            textColor=NAVY,
            alignment=TA_JUSTIFY,
            leading=13.2,
            spaceAfter=5,
        ),
        "body_left": ParagraphStyle(
            "body_left",
            fontName="NC",
            fontSize=9.5,
            textColor=NAVY,
            alignment=TA_LEFT,
            leading=13.2,
            spaceAfter=4,
        ),
        "small": ParagraphStyle(
            "small",
            fontName="NC",
            fontSize=8,
            textColor=SLATE,
            leading=11,
            alignment=TA_LEFT,
        ),
        "center_small": ParagraphStyle(
            "center_small",
            fontName="NC",
            fontSize=8,
            textColor=SLATE,
            alignment=TA_CENTER,
            leading=11,
        ),
        "qhead": ParagraphStyle(
            "qhead",
            fontName="NC-Bold",
            fontSize=10.5,
            textColor=NAVY,
            spaceBefore=2,
            spaceAfter=3,
            leading=14,
        ),
        "stem": ParagraphStyle(
            "stem",
            fontName="NC",
            fontSize=9.6,
            textColor=NAVY,
            alignment=TA_JUSTIFY,
            leading=13.4,
            spaceAfter=4,
        ),
        "choice": ParagraphStyle(
            "choice",
            fontName="NC",
            fontSize=9.3,
            textColor=NAVY,
            leading=12.8,
            leftIndent=8,
            spaceAfter=1.5,
        ),
        "note": ParagraphStyle(
            "note",
            fontName="NC",
            fontSize=8.5,
            textColor=SLATE,
            leading=11.5,
            alignment=TA_LEFT,
            spaceAfter=4,
        ),
        "footer": ParagraphStyle(
            "footer",
            fontName="NC",
            fontSize=6.8,
            textColor=SLATE,
            alignment=TA_LEFT,
            leading=8.5,
        ),
        "cell": ParagraphStyle(
            "cell",
            fontName="NC",
            fontSize=8.5,
            textColor=NAVY,
            leading=11.5,
        ),
        "cell_b": ParagraphStyle(
            "cell_b",
            fontName="NC-Bold",
            fontSize=8.5,
            textColor=NAVY,
            leading=11.5,
        ),
        "cell_w": ParagraphStyle(
            "cell_w",
            fontName="NC-Bold",
            fontSize=8.5,
            textColor=white,
            leading=11.5,
            alignment=TA_CENTER,
        ),
        "answer": ParagraphStyle(
            "answer",
            fontName="NC",
            fontSize=9,
            textColor=NAVY,
            leading=12.5,
            spaceAfter=3,
        ),
        "mono": ParagraphStyle(
            "mono",
            fontName="NC-Mono",
            fontSize=7.8,
            textColor=NAVY,
            leading=10.6,
            leftIndent=2,
        ),
    }


class CodeBox(Table):
    def __init__(self, text: str):
        clean = text.replace("\t", "    ").rstrip() + "\n"
        inner = Preformatted(clean, styles()["mono"])
        super().__init__([[inner]], colWidths=[170 * mm])
        self.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                    ("BOX", (0, 0), (-1, -1), 0.4, LINE),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )


def _draw_flag_bar(c, y, height=7 * mm):
    """Bandeau aux couleurs du drapeau du Niger (orange / blanc / vert, disque)."""
    w, _ = A4
    h3 = height / 3.0
    c.setFillColor(ORANGE)
    c.rect(0, y + 2 * h3, w, h3 + 0.15, fill=1, stroke=0)
    c.setFillColor(white)
    c.rect(0, y + h3, w, h3 + 0.15, fill=1, stroke=0)
    c.setFillColor(GREEN)
    c.rect(0, y, w, h3 + 0.15, fill=1, stroke=0)
    c.setFillColor(ORANGE)
    c.circle(w / 2.0, y + height / 2.0, max(h3 * 0.45, 0.7 * mm), fill=1, stroke=0)


def _draw_logo(c, x, y, size=16 * mm):
    """Monogramme NC dans un disque orange cerclé vert."""
    c.setFillColor(GREEN)
    c.circle(x, y, size / 2.0, fill=1, stroke=0)
    c.setFillColor(ORANGE)
    c.circle(x, y, size / 2.0 - 1.3 * mm, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("NC-Bold", size * 0.38)
    c.drawCentredString(x, y - size * 0.14, "NC")


def draw_cover_page(c, exam: dict) -> None:
    w, h = A4
    c.saveState()
    c.setFillColor(NAVY)
    c.rect(0, 0, w, h, fill=1, stroke=0)

    # Bandes drapeau en haut
    _draw_flag_bar(c, h - 8 * mm, 8 * mm)

    _draw_logo(c, w / 2.0, h - 38 * mm, 28 * mm)

    c.setFillColor(white)
    c.setFont("NC-Bold", 22)
    c.drawCentredString(w / 2.0, h - 58 * mm, "NIGER CERTIFY")
    c.setFont("NC", 10)
    c.setFillColor(HexColor("#F3D2BC"))
    c.drawCentredString(
        w / 2.0,
        h - 66 * mm,
        "Centre de formation et de certification professionnelle — Niamey",
    )

    # Cartouche titre
    c.setFillColor(ORANGE)
    c.roundRect(18 * mm, h - 118 * mm, w - 36 * mm, 38 * mm, 3 * mm, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("NC-Bold", 11)
    c.drawCentredString(w / 2.0, h - 88 * mm, "EXAMEN BLANC  ·  DOCUMENT PROPRIÉTAIRE")
    c.setFont("NC-Bold", 16)
    c.drawCentredString(w / 2.0, h - 98 * mm, exam["title"])
    c.setFont("NC", 10)
    c.drawCentredString(w / 2.0, h - 108 * mm, exam["subtitle"])

    # Badge version
    c.setFillColor(GREEN)
    bw = 48 * mm
    c.roundRect((w - bw) / 2.0, h - 136 * mm, bw, 12 * mm, 2 * mm, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("NC-Bold", 12)
    c.drawCentredString(w / 2.0, h - 132 * mm, f"VERSION {exam['version']}")

    # Métadonnées
    meta = [
        ("Code document", exam["code"]),
        ("Référentiel", "Cisco CCNA 200-301 v1.1"),
        ("Durée", exam["duration"]),
        ("Nombre de questions", str(exam["n_questions"])),
        ("Barème", exam["bareme"]),
        ("Seuil indicatif", exam["seuil"]),
        ("Langue", "Français"),
        ("Édition", f"{YEAR} — Usage pédagogique interne"),
    ]
    y = h - 155 * mm
    c.setFillColor(HexColor("#243044"))
    c.roundRect(22 * mm, y - 78 * mm, w - 44 * mm, 82 * mm, 3 * mm, fill=1, stroke=0)
    c.setFont("NC", 9.5)
    row_h = 9.2 * mm
    for i, (k, v) in enumerate(meta):
        yy = y - 6 * mm - i * row_h
        c.setFillColor(HexColor("#F3D2BC"))
        c.drawString(28 * mm, yy, k)
        c.setFillColor(white)
        c.setFont("NC-Bold", 9.5)
        c.drawRightString(w - 28 * mm, yy, v)
        c.setFont("NC", 9.5)
        if i < len(meta) - 1:
            c.setStrokeColor(HexColor("#3A4A63"))
            c.setLineWidth(0.3)
            c.line(28 * mm, yy - 3.2 * mm, w - 28 * mm, yy - 3.2 * mm)

    # Avertissement propriétaire
    c.setFillColor(PALE_ORANGE)
    c.roundRect(22 * mm, 28 * mm, w - 44 * mm, 28 * mm, 2.5 * mm, fill=1, stroke=0)
    c.setFillColor(ORANGE_DARK)
    c.setFont("NC-Bold", 8)
    c.drawCentredString(w / 2.0, 48 * mm, "PROPRIÉTÉ EXCLUSIVE — NIGER CERTIFY")
    c.setFont("NC", 7.4)
    c.setFillColor(NAVY)
    lines = [
        COPYRIGHT,
        "Ce sujet (énoncé, barème, mini-lab et identité visuelle) est protégé.",
        "Remise aux seuls candidats convoqués. Restitution obligatoire en fin d'épreuve.",
    ]
    for i, line in enumerate(lines):
        c.drawCentredString(w / 2.0, 42.5 * mm - i * 4.2 * mm, line)

    _draw_flag_bar(c, 0, 8 * mm)
    c.restoreState()


def _header_footer(c, doc, exam: dict) -> None:
    w, h = A4
    c.saveState()

    # Filigrane
    c.setFillColor(WATERMARK)
    c.saveState()
    c.translate(w / 2.0, h / 2.0)
    c.rotate(38)
    c.setFont("NC-Bold", 42)
    c.drawCentredString(0, 8, "NIGER CERTIFY")
    c.setFont("NC", 13)
    c.drawCentredString(0, -16, "DOCUMENT PROPRIÉTAIRE")
    c.restoreState()

    # En-tête
    c.setFillColor(NAVY)
    c.rect(0, h - 16 * mm, w, 16 * mm, fill=1, stroke=0)
    _draw_flag_bar(c, h - 20.2 * mm, 4.2 * mm)
    _draw_logo(c, 14 * mm, h - 8.2 * mm, 11 * mm)
    c.setFillColor(white)
    c.setFont("NC-Bold", 9)
    c.drawString(22 * mm, h - 7.2 * mm, "NIGER CERTIFY")
    c.setFont("NC", 7)
    c.setFillColor(HexColor("#F3D2BC"))
    c.drawString(22 * mm, h - 11.6 * mm, "Examen blanc CCNA 200-301  ·  Document propriétaire")
    c.setFillColor(ORANGE)
    c.roundRect(w - 42 * mm, h - 12.6 * mm, 28 * mm, 7.5 * mm, 1.5 * mm, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("NC-Bold", 8)
    c.drawCentredString(w - 28 * mm, h - 10.2 * mm, f"VERSION {exam['version']}")

    # Pied
    c.setFillColor(NAVY)
    c.rect(0, 0, w, 12 * mm, fill=1, stroke=0)
    c.setFillColor(HexColor("#E8D5C4"))
    c.setFont("NC", 6.4)
    c.drawString(12 * mm, 6.8 * mm, COPYRIGHT)
    c.drawString(12 * mm, 3.2 * mm, f"{exam['code']}  ·  Ne pas emporter  ·  Usage pédagogique interne {OWNER}")
    c.setFillColor(ORANGE)
    c.circle(w - 16 * mm, 6 * mm, 5.2 * mm, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("NC-Bold", 7)
    c.drawCentredString(w - 16 * mm, 4.7 * mm, str(doc.page))
    c.restoreState()


def identity_block(s: dict) -> Table:
    label = s["cell_b"]
    field = s["cell"]
    data = [
        [
            Paragraph("Nom", label),
            Paragraph("........................................", field),
            Paragraph("Prénom", label),
            Paragraph("........................................", field),
        ],
        [
            Paragraph("Centre / session", label),
            Paragraph("........................................", field),
            Paragraph("Date", label),
            Paragraph("........................................", field),
        ],
        [
            Paragraph("N° de copie", label),
            Paragraph("........................................", field),
            Paragraph("Salle", label),
            Paragraph("........................................", field),
        ],
    ]
    t = Table(data, colWidths=[32 * mm, 53 * mm, 28 * mm, 57 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CREAM),
                ("BOX", (0, 0), (-1, -1), 0.7, ORANGE),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, LINE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return t


def info_table(exam: dict, s: dict) -> Table:
    rows = [
        [Paragraph("<b>Épreuve</b>", s["cell"]), Paragraph(exam["title"], s["cell"])],
        [Paragraph("<b>Durée</b>", s["cell"]), Paragraph(exam["duration"], s["cell"])],
        [Paragraph("<b>Documents autorisés</b>", s["cell"]), Paragraph("Aucun. Brouillon fourni par le centre.", s["cell"])],
        [Paragraph("<b>Matériel</b>", s["cell"]), Paragraph("Stylo. Calculatrice mentale / brouillon uniquement.", s["cell"])],
        [Paragraph("<b>Pénalité</b>", s["cell"]), Paragraph("Pas de point négatif. QCM multiple : toute erreur (oubli ou case en trop) = 0.", s["cell"])],
        [Paragraph("<b>Consignes</b>", s["cell"]), Paragraph("Réponses sur le sujet (cases ☐). Transcrire aussi sur la feuille récapitulative.", s["cell"])],
    ]
    t = Table(rows, colWidths=[48 * mm, 122 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), PALE_GREEN),
                ("BACKGROUND", (1, 0), (1, -1), white),
                ("BOX", (0, 0), (-1, -1), 0.5, GREEN),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return t


def render_question(q: dict, s: dict) -> KeepTogether:
    bits = []
    pts = "pt" if q["points"] == 1 else "pts"
    extra = ""
    if q.get("multi"):
        n = q.get("n_correct", 2)
        extra = f"  —  <font color='#E05206'>cocher {n} réponses</font>"
    head = f"Question {q['n']}  <font color='#0A8A3A'>({q['points']} {pts})</font>{extra}"
    bits.append(Paragraph(head, s["qhead"]))
    bits.append(Paragraph(q["stem"], s["stem"]))
    if q.get("code"):
        bits.append(Spacer(1, 2))
        bits.append(CodeBox(q["code"]))
        bits.append(Spacer(1, 3))
    for letter, text in q["choices"]:
        bits.append(Paragraph(f"☐&nbsp;&nbsp;<b>{letter}.</b>  {text}", s["choice"]))
    bits.append(Spacer(1, 7))
    return KeepTogether(bits)


def answer_grid(n_questions: int, s: dict) -> Table:
    header = [Paragraph("Q", s["cell_w"])] + [
        Paragraph(l, s["cell_w"]) for l in "ABCDE"
    ]
    rows = [header]
    for i in range(1, n_questions + 1):
        rows.append(
            [Paragraph(str(i), s["cell_b"])]
            + [Paragraph("☐", s["cell"]) for _ in range(5)]
        )
    t = Table(rows, colWidths=[16 * mm] + [30.8 * mm] * 5, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), white),
        ("BOX", (0, 0), (-1, -1), 0.5, NAVY),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, LINE),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]
    for i in range(1, n_questions + 1):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), CREAM))
    t.setStyle(TableStyle(style_cmds))
    # Recolor header text: Paragraphs already navy; rebuild header with white via background only
    return t


def build_story(exam: dict, s: dict) -> list:
    story: list = []
    # Page 1 = cover (drawn in onPage). Then identity.
    story.append(NextPageTemplate("content"))
    story.append(PageBreak())

    story.append(Paragraph("Identité du candidat", s["h1"]))
    story.append(identity_block(s))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Modalités de l'épreuve", s["h1"]))
    story.append(info_table(exam, s))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Répartition (blueprint Cisco 200-301 v1.1)", s["h2"]))
    story.append(
        Paragraph(
            "Fondamentaux réseau 20 %  ·  Accès réseau 20 %  ·  Connectivité IP 25 %  ·  "
            "Services IP 10 %  ·  Sécurité 15 %  ·  Automatisation et programmabilité 10 %.",
            s["body"],
        )
    )
    story.append(Paragraph("Rappels de notation", s["h2"]))
    bullets = [
        "Partie A (Q 1–36) : une seule bonne réponse — 1 point.",
        "Partie B (Q 37–44) : plusieurs bonnes réponses — 2 points, tout ou rien.",
        "Partie C (Q 45–50) : scénarios / sorties IOS — 2 points.",
        "Total : 58 points. Seuil indicatif « prêt CCNA » : 80 % (47/58).",
        "Mini-lab papier : hors barème principal (bonus formateur +10 pts max si activé).",
        "Écrire lisiblement. Les ratures illisibles sont nulles.",
    ]
    story.append(
        ListFlowable(
            [ListItem(Paragraph(b, s["body_left"]), leftIndent=8, bulletColor=ORANGE) for b in bullets],
            bulletType="bullet",
            start="•",
            leftIndent=12,
            bulletFontName="NC-Bold",
            bulletFontSize=9,
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            "<b>Avertissement propriétaire.</b> L'intégralité de ce fascicule (textes, scénarios, "
            "identifiants de questions, mise en page et marques) appartient à <b>Niger Certify</b>. "
            "Toute reproduction, photographie, partage en ligne ou usage commercial non autorisé "
            "expose à des sanctions pédagogiques et juridiques.",
            s["note"],
        )
    )

    story.append(PageBreak())
    for part in exam["parts"]:
        story.append(Paragraph(part["title"], s["h1"]))
        if part.get("intro"):
            story.append(Paragraph(part["intro"], s["body"]))
        story.append(
            HRFlowable(width="100%", thickness=1, color=ORANGE, spaceAfter=8, spaceBefore=1)
        )
        for q in part["questions"]:
            story.append(render_question(q, s))
        story.append(Spacer(1, 4))

    # Mini-lab
    lab = exam["minilab"]
    story.append(PageBreak())
    story.append(Paragraph(lab["title"], s["h1"]))
    story.append(Paragraph(lab["intro"], s["body"]))
    if lab.get("topo"):
        story.append(Paragraph("Topologie (description)", s["h2"]))
        story.append(CodeBox(lab["topo"]))
    story.append(Paragraph("Tâches", s["h2"]))
    for i, task in enumerate(lab["tasks"], 1):
        story.append(Paragraph(f"<b>T{i}.</b>  {task}", s["stem"]))
        story.append(
            Paragraph(
                "Commandes / réponse :<br/>"
                ".................................................................................................................<br/>"
                ".................................................................................................................<br/>"
                ".................................................................................................................",
                s["note"],
            )
        )

    # Feuille récapitulative
    story.append(PageBreak())
    story.append(Paragraph("Feuille récapitulative de réponses", s["h1"]))
    story.append(
        Paragraph(
            "Reporter clairement les lettres choisies. Cette feuille est collée à la copie. "
            "Nom / prénom identiques à la page d'identité.",
            s["body"],
        )
    )
    story.append(identity_block(s))
    story.append(Spacer(1, 8))
    story.append(answer_grid(exam["n_questions"], s))
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            "Signature du candidat : ........................................    "
            "Visa surveillant : ........................................",
            s["body_left"],
        )
    )
    story.append(Spacer(1, 10))
    story.append(
        HRFlowable(width="100%", thickness=1.2, color=GREEN, spaceAfter=6)
    )
    story.append(
        Paragraph(
            f"Fin de l'énoncé — Version {exam['version']} — {OWNER} — {exam['code']}",
            s["center_small"],
        )
    )
    return story


def draw_first_page(c, doc):
    exam = doc.exam
    if doc.page == 1:
        draw_cover_page(c, exam)
    else:
        _header_footer(c, doc, exam)


def draw_later_pages(c, doc):
    _header_footer(c, doc, doc.exam)


def build_pdf(exam: dict, outfile: Path) -> Path:
    register_fonts()
    s = styles()
    outfile.parent.mkdir(parents=True, exist_ok=True)

    doc = BaseDocTemplate(
        str(outfile),
        pagesize=A4,
        title=f"{exam['title']} — Version {exam['version']}",
        author=OWNER,
        subject=f"Examen blanc CCNA 200-301 v1.1 — {OWNER}",
        creator=f"{OWNER} — générateur interne {YEAR}",
        keywords="CCNA, Cisco, Niger Certify, examen blanc, propriétaire",
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=24 * mm,
        bottomMargin=18 * mm,
    )
    doc.exam = exam

    frame_cover = Frame(0, 0, A4[0], A4[1], id="cover", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    frame_content = Frame(
        16 * mm,
        16 * mm,
        A4[0] - 32 * mm,
        A4[1] - 42 * mm,
        id="content",
    )
    doc.addPageTemplates(
        [
            PageTemplate(id="cover", frames=[frame_cover], onPage=draw_first_page),
            PageTemplate(id="content", frames=[frame_content], onPage=draw_later_pages),
        ]
    )
    doc.build(build_story(exam, s))
    return outfile


def build_corrige_pdf(exams: list[dict], outfile: Path) -> Path:
    """Corrigé formateur (A + B) — ne pas distribuer aux candidats."""
    register_fonts()
    s = styles()
    outfile.parent.mkdir(parents=True, exist_ok=True)

    meta = {
        "version": "CORRIGÉ",
        "title": "Corrigé formateur — Examens blancs A et B",
        "subtitle": "Cisco CCNA 200-301 v1.1  ·  CONFIDENTIEL FORMATEUR",
        "code": "NC-CCNA-BLANC-CORRIGE-2026",
        "duration": "N/A (document formateur)",
        "n_questions": "50 + 50",
        "bareme": "58 pts / version",
        "seuil": "80 % = 47/58",
    }

    doc = BaseDocTemplate(
        str(outfile),
        pagesize=A4,
        title="Corrigé formateur CCNA — Niger Certify",
        author=OWNER,
        subject="Corrigé confidentiel — ne pas diffuser aux candidats",
        creator=f"{OWNER} {YEAR}",
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=24 * mm,
        bottomMargin=18 * mm,
    )
    doc.exam = meta
    frame_cover = Frame(0, 0, A4[0], A4[1], id="cover", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    frame_content = Frame(16 * mm, 16 * mm, A4[0] - 32 * mm, A4[1] - 42 * mm, id="content")
    doc.addPageTemplates(
        [
            PageTemplate(id="cover", frames=[frame_cover], onPage=draw_first_page),
            PageTemplate(id="content", frames=[frame_content], onPage=draw_later_pages),
        ]
    )

    story: list = [NextPageTemplate("content"), PageBreak()]
    story.append(Paragraph("Diffusion restreinte", s["h1"]))
    story.append(
        Paragraph(
            "Ce corrigé est réservé aux formateurs <b>Niger Certify</b>. "
            "Ne jamais photocopier avec les énoncés élèves. Conserver sous clé / dossier formateur.",
            s["body"],
        )
    )

    for exam in exams:
        story.append(Paragraph(f"Version {exam['version']} — grille de réponses", s["h1"]))
        story.append(
            Paragraph(
                f"Code {esc(exam['code'])}. Mini-lab : voir extraits de configuration en fin de version.",
                s["note"],
            )
        )
        header = [
            Paragraph("Q", s["cell_w"]),
            Paragraph("Réponse", s["cell_w"]),
            Paragraph("Justification pédagogique", s["cell_w"]),
        ]
        rows = [header]
        for part in exam["parts"]:
            for q in part["questions"]:
                rows.append(
                    [
                        Paragraph(str(q["n"]), s["cell_b"]),
                        Paragraph(esc(q["answer"]), s["cell_b"]),
                        Paragraph(q.get("explain", "—"), s["cell"]),
                    ]
                )
        t = Table(rows, colWidths=[12 * mm, 28 * mm, 130 * mm], repeatRows=1)
        cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("BOX", (0, 0), (-1, -1), 0.4, NAVY),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for i in range(1, len(rows)):
            if i % 2 == 0:
                cmds.append(("BACKGROUND", (0, i), (-1, i), CREAM))
            else:
                cmds.append(("BACKGROUND", (0, i), (-1, i), white))
        t.setStyle(TableStyle(cmds))
        story.append(t)
        story.append(Paragraph("Mini-lab — extraits attendus", s["h2"]))
        story.append(CodeBox(exam["minilab"]["correction"]))
        story.append(PageBreak())

    story.append(Paragraph("Grille d'interprétation (promo)", s["h1"]))
    story.append(
        Paragraph(
            "≥ 90 % : prêt examen officiel.  80–89 % : blanc réussi, revoir 1–2 domaines.  "
            "70–79 % : lacunes ciblées (souvent masques, OSPF, ACL, STP).  "
            "&lt; 70 % : ne pas planifier la date Cisco.",
            s["body"],
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            f"Fin du corrigé — {OWNER} — NC-CCNA-BLANC-CORRIGE-2026",
            s["center_small"],
        )
    )
    doc.build(story)
    return outfile
