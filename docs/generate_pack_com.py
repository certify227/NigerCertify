#!/usr/bin/env python3
"""Génère le pack Word + Excel NigerCertify (plan com & calendrier éditorial)."""

from datetime import date, timedelta
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

OUT = Path(__file__).resolve().parent
WHATSAPP = "94 10 70 74"
WA_LINK = "https://wa.me/22794107074"


def add_heading(doc: Document, text: str, level: int = 1) -> None:
    doc.add_heading(text, level=level)


def add_para(doc: Document, text: str, bold: bool = False) -> None:
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold = bold
    run.font.size = Pt(11)


def add_bullets(doc: Document, items: list[str]) -> None:
    for item in items:
        doc.add_paragraph(item, style="List Bullet")


def build_word() -> Path:
    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)

    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = title.add_run("NigerCertify")
    r.bold = True
    r.font.size = Pt(28)
    r.font.color.rgb = RGBColor(0x0F, 0x4C, 0x3A)

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    s = sub.add_run("Plan de communication & catalogue formations\nVersion 2.3 — Niger & Sénégal")
    s.font.size = Pt(14)

    add_para(doc, f"WhatsApp commercial : {WHATSAPP}  ·  {WA_LINK}", bold=True)
    add_para(doc, "Budget com : 20 000 FCFA / mois — stratégie organique (Facebook, LinkedIn, YouTube, WhatsApp).")

    add_heading(doc, "1. Positionnement", 1)
    add_para(
        doc,
        "NigerCertify forme et certifie (PECB + LPI) et digitalise les métiers via nBusiness et CouturePro.",
    )
    add_para(doc, "Promesse : Certifiez-vous. Structurez votre métier.", bold=True)
    add_bullets(
        doc,
        [
            "PECB : ISO/IEC 27001, ISO/IEC 27701 — session en ligne 10 octobre 2026 — 350 000 FCFA (accès 12 mois, 2 retakes)",
            "LPI : Linux Essentials 150 000 FCFA · LPIC-1/2/3 200 000 FCFA / niveau — format mixte",
            "nBusiness : gestion multi-secteur (commerce, éducation, business, pressing…)",
            "CouturePro : gestion ateliers de couture",
            "Lab GitHub offensif : hors communication grand public",
        ],
    )

    add_heading(doc, "2. Architecture d’offres (répartition com)", 1)
    table = doc.add_table(rows=5, cols=3)
    table.style = "Table Grid"
    headers = ("Priorité", "Offre", "Part des messages")
    for i, h in enumerate(headers):
        table.rows[0].cells[i].text = h
    data = [
        ("#1", "PECB (ISO 27001 / 27701)", "60 %"),
        ("#2", "LPI LE → LPIC-3", "20 %"),
        ("#3", "nBusiness", "15 %"),
        ("#4", "CouturePro", "5 %"),
    ]
    for r_i, row in enumerate(data, start=1):
        for c_i, val in enumerate(row):
            table.rows[r_i].cells[c_i].text = val

    add_heading(doc, "3. Catalogue formations", 1)
    add_heading(doc, "3.1 PECB", 2)
    add_bullets(
        doc,
        [
            "Normes : ISO/IEC 27001 · ISO/IEC 27701",
            "Démarrage : 10 octobre 2026",
            "Modalité : 100 % en ligne",
            "Accès plateforme : 12 mois",
            "Examens : inclus + 2 retakes",
            "Tarif : 350 000 FCFA",
            "Inscription : WhatsApp 94 10 70 74 — JE M’INSCRIS",
        ],
    )

    add_heading(doc, "3.2 LPI (Linux)", 2)
    t2 = doc.add_table(rows=5, cols=4)
    t2.style = "Table Grid"
    for i, h in enumerate(("Niveau", "Certification", "Tarif", "Format")):
        t2.rows[0].cells[i].text = h
    lpi_rows = [
        ("LPI LE", "Linux Essentials", "150 000 FCFA", "Mixte"),
        ("LPIC-1", "Linux Administrator", "200 000 FCFA", "Mixte"),
        ("LPIC-2", "Linux Engineer", "200 000 FCFA", "Mixte"),
        ("LPIC-3", "Linux Enterprise", "200 000 FCFA", "Mixte"),
    ]
    for r_i, row in enumerate(lpi_rows, start=1):
        for c_i, val in enumerate(row):
            t2.rows[r_i].cells[c_i].text = val
    add_para(doc, "Mot-clé WhatsApp : LPI + niveau (LE / LPIC1 / LPIC2 / LPIC3)")

    add_heading(doc, "4. Canaux prioritaires", 1)
    add_bullets(
        doc,
        [
            "WhatsApp Business — canal #1 commercial",
            "LinkedIn — B2B / PECB / LPI",
            "Facebook — PME, CouturePro, audiences locales Niger & Sénégal",
            "YouTube — démos courtes (PECB tips, Linux, nBusiness, CouturePro)",
            "Email — nurturing sessions",
        ],
    )

    add_heading(doc, "5. Mots-clés WhatsApp", 1)
    t3 = doc.add_table(rows=7, cols=2)
    t3.style = "Table Grid"
    t3.rows[0].cells[0].text = "Mot-clé"
    t3.rows[0].cells[1].text = "Action"
    keywords = [
        ("PROGRAMME", "Catalogue complet"),
        ("PECB / JE M’INSCRIS", "Session ISO 10/10/2026"),
        ("LPI", "Parcours Linux"),
        ("LE / LPIC1 / LPIC2 / LPIC3", "Niveau LPI précis"),
        ("NBUSINESS", "Démo nBusiness"),
        ("COUTUREPRO", "Démo CouturePro"),
    ]
    for r_i, (k, v) in enumerate(keywords, start=1):
        t3.rows[r_i].cells[0].text = k
        t3.rows[r_i].cells[1].text = v

    add_heading(doc, "6. Scripts WhatsApp (extraits)", 1)
    add_para(doc, "Accueil général", bold=True)
    add_para(
        doc,
        "Bonjour, NigerCertify — formations certifiantes (Niger & Sénégal).\n"
        "1) PECB ISO 27001/27701 — 10 oct. 2026 — 350 000 FCFA — 12 mois — 2 retakes\n"
        "2) LPI mixte — LE 150 000 FCFA — LPIC-1/2/3 200 000 FCFA / niveau\n"
        "Aussi : nBusiness · CouturePro — WhatsApp 94 10 70 74",
    )

    add_heading(doc, "7. Règles de publication", 1)
    add_bullets(
        doc,
        [
            "1 contenu = 1 public + 1 offre + 1 CTA",
            "Répartition : PECB 60 % · LPI 20 % · nBusiness 15 % · CouturePro 5 %",
            "Pas de contenu lab offensif / webshell sur Facebook, LinkedIn, YouTube grand public",
            "Toujours indiquer WhatsApp 94 10 70 74 et un mot-clé clair",
            "Calendrier détaillé : fichier Excel joint (Facebook / LinkedIn / YouTube)",
        ],
    )

    add_heading(doc, "8. Feuille de route 90 jours", 1)
    add_bullets(
        doc,
        [
            "Jours 1–30 : catalogue PDF, bios, 9 posts LinkedIn, liste 50+50 prospects, WhatsApp structuré",
            "Jours 31–60 : pousser session PECB 10/10, 2 témoignages, démos LPI/nBusiness",
            "Jours 61–90 : calendrier T2, partenariat, industrialiser les relances",
        ],
    )

    add_heading(doc, "9. Contact", 1)
    add_para(doc, f"WhatsApp : {WHATSAPP}", bold=True)
    add_para(doc, WA_LINK)
    add_para(doc, "Marchés : Niger · Sénégal · distanciel francophone")

    footer = doc.add_paragraph()
    footer.add_run(
        "\nDocument généré pour NigerCertify — usage interne / commercial. "
        "Compléter modalités de paiement et calendrier de démarrage LPI."
    ).italic = True

    path = OUT / "NigerCertify-Plan-Communication.docx"
    doc.save(path)
    return path


# --- Excel calendar ---

THEMES = {
    "PECB": {
        "fill": "1F6B4F",
        "posts": [
            (
                "Session PECB 10 oct. 2026 — inscriptions ouvertes",
                "ISO 27001 · ISO 27701 · en ligne · 12 mois · 2 retakes · 350 000 FCFA\nWhatsApp 94 10 70 74 — JE M’INSCRIS",
                "JE M’INSCRIS",
            ),
            (
                "Pourquoi ISO 27001 ?",
                "Le langage commun de la sécurité de l’information. Session PECB NigerCertify dès le 10/10/2026.",
                "PROGRAMME",
            ),
            (
                "Ce qui est inclus pour 350 000 FCFA",
                "Formation PECB + accès 12 mois + examen + 2 retakes + suivi NigerCertify.",
                "PECB",
            ),
            (
                "ISO 27701 — privacy",
                "Protéger les données personnelles : extension naturelle du SMSI. Places session 10 oct.",
                "PROGRAMME",
            ),
            (
                "Niger & Sénégal — même session en ligne",
                "Certification internationale, accompagnement local. 94 10 70 74",
                "JE M’INSCRIS",
            ),
        ],
    },
    "LPI": {
        "fill": "2E5A88",
        "posts": [
            (
                "Parcours LPI : LE → LPIC-1 → LPIC-2 → LPIC-3",
                "Format mixte. LE 150 000 FCFA · LPIC 200 000 FCFA / niveau.",
                "LPI",
            ),
            (
                "Linux Essentials — premier pas",
                "LPI LE · 150 000 FCFA · mixte. Idéal débutants & reconversion.",
                "LPI LE",
            ),
            (
                "LPIC-1 / 2 / 3 — montez en niveau",
                "Admin → Engineer → Enterprise. 200 000 FCFA / niveau · format mixte.",
                "LPI",
            ),
            (
                "Tip Linux (60 sec)",
                "Une commande utile + lien vers le parcours LPI NigerCertify.",
                "LPI",
            ),
        ],
    },
    "nBusiness": {
        "fill": "8A6D1D",
        "posts": [
            (
                "nBusiness — gestion multi-secteur",
                "Commerce, école, pressing, business : stock, clients, ventes.",
                "NBUSINESS",
            ),
            (
                "Démo nBusiness 10 min",
                "Réservez une démo WhatsApp. 94 10 70 74",
                "NBUSINESS",
            ),
        ],
    },
    "CouturePro": {
        "fill": "8B3A4A",
        "posts": [
            (
                "CouturePro — ateliers de couture",
                "Commandes, tissus, clients, délais — un seul outil.",
                "COUTUREPRO",
            ),
        ],
    },
}


def next_weekday(d: date, weekday: int) -> date:
    """weekday: 0=Mon ... 6=Sun"""
    days = (weekday - d.weekday()) % 7
    return d + timedelta(days=days)


def build_excel(start: date | None = None) -> Path:
    """Calendrier 12 semaines à partir du prochain lundi (ou start)."""
    if start is None:
        today = date.today()
        start = next_weekday(today, 0)  # lundi
        if start == today and today.weekday() != 0:
            start = next_weekday(today + timedelta(days=1), 0)

    wb = Workbook()

    # Styles
    header_fill = PatternFill("solid", fgColor="0F4C3A")
    header_font = Font(bold=True, color="FFFFFF", name="Calibri", size=11)
    thin = Border(
        left=Side(style="thin", color="CCCCCC"),
        right=Side(style="thin", color="CCCCCC"),
        top=Side(style="thin", color="CCCCCC"),
        bottom=Side(style="thin", color="CCCCCC"),
    )
    wrap = Alignment(wrap_text=True, vertical="top")

    # --- Feuille Guide ---
    guide = wb.active
    guide.title = "Guide"
    guide["A1"] = "Calendrier de publication NigerCertify"
    guide["A1"].font = Font(bold=True, size=16, color="0F4C3A")
    guide["A2"] = f"WhatsApp : {WHATSAPP}  |  {WA_LINK}"
    guide["A3"] = "Canaux : Facebook · LinkedIn · YouTube"
    guide["A4"] = "Répartition : PECB 60% · LPI 20% · nBusiness 15% · CouturePro 5%"
    guide["A5"] = "Période : 12 semaines (colonne Date = jour de publication prévu)"
    guide["A7"] = "Légende des statuts"
    guide["A8"] = "À faire / En cours / Publié / Reporté"
    guide["A10"] = "Consignes"
    for i, line in enumerate(
        [
            "1. Adapter le texte au format du canal (LinkedIn plus pro, Facebook plus local, YouTube = script + titre + description).",
            "2. Toujours finir par un CTA + WhatsApp 94 10 70 74.",
            "3. Cocher Statut = Publié après mise en ligne ; coller l’URL dans Lien publication.",
            "4. YouTube : viser 3–8 min (tips) ou Shorts 30–60 s.",
            "5. Ne jamais publier de contenu lab offensif / exploit sur ces canaux.",
            "6. Jour type : Lun LinkedIn PECB · Mer Facebook mixte · Ven YouTube · Dim Facebook CTA.",
        ],
        start=11,
    ):
        guide[f"A{i}"] = line
    guide.column_dimensions["A"].width = 110

    # --- Feuille Calendrier ---
    ws = wb.create_sheet("Calendrier", 0)
    headers = [
        "Semaine",
        "Date",
        "Jour",
        "Canal",
        "Offre",
        "Titre / Accroche",
        "Texte / Script (brouillon)",
        "Format",
        "CTA / Mot-clé",
        "Statut",
        "Responsable",
        "Lien publication",
        "Notes",
    ]
    for col, h in enumerate(headers, 1):
        cell = ws.cell(1, col, h)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(wrap_text=True, vertical="center", horizontal="center")
        cell.border = thin

    # Pattern hebdomadaire : canal + offre index
    # Lun LinkedIn PECB, Mar Facebook LPI, Mer LinkedIn PECB, Jeu YouTube,
    # Ven Facebook nBusiness/CouturePro alt, Sam YouTube Short (option), Dim Facebook CTA PECB
    week_slots = [
        (0, "LinkedIn", "PECB", "Post carrousel / texte"),  # Lun
        (1, "Facebook", "LPI", "Post image + texte"),  # Mar
        (2, "LinkedIn", "PECB", "Post texte + CTA"),  # Mer
        (3, "YouTube", "PECB", "Vidéo 5–8 min ou Short"),  # Jeu (alternance LPI)
        (4, "Facebook", "nBusiness", "Post / Reels"),  # Ven
        (6, "Facebook", "PECB", "Statut / CTA session"),  # Dim
    ]

    pecb_i = lpi_i = nb_i = cp_i = 0
    row = 2
    for week in range(1, 13):
        week_start = start + timedelta(weeks=week - 1)
        for day_offset, canal, offre_default, fmt in week_slots:
            pub_date = week_start + timedelta(days=day_offset)

            # Alternance YouTube : semaines paires = LPI
            offre = offre_default
            if canal == "YouTube" and week % 2 == 0:
                offre = "LPI"
            # Vendredi : 1 semaine sur 4 CouturePro
            if canal == "Facebook" and day_offset == 4 and week % 4 == 0:
                offre = "CouturePro"

            bundle = THEMES[offre]
            posts = bundle["posts"]
            if offre == "PECB":
                title, body, cta = posts[pecb_i % len(posts)]
                pecb_i += 1
            elif offre == "LPI":
                title, body, cta = posts[lpi_i % len(posts)]
                lpi_i += 1
            elif offre == "nBusiness":
                title, body, cta = posts[nb_i % len(posts)]
                nb_i += 1
            else:
                title, body, cta = posts[cp_i % len(posts)]
                cp_i += 1

            # YouTube : adapter le format texte en script
            texte = body
            if canal == "YouTube":
                texte = (
                    f"TITRE : {title}\n"
                    f"HOOK (0–5s) : {title}\n"
                    f"CORPS : {body}\n"
                    f"CTA fin : Écrivez {cta} au {WHATSAPP}\n"
                    f"DESCRIPTION : NigerCertify · Niger & Sénégal · {WA_LINK}?text={cta.replace(' ', '%20')}"
                )
                fmt = "YouTube Short (45–60s)" if week % 3 == 0 else "Vidéo 5–8 min"

            jour = ["Lun", "Mar", "Mer", "Jeu", "Ven", "Sam", "Dim"][pub_date.weekday()]
            values = [
                week,
                pub_date.isoformat(),
                jour,
                canal,
                offre,
                title,
                texte,
                fmt,
                cta,
                "À faire",
                "",
                "",
                "",
            ]
            fill = PatternFill("solid", fgColor=bundle["fill"])
            light = PatternFill("solid", fgColor="E8F5F0" if offre == "PECB" else "EEF3F8" if offre == "LPI" else "F8F3E0" if offre == "nBusiness" else "F8E8EC")

            for col, val in enumerate(values, 1):
                cell = ws.cell(row, col, val)
                cell.border = thin
                cell.alignment = wrap
                if col == 5:  # Offre
                    cell.fill = fill
                    cell.font = Font(bold=True, color="FFFFFF")
                elif col == 4:
                    cell.fill = light
            row += 1

    widths = {
        "A": 10,
        "B": 12,
        "C": 8,
        "D": 12,
        "E": 12,
        "F": 42,
        "G": 55,
        "H": 22,
        "I": 14,
        "J": 12,
        "K": 14,
        "L": 28,
        "M": 20,
    }
    for col, w in widths.items():
        ws.column_dimensions[col].width = w
    ws.row_dimensions[1].height = 30
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:M{row - 1}"

    # Validation statut
    dv = DataValidation(type="list", formula1='"À faire,En cours,Publié,Reporté"', allow_blank=True)
    ws.add_data_validation(dv)
    dv.add(f"J2:J{row - 1}")

    dv_canal = DataValidation(type="list", formula1='"Facebook,LinkedIn,YouTube"', allow_blank=True)
    ws.add_data_validation(dv_canal)
    dv_canal.add(f"D2:D{row - 1}")

    dv_offre = DataValidation(type="list", formula1='"PECB,LPI,nBusiness,CouturePro"', allow_blank=True)
    ws.add_data_validation(dv_offre)
    dv_offre.add(f"E2:E{row - 1}")

    # --- Feuille Récap ---
    recap = wb.create_sheet("Recap_mensuel")
    recap["A1"] = "Objectif mensuel (indicatif)"
    recap["A1"].font = Font(bold=True, size=14, color="0F4C3A")
    recap_headers = ["Canal", "Posts / mois (cible)", "Notes"]
    for col, h in enumerate(recap_headers, 1):
        c = recap.cell(3, col, h)
        c.fill = header_fill
        c.font = header_font
    for r_i, row_data in enumerate(
        [
            ("LinkedIn", "8–10", "PECB + LPI B2B"),
            ("Facebook", "10–12", "PECB CTA + LPI + logiciels"),
            ("YouTube", "4–6", "Alterner tips PECB / Linux + 1 démo logiciel"),
            ("WhatsApp Status", "20+", "Hors Excel mais quotidien"),
        ],
        start=4,
    ):
        for c_i, val in enumerate(row_data, 1):
            recap.cell(r_i, c_i, val).border = thin
    recap.column_dimensions["A"].width = 18
    recap.column_dimensions["B"].width = 22
    recap.column_dimensions["C"].width = 40

    # --- Feuille Offres ---
    offres = wb.create_sheet("Tarifs_offres")
    offres["A1"] = "Grille tarifaire formations"
    offres["A1"].font = Font(bold=True, size=14, color="0F4C3A")
    for col, h in enumerate(("Offre", "Détail", "Format", "Tarif (FCFA)", "CTA"), 1):
        c = offres.cell(3, col, h)
        c.fill = header_fill
        c.font = header_font
    for r_i, row_data in enumerate(
        [
            ("PECB ISO 27001/27701", "Session 10 oct. 2026 · 12 mois · 2 retakes", "En ligne", 350000, "JE M’INSCRIS"),
            ("LPI LE", "Linux Essentials", "Mixte", 150000, "LPI LE"),
            ("LPIC-1", "Linux Administrator", "Mixte", 200000, "LPIC1"),
            ("LPIC-2", "Linux Engineer", "Mixte", 200000, "LPIC2"),
            ("LPIC-3", "Linux Enterprise", "Mixte", 200000, "LPIC3"),
            ("nBusiness", "Gestion multi-secteur", "Démo", "Sur devis", "NBUSINESS"),
            ("CouturePro", "Ateliers couture", "Démo", "Sur devis", "COUTUREPRO"),
        ],
        start=4,
    ):
        for c_i, val in enumerate(row_data, 1):
            cell = offres.cell(r_i, c_i, val)
            cell.border = thin
            if c_i == 4 and isinstance(val, int):
                cell.number_format = '#,##0'
    for col in range(1, 6):
        offres.column_dimensions[get_column_letter(col)].width = 28

    path = OUT / "NigerCertify-Calendrier-Publication.xlsx"
    wb.save(path)
    return path


def main() -> None:
    word = build_word()
    excel = build_excel()
    print(f"Word  : {word}")
    print(f"Excel : {excel}")


if __name__ == "__main__":
    main()
