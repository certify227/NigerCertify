"""
Génération optimisée des classeurs Excel pour impression parfaite sur 1 page A4 :
- Proforma_Anper.xlsx (Facture A : A4 Portrait, Fit to 1x1, Centré, Marges adaptées)
- Pro_forma_GIZ.xlsx (Facture B : A4 Portrait, Fit to 1x1, Centré, Marges adaptées)
- Tableau_Comparatif_Offres_ANMC.xlsx (A4 Paysage, Fit to 1x1, Centré, Marges adaptées)
"""

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.worksheet.page import PageMargins

def apply_print_setup(ws, orientation="portrait", print_area=None):
    """Configure les paramètres d'impression Excel pour un ajustement A4 parfait."""
    if orientation == "landscape":
        ws.page_setup.orientation = ws.ORIENTATION_LANDSCAPE
    else:
        ws.page_setup.orientation = ws.ORIENTATION_PORTRAIT
    
    ws.page_setup.paperSize = ws.PAPERSIZE_A4  # 9 = A4
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.page_setup.fitToPage = True
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 1
    
    ws.print_options.horizontalCentered = True
    ws.print_options.verticalCentered = False
    ws.print_options.gridLines = False
    
    # Marges fines (en pouces : 0.35 in ~ 9mm)
    ws.page_margins = PageMargins(
        left=0.35, right=0.35, top=0.35, bottom=0.35, header=0.2, footer=0.2
    )
    
    if print_area:
        ws.print_area = print_area


def create_proforma_anper(filepath="/workspace/proformas-concurrentes/Proforma_Anper.xlsx"):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Facture Proforma A"
    ws.views.sheetView[0].showGridLines = True

    # Palette ANPER / Entreprise A : Bleu Roi (#1F4E79), Bleu Ciel (#D9E1F2)
    color_primary = "1F4E79"
    
    font_header_org = Font(name="Calibri", size=12, bold=True, color=color_primary)
    font_sub_org = Font(name="Calibri", size=8.5, italic=True, color="505050")
    font_title = Font(name="Calibri", size=14, bold=True, color=color_primary)
    font_bold = Font(name="Calibri", size=9, bold=True, color="000000")
    font_normal = Font(name="Calibri", size=8.5, color="000000")
    font_small = Font(name="Calibri", size=7.8, color="505050")
    font_th = Font(name="Calibri", size=8.5, bold=True, color="FFFFFF")
    font_total = Font(name="Calibri", size=10, bold=True, color="1F4E79")

    fill_th = PatternFill(start_color=color_primary, end_color=color_primary, fill_type="solid")
    fill_zebra = PatternFill(start_color="F2F5F9", end_color="F2F5F9", fill_type="solid")
    fill_total = PatternFill(start_color="D9E1F2", end_color="D9E1F2", fill_type="solid")
    fill_box = PatternFill(start_color="F5F8FB", end_color="F5F8FB", fill_type="solid")

    thin_border = Border(
        left=Side(style='thin', color="B0C4DE"),
        right=Side(style='thin', color="B0C4DE"),
        top=Side(style='thin', color="B0C4DE"),
        bottom=Side(style='thin', color="B0C4DE")
    )
    total_border = Border(
        top=Side(style='medium', color="1F4E79"),
        bottom=Side(style='double', color="1F4E79"),
        left=Side(style='thin', color="B0C4DE"),
        right=Side(style='thin', color="B0C4DE")
    )

    # Largeurs de colonnes optimisées A4 Portrait (Total = 91)
    col_widths = {
        "A": 5,    # N°
        "B": 46,   # Désignation
        "C": 10,   # Quantité
        "D": 15,   # Prix Unitaire
        "E": 15    # Montant Total
    }
    for col, width in col_widths.items():
        ws.column_dimensions[col].width = width

    # En-tête émetteur (Lignes 1-4)
    ws.merge_cells("A1:C1")
    ws["A1"] = "IMPRIMERIE & MULTISERVICES DU SAHEL (IMS SARL)"
    ws["A1"].font = font_header_org
    ws.row_dimensions[1].height = 18
    
    ws.merge_cells("A2:C2")
    ws["A2"] = "Imprimerie Offset, Sérigraphie Industrielle & Fournitures Générales"
    ws["A2"].font = font_sub_org
    ws.row_dimensions[2].height = 14
    
    ws.merge_cells("A3:C3")
    ws["A3"] = "Quartier Nouveau Marché, BP 11 204 Niamey (Niger) | Tél: (+227) 20 73 45 12 / 96 45 10 20"
    ws["A3"].font = font_small
    ws.row_dimensions[3].height = 13

    ws.merge_cells("A4:C4")
    ws["A4"] = "NIF: 45128/R | RCCM: NI-NIA-2021-B-1420 | Régime fiscal: Réel Simplifié"
    ws["A4"].font = font_small
    ws.row_dimensions[4].height = 13

    # Bloc Meta Proforma (Droite D1:E4)
    ws.merge_cells("D1:E1")
    ws["D1"] = "FACTURE PROFORMA A"
    ws["D1"].font = font_title
    ws["D1"].alignment = Alignment(horizontal="right", vertical="center")

    ws["D2"] = "N° Proforma :"
    ws["D2"].font = font_bold
    ws["D2"].alignment = Alignment(horizontal="right", vertical="center")
    ws["E2"] = "FP-2026/09-084"
    ws["E2"].font = font_bold
    ws["E2"].alignment = Alignment(horizontal="right", vertical="center")

    ws["D3"] = "Date :"
    ws["D3"].font = font_normal
    ws["D3"].alignment = Alignment(horizontal="right", vertical="center")
    ws["E3"] = "15/09/2026"
    ws["E3"].font = font_normal
    ws["E3"].alignment = Alignment(horizontal="right", vertical="center")

    ws["D4"] = "Validité de l'offre :"
    ws["D4"].font = font_normal
    ws["D4"].alignment = Alignment(horizontal="right", vertical="center")
    ws["E4"] = "60 jours"
    ws["E4"].font = font_normal
    ws["E4"].alignment = Alignment(horizontal="right", vertical="center")

    # Ligne 6-8 : Client ANMC
    ws.row_dimensions[5].height = 6
    ws.merge_cells("A6:E6")
    ws["A6"] = "CLIENT : AGENCE NATIONALE DE LA MÉTROLOGIE ET DE LA CONFORMITÉ (ANMC)"
    ws["A6"].font = font_bold
    ws["A6"].fill = fill_box
    ws["A6"].alignment = Alignment(horizontal="left", vertical="center")
    ws.row_dimensions[6].height = 18

    ws.merge_cells("A7:C7")
    ws["A7"] = "Direction Générale — BP 10 700 Niamey (République du Niger)"
    ws["A7"].font = font_normal
    ws.row_dimensions[7].height = 14

    ws.merge_cells("D7:E7")
    ws["D7"] = "NIF Client : 82397/P"
    ws["D7"].font = font_bold
    ws["D7"].alignment = Alignment(horizontal="right", vertical="center")

    ws.merge_cells("A8:E8")
    ws["A8"] = "Objet : Fourniture d'étiquettes de métrologie et scellés de sécurité (Exercices 2027 & 2028)"
    ws["A8"].font = font_normal
    ws["A8"].alignment = Alignment(vertical="center")
    ws.row_dimensions[8].height = 15

    ws.row_dimensions[9].height = 6

    # Ligne 10 : En-têtes du tableau
    headers = [
        ("A10", "N°"),
        ("B10", "Désignation / Nature de la commande"),
        ("C10", "Quantité"),
        ("D10", "P.U. HT (FCFA)"),
        ("E10", "Total HT (FCFA)")
    ]
    for cell_ref, text in headers:
        cell = ws[cell_ref]
        cell.value = text
        cell.font = font_th
        cell.fill = fill_th
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    ws.row_dimensions[10].height = 22

    # Lignes des 11 articles (Facture A : +30%)
    items_A = [
        (1, "Conception/Impression étiquette verte 9cm X 9cm (année 2027, n°6001 à 11000)", 5000, 195),
        (2, "Conception/Impression étiquette verte 9cm X 9cm (année 2028, n°0001 à 8000)", 8000, 195),
        (3, "Conception/Impression étiquette orange 9cm X 9cm (n°2001 à 4000)", 1000, 195),
        (4, "Conception/Impression étiquette rouge 9cm X 9cm (n°3001 à 4000)", 1000, 195),
        (5, "Conception/Impression étiquette verte 5,5cm X 5,5cm (année 2027, n°2501 à 3000)", 500, 130),
        (6, "Conception/Impression étiquette verte 5,5cm X 5,5cm (année 2028, n°0001 à 1000)", 1000, 130),
        (7, "Conception/Impression étiquette orange 5,5cm X 5,5cm (n°2001 à 3000)", 1000, 130),
        (8, "Conception/Impression étiquette rouge 5,5cm X 5,5cm (n°2001 à 3000)", 1000, 130),
        (9, "Conception/Impression étiquette verte 5cm X 2cm (année 2027, n°401 à 650)", 250, 117),
        (10, "Conception/Impression étiquette verte 5cm X 2cm (année 2028, n°1 à 250)", 250, 117),
        (11, "Scellé de sécurité personnalisés (gravure laser / numérotés)", 1000, 1300),
    ]

    start_row = 11
    for i, (num, desc, qty, pu) in enumerate(items_A):
        r = start_row + i
        ws.row_dimensions[r].height = 17
        
        ws[f"A{r}"] = num
        ws[f"A{r}"].alignment = Alignment(horizontal="center", vertical="center")
        
        ws[f"B{r}"] = desc
        ws[f"B{r}"].alignment = Alignment(horizontal="left", vertical="center")
        
        ws[f"C{r}"] = qty
        ws[f"C{r}"].alignment = Alignment(horizontal="right", vertical="center")
        ws[f"C{r}"].number_format = "#,##0"
        
        ws[f"D{r}"] = pu
        ws[f"D{r}"].alignment = Alignment(horizontal="right", vertical="center")
        ws[f"D{r}"].number_format = "#,##0"
        
        ws[f"E{r}"] = f"=C{r}*D{r}"
        ws[f"E{r}"].alignment = Alignment(horizontal="right", vertical="center")
        ws[f"E{r}"].number_format = "#,##0"

        for c in ["A", "B", "C", "D", "E"]:
            ws[f"{c}{r}"].font = font_normal
            ws[f"{c}{r}"].border = thin_border
            if i % 2 == 1:
                ws[f"{c}{r}"].fill = fill_zebra

    # Ligne Total
    tot_row = start_row + len(items_A)
    ws.row_dimensions[tot_row].height = 20
    
    ws.merge_cells(f"A{tot_row}:D{tot_row}")
    ws[f"A{tot_row}"] = "TOTAL MONTANT HORS TAXES (HT) FCFA"
    ws[f"A{tot_row}"].font = font_total
    ws[f"A{tot_row}"].alignment = Alignment(horizontal="right", vertical="center")
    ws[f"A{tot_row}"].fill = fill_total

    ws[f"E{tot_row}"] = f"=SUM(E{start_row}:E{tot_row-1})"
    ws[f"E{tot_row}"].font = font_total
    ws[f"E{tot_row}"].alignment = Alignment(horizontal="right", vertical="center")
    ws[f"E{tot_row}"].number_format = "#,##0"
    ws[f"E{tot_row}"].fill = fill_total

    for c in ["A", "B", "C", "D", "E"]:
        ws[f"{c}{tot_row}"].border = total_border

    # Montant en lettres
    r_words = tot_row + 2
    ws.row_dimensions[tot_row+1].height = 6
    ws.merge_cells(f"A{r_words}:E{r_words}")
    ws[f"A{r_words}"] = "Arrêtée la présente facture proforma à la somme de : QUATRE MILLIONS SEPT CENT TRENTE-HUIT MILLE CINQ CENTS (4 738 500) FCFA HT."
    ws[f"A{r_words}"].font = font_bold
    ws[f"A{r_words}"].alignment = Alignment(horizontal="left", vertical="center")
    ws.row_dimensions[r_words].height = 17

    # Conditions & Coordonnées bancaires
    r_cond = r_words + 2
    ws.row_dimensions[r_words+1].height = 6
    ws.merge_cells(f"A{r_cond}:C{r_cond}")
    ws[f"A{r_cond}"] = "CONDITIONS COMMERCIALES & BANCAIRES :"
    ws[f"A{r_cond}"].font = font_bold
    ws.row_dimensions[r_cond].height = 15

    conds = [
        "• Délai d'exécution : 30 à 45 jours ouvrables après réception du bon de commande et validation du BAT.",
        "• Modalités de règlement : 40% à la commande, solde de 60% par virement bancaire à la livraison.",
        "• Matière : Vinyle adhésif haute résistance, encres anti-UV indélébiles pour métrologie légale.",
        "• Compte bancaire : BIA-NIGER Niamey | Code Banque: NE034 | Guichet: 01001 | Compte: 02511488901 | Clé: 42"
    ]
    for idx, ctext in enumerate(conds):
        row_c = r_cond + 1 + idx
        ws.merge_cells(f"A{row_c}:C{row_c}")
        ws[f"A{row_c}"] = ctext
        ws[f"A{row_c}"].font = font_small
        ws.row_dimensions[row_c].height = 13

    # Bloc signature (D{r_cond}:E{r_cond+4})
    ws.merge_cells(f"D{r_cond}:E{r_cond}")
    ws[f"D{r_cond}"] = "Pour l'Imprimerie IMS SARL"
    ws[f"D{r_cond}"].font = font_bold
    ws[f"D{r_cond}"].alignment = Alignment(horizontal="center", vertical="center")

    ws.merge_cells(f"D{r_cond+1}:E{r_cond+1}")
    ws[f"D{r_cond+1}"] = "La Direction Commerciale"
    ws[f"D{r_cond+1}"].font = font_normal
    ws[f"D{r_cond+1}"].alignment = Alignment(horizontal="center", vertical="center")

    ws.merge_cells(f"D{r_cond+2}:E{r_cond+4}")
    ws[f"D{r_cond+2}"] = "[Cachet & Signature]"
    ws[f"D{r_cond+2}"].font = font_sub_org
    ws[f"D{r_cond+2}"].alignment = Alignment(horizontal="center", vertical="center")

    # Bandeau bas de page (Row 32)
    r_foot = r_cond + 5
    ws.row_dimensions[r_foot].height = 16
    ws.merge_cells(f"A{r_foot}:E{r_foot}")
    ws[f"A{r_foot}"] = "« Offre soumise aux conditions générales de vente — Imprimerie & Multiservices du Sahel SARL — Niamey »"
    ws[f"A{r_foot}"].font = Font(name="Calibri", size=7.5, italic=True, color="FFFFFF")
    ws[f"A{r_foot}"].fill = fill_th
    ws[f"A{r_foot}"].alignment = Alignment(horizontal="center", vertical="center")

    # Configuration Impression A4
    apply_print_setup(ws, orientation="portrait", print_area=f"A1:E{r_foot}")

    wb.save(filepath)
    print(f"[OK] Classeur adapté pour impression A4 : {filepath}")


def create_proforma_giz(filepath="/workspace/proformas-concurrentes/Pro_forma_GIZ.xlsx"):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Facture Proforma B"
    ws.views.sheetView[0].showGridLines = True

    # Palette GIZ / Entreprise B : Vert Forêt (#006633), Vert Sauge (#E2EFDA)
    color_primary = "006633"
    
    font_header_org = Font(name="Arial", size=11, bold=True, color=color_primary)
    font_sub_org = Font(name="Arial", size=8.5, italic=True, color="404040")
    font_title = Font(name="Arial", size=13, bold=True, color=color_primary)
    font_bold = Font(name="Arial", size=9, bold=True, color="000000")
    font_normal = Font(name="Arial", size=8.5, color="000000")
    font_small = Font(name="Arial", size=7.8, color="505050")
    font_th = Font(name="Arial", size=8.5, bold=True, color="FFFFFF")
    font_total = Font(name="Arial", size=9.5, bold=True, color=color_primary)

    fill_th = PatternFill(start_color=color_primary, end_color=color_primary, fill_type="solid")
    fill_zebra = PatternFill(start_color="F7FAF8", end_color="F7FAF8", fill_type="solid")
    fill_total = PatternFill(start_color="E2EFDA", end_color="E2EFDA", fill_type="solid")
    fill_box = PatternFill(start_color="F0F6F2", end_color="F0F6F2", fill_type="solid")

    thin_border = Border(
        left=Side(style='thin', color="B2D8C0"),
        right=Side(style='thin', color="B2D8C0"),
        top=Side(style='thin', color="B2D8C0"),
        bottom=Side(style='thin', color="B2D8C0")
    )
    total_border = Border(
        top=Side(style='medium', color=color_primary),
        bottom=Side(style='double', color=color_primary),
        left=Side(style='thin', color="B2D8C0"),
        right=Side(style='thin', color="B2D8C0")
    )

    # Largeurs de colonnes optimisées A4 Portrait (Total = 91)
    col_widths = {
        "A": 5,    # Item
        "B": 46,   # Description
        "C": 10,   # Quantité
        "D": 15,   # Prix Unitaire
        "E": 15    # Montant Total
    }
    for col, width in col_widths.items():
        ws.column_dimensions[col].width = width

    # En-tête émetteur
    ws.merge_cells("A1:C1")
    ws["A1"] = "SAHEL GRAPHIQUE & SÉCURITÉ INDUSTRIELLE (SGSI SA)"
    ws["A1"].font = font_header_org
    ws.row_dimensions[1].height = 18
    
    ws.merge_cells("A2:C2")
    ws["A2"] = "Solutions d'Étiquetage Technique, Marquage Métrologique & Systèmes de Sécurité"
    ws["A2"].font = font_sub_org
    ws.row_dimensions[2].height = 14
    
    ws.merge_cells("A3:C3")
    ws["A3"] = "Zone Industrielle Yantala, Rue ZI-14, BP 12 850 Niamey (Niger) | Tél: (+227) 20 75 18 90 / 90 22 34 56"
    ws["A3"].font = font_small
    ws.row_dimensions[3].height = 13

    ws.merge_cells("A4:C4")
    ws["A4"] = "NIF: 52189/S | RCCM: NI-NIA-2019-B-0895 | Email: commercial@sahel-graphique.ne"
    ws["A4"].font = font_small
    ws.row_dimensions[4].height = 13

    # Meta Proforma
    ws.merge_cells("D1:E1")
    ws["D1"] = "PROFORMA INVOICE B"
    ws["D1"].font = font_title
    ws["D1"].alignment = Alignment(horizontal="right", vertical="center")

    ws["D2"] = "Référence N° :"
    ws["D2"].font = font_bold
    ws["D2"].alignment = Alignment(horizontal="right", vertical="center")
    ws["E2"] = "SGSI/2026/PF-091"
    ws["E2"].font = font_bold
    ws["E2"].alignment = Alignment(horizontal="right", vertical="center")

    ws["D3"] = "Date d'émission :"
    ws["D3"].font = font_normal
    ws["D3"].alignment = Alignment(horizontal="right", vertical="center")
    ws["E3"] = "16/09/2026"
    ws["E3"].font = font_normal
    ws["E3"].alignment = Alignment(horizontal="right", vertical="center")

    ws["D4"] = "Délai de validité :"
    ws["D4"].font = font_normal
    ws["D4"].alignment = Alignment(horizontal="right", vertical="center")
    ws["E4"] = "90 jours"
    ws["E4"].font = font_normal
    ws["E4"].alignment = Alignment(horizontal="right", vertical="center")

    # Destinataire
    ws.row_dimensions[5].height = 6
    ws.merge_cells("A6:E6")
    ws["A6"] = "DESTINATAIRE : AGENCE NATIONALE DE LA MÉTROLOGIE ET DE LA CONFORMITÉ (ANMC)"
    ws["A6"].font = font_bold
    ws["A6"].fill = fill_box
    ws["A6"].alignment = Alignment(horizontal="left", vertical="center")
    ws.row_dimensions[6].height = 18

    ws.merge_cells("A7:C7")
    ws["A7"] = "Direction Générale — BP 10 700 Niamey (République du Niger)"
    ws["A7"].font = font_normal
    ws.row_dimensions[7].height = 14

    ws.merge_cells("D7:E7")
    ws["D7"] = "NIF Client : 82397/P"
    ws["D7"].font = font_bold
    ws["D7"].alignment = Alignment(horizontal="right", vertical="center")

    ws.merge_cells("A8:E8")
    ws["A8"] = "Objet : Offre pour étiquettes de métrologie et scellés de sécurité personnalisés (2027/2028)"
    ws["A8"].font = font_normal
    ws["A8"].alignment = Alignment(vertical="center")
    ws.row_dimensions[8].height = 15

    ws.row_dimensions[9].height = 6

    # Colonnes
    headers = [
        ("A10", "Item"),
        ("B10", "Description détaillée de la prestation / fourniture"),
        ("C10", "Quantité"),
        ("D10", "P.U. HT (FCFA)"),
        ("E10", "Total HT (FCFA)")
    ]
    for cell_ref, text in headers:
        cell = ws[cell_ref]
        cell.value = text
        cell.font = font_th
        cell.fill = fill_th
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    ws.row_dimensions[10].height = 22

    # Articles B (+35%)
    items_B = [
        (1, "Conception/Impression étiquette verte 9cm X 9cm (année 2027, n°6001 à 11000)", 5000, 200),
        (2, "Conception/Impression étiquette verte 9cm X 9cm (année 2028, n°0001 à 8000)", 8000, 200),
        (3, "Conception/Impression étiquette orange 9cm X 9cm (n°2001 à 4000)", 1000, 200),
        (4, "Conception/Impression étiquette rouge 9cm X 9cm (n°3001 à 4000)", 1000, 200),
        (5, "Conception/Impression étiquette verte 5,5cm X 5,5cm (année 2027, n°2501 à 3000)", 500, 140),
        (6, "Conception/Impression étiquette verte 5,5cm X 5,5cm (année 2028, n°0001 à 1000)", 1000, 140),
        (7, "Conception/Impression étiquette orange 5,5cm X 5,5cm (n°2001 à 3000)", 1000, 140),
        (8, "Conception/Impression étiquette rouge 5,5cm X 5,5cm (n°2001 à 3000)", 1000, 140),
        (9, "Conception/Impression étiquette verte 5cm X 2cm (année 2027, n°401 à 650)", 250, 120),
        (10, "Conception/Impression étiquette verte 5cm X 2cm (année 2028, n°1 à 250)", 250, 120),
        (11, "Scellé de sécurité personnalisés (câble acier & corps polycarbonate inviolable)", 1000, 1370),
    ]

    start_row = 11
    for i, (num, desc, qty, pu) in enumerate(items_B):
        r = start_row + i
        ws.row_dimensions[r].height = 17
        
        ws[f"A{r}"] = num
        ws[f"A{r}"].alignment = Alignment(horizontal="center", vertical="center")
        
        ws[f"B{r}"] = desc
        ws[f"B{r}"].alignment = Alignment(horizontal="left", vertical="center")
        
        ws[f"C{r}"] = qty
        ws[f"C{r}"].alignment = Alignment(horizontal="right", vertical="center")
        ws[f"C{r}"].number_format = "#,##0"
        
        ws[f"D{r}"] = pu
        ws[f"D{r}"].alignment = Alignment(horizontal="right", vertical="center")
        ws[f"D{r}"].number_format = "#,##0"
        
        ws[f"E{r}"] = f"=C{r}*D{r}"
        ws[f"E{r}"].alignment = Alignment(horizontal="right", vertical="center")
        ws[f"E{r}"].number_format = "#,##0"

        for c in ["A", "B", "C", "D", "E"]:
            ws[f"{c}{r}"].font = font_normal
            ws[f"{c}{r}"].border = thin_border
            if i % 2 == 1:
                ws[f"{c}{r}"].fill = fill_zebra

    # Total
    tot_row = start_row + len(items_B)
    ws.row_dimensions[tot_row].height = 20
    
    ws.merge_cells(f"A{tot_row}:D{tot_row}")
    ws[f"A{tot_row}"] = "TOTAL GÉNÉRAL HORS TAXES (HT) FCFA"
    ws[f"A{tot_row}"].font = font_total
    ws[f"A{tot_row}"].alignment = Alignment(horizontal="right", vertical="center")
    ws[f"A{tot_row}"].fill = fill_total

    ws[f"E{tot_row}"] = f"=SUM(E{start_row}:E{tot_row-1})"
    ws[f"E{tot_row}"].font = font_total
    ws[f"E{tot_row}"].alignment = Alignment(horizontal="right", vertical="center")
    ws[f"E{tot_row}"].number_format = "#,##0"
    ws[f"E{tot_row}"].fill = fill_total

    for c in ["A", "B", "C", "D", "E"]:
        ws[f"{c}{tot_row}"].border = total_border

    # Lettres
    r_words = tot_row + 2
    ws.row_dimensions[tot_row+1].height = 6
    ws.merge_cells(f"A{r_words}:E{r_words}")
    ws[f"A{r_words}"] = "Arrêtée la présente facture proforma à la somme de : QUATRE MILLIONS NEUF CENT VINGT MILLE (4 920 000) FCFA HT."
    ws[f"A{r_words}"].font = font_bold
    ws[f"A{r_words}"].alignment = Alignment(horizontal="left", vertical="center")
    ws.row_dimensions[r_words].height = 17

    # Conditions
    r_cond = r_words + 2
    ws.row_dimensions[r_words+1].height = 6
    ws.merge_cells(f"A{r_cond}:C{r_cond}")
    ws[f"A{r_cond}"] = "TERMES ET CONDITIONS D'EXÉCUTION :"
    ws[f"A{r_cond}"].font = font_bold
    ws.row_dimensions[r_cond].height = 15

    conds = [
        "• Délai de livraison : 35 à 50 jours calendaires après signature du contrat et approbation du BAT.",
        "• Conditions de règlement : 50% d'acompte à la commande, solde à la livraison sur facture définitive.",
        "• Spécifications : Support polyester indéchirable, adhésif renforcé résistant aux solvants et aux UV.",
        "• Domiciliation : BANK OF AFRICA (BOA NIGER) Niamey | N° Compte: 00125478901-54 | Clé: 18"
    ]
    for idx, ctext in enumerate(conds):
        row_c = r_cond + 1 + idx
        ws.merge_cells(f"A{row_c}:C{row_c}")
        ws[f"A{row_c}"] = ctext
        ws[f"A{row_c}"].font = font_small
        ws.row_dimensions[row_c].height = 13

    # Signature
    ws.merge_cells(f"D{r_cond}:E{r_cond}")
    ws[f"D{r_cond}"] = "Pour SGSI SA"
    ws[f"D{r_cond}"].font = font_bold
    ws[f"D{r_cond}"].alignment = Alignment(horizontal="center", vertical="center")

    ws.merge_cells(f"D{r_cond+1}:E{r_cond+1}")
    ws[f"D{r_cond+1}"] = "Le Directeur Général"
    ws[f"D{r_cond+1}"].font = font_normal
    ws[f"D{r_cond+1}"].alignment = Alignment(horizontal="center", vertical="center")

    ws.merge_cells(f"D{r_cond+2}:E{r_cond+4}")
    ws[f"D{r_cond+2}"] = "[Cachet & Signature]"
    ws[f"D{r_cond+2}"].font = font_sub_org
    ws[f"D{r_cond+2}"].alignment = Alignment(horizontal="center", vertical="center")

    # Footer
    r_foot = r_cond + 5
    ws.row_dimensions[r_foot].height = 16
    ws.merge_cells(f"A{r_foot}:E{r_foot}")
    ws[f"A{r_foot}"] = "« SGSI SA — Société Anonyme au capital de 25 000 000 FCFA — Niamey, Niger »"
    ws[f"A{r_foot}"].font = Font(name="Arial", size=7.5, italic=True, color="FFFFFF")
    ws[f"A{r_foot}"].fill = fill_th
    ws[f"A{r_foot}"].alignment = Alignment(horizontal="center", vertical="center")

    # Configuration Impression A4
    apply_print_setup(ws, orientation="portrait", print_area=f"A1:E{r_foot}")

    wb.save(filepath)
    print(f"[OK] Classeur adapté pour impression A4 : {filepath}")


def create_comparative_table(filepath="/workspace/proformas-concurrentes/Tableau_Comparatif_Offres_ANMC.xlsx"):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Comparatif des 3 Offres"
    ws.views.sheetView[0].showGridLines = True

    font_title = Font(name="Calibri", size=13, bold=True, color="1F4E79")
    font_sub = Font(name="Calibri", size=9, italic=True, color="595959")
    font_bold = Font(name="Calibri", size=9, bold=True, color="000000")
    font_normal = Font(name="Calibri", size=8.5, color="000000")
    font_th = Font(name="Calibri", size=9, bold=True, color="FFFFFF")

    fill_th = PatternFill(start_color="1F4E79", end_color="1F4E79", fill_type="solid")
    fill_winner = PatternFill(start_color="E2EFDA", end_color="E2EFDA", fill_type="solid")
    fill_light = PatternFill(start_color="F2F5F9", end_color="F2F5F9", fill_type="solid")

    thin_border = Border(
        left=Side(style='thin', color="BFBFBF"),
        right=Side(style='thin', color="BFBFBF"),
        top=Side(style='thin', color="BFBFBF"),
        bottom=Side(style='thin', color="BFBFBF")
    )
    thick_border = Border(
        top=Side(style='medium', color="1F4E79"),
        bottom=Side(style='double', color="1F4E79"),
        left=Side(style='thin', color="BFBFBF"),
        right=Side(style='thin', color="BFBFBF")
    )

    # Largeurs de colonnes optimisées A4 Paysage (Total = 135)
    col_widths = {
        "A": 5,    # N°
        "B": 44,   # Désignation
        "C": 10,   # Quantité
        "D": 19,   # Offre 1 (Niger Certify)
        "E": 19,   # Offre 2 (IMS SARL)
        "F": 19,   # Offre 3 (SGSI SA)
        "G": 19    # Écart vs Offre 3
    }
    for col, width in col_widths.items():
        ws.column_dimensions[col].width = width

    # Titre
    ws.merge_cells("A1:G1")
    ws["A1"] = "TABLEAU COMPARATIF D'ANALYSE DES OFFRES FINANCIÈRES — ANMC"
    ws["A1"].font = font_title
    ws["A1"].alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 20

    ws.merge_cells("A2:G2")
    ws["A2"] = "Dossier de consultation / Procédure de mise en concurrence à 3 devis contradictoires (Réf. Client : NIF 82397/P)"
    ws["A2"].font = font_sub
    ws["A2"].alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[2].height = 14

    ws.row_dimensions[3].height = 6

    # En-têtes
    headers = [
        ("A4", "N°"),
        ("B4", "Désignation des Fournitures"),
        ("C4", "Quantité"),
        ("D4", "Offre 1 : Niger CERTIFY\n(Moins-disant / Retenu)"),
        ("E4", "Offre 2 : IMS SARL\n(Facture A : +30%)"),
        ("F4", "Offre 3 : SGSI SA\n(Facture B : +35%)"),
        ("G4", "Écart Financier\n(Offre 1 vs Offre 3)")
    ]

    for cell_ref, text in headers:
        cell = ws[cell_ref]
        cell.value = text
        cell.font = font_th
        cell.fill = fill_th
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    ws.row_dimensions[4].height = 26

    # Données
    items_comp = [
        (1, "Étiquette verte 9cm X 9cm (2027, n°6001 à 11000)", 5000, 750000, 975000, 1000000),
        (2, "Étiquette verte 9cm X 9cm (2028, n°0001 à 8000)", 8000, 1200000, 1560000, 1600000),
        (3, "Étiquette orange 9cm X 9cm (n°2001 à 4000)", 1000, 150000, 195000, 200000),
        (4, "Étiquette rouge 9cm X 9cm (n°3001 à 4000)", 1000, 150000, 195000, 200000),
        (5, "Étiquette verte 5,5cm X 5,5cm (2027, n°2501 à 3000)", 500, 50000, 65000, 70000),
        (6, "Étiquette verte 5,5cm X 5,5cm (2028, n°0001 à 1000)", 1000, 100000, 130000, 140000),
        (7, "Étiquette orange 5,5cm X 5,5cm (n°2001 à 3000)", 1000, 100000, 130000, 140000),
        (8, "Étiquette rouge 5,5cm X 5,5cm (n°2001 à 3000)", 1000, 100000, 130000, 140000),
        (9, "Étiquette verte 5cm X 2cm (2027, n°401 à 650)", 250, 22500, 29250, 30000),
        (10, "Étiquette verte 5cm X 2cm (2028, n°1 à 250)", 250, 22500, 29250, 30000),
        (11, "Scellé de sécurité personnalisés (x1 000)", 1000, 1000000, 1300000, 1370000),
    ]

    for idx, (num, desc, qty, m1, m2, m3) in enumerate(items_comp):
        r = 5 + idx
        ws.row_dimensions[r].height = 17
        ws[f"A{r}"] = num
        ws[f"A{r}"].alignment = Alignment(horizontal="center", vertical="center")
        
        ws[f"B{r}"] = desc
        ws[f"B{r}"].alignment = Alignment(horizontal="left", vertical="center")
        
        ws[f"C{r}"] = qty
        ws[f"C{r}"].alignment = Alignment(horizontal="right", vertical="center")
        ws[f"C{r}"].number_format = "#,##0"
        
        ws[f"D{r}"] = m1
        ws[f"D{r}"].alignment = Alignment(horizontal="right", vertical="center")
        ws[f"D{r}"].number_format = "#,##0"
        ws[f"D{r}"].fill = fill_winner
        
        ws[f"E{r}"] = m2
        ws[f"E{r}"].alignment = Alignment(horizontal="right", vertical="center")
        ws[f"E{r}"].number_format = "#,##0"
        
        ws[f"F{r}"] = m3
        ws[f"F{r}"].alignment = Alignment(horizontal="right", vertical="center")
        ws[f"F{r}"].number_format = "#,##0"

        ws[f"G{r}"] = f"=F{r}-D{r}"
        ws[f"G{r}"].alignment = Alignment(horizontal="right", vertical="center")
        ws[f"G{r}"].number_format = "+#,##0"

        for c in ["A", "B", "C", "D", "E", "F", "G"]:
            ws[f"{c}{r}"].font = font_normal
            ws[f"{c}{r}"].border = thin_border
            if idx % 2 == 1 and c != "D":
                ws[f"{c}{r}"].fill = fill_light

    # Ligne Totaux
    r_tot = 5 + len(items_comp)
    ws.row_dimensions[r_tot].height = 20
    
    ws.merge_cells(f"A{r_tot}:C{r_tot}")
    ws[f"A{r_tot}"] = "TOTAL MONTANT HORS TAXES (HT) FCFA"
    ws[f"A{r_tot}"].font = font_bold
    ws[f"A{r_tot}"].alignment = Alignment(horizontal="right", vertical="center")

    ws[f"D{r_tot}"] = f"=SUM(D5:D{r_tot-1})"
    ws[f"D{r_tot}"].font = font_bold
    ws[f"D{r_tot}"].fill = fill_winner
    ws[f"D{r_tot}"].alignment = Alignment(horizontal="right", vertical="center")
    ws[f"D{r_tot}"].number_format = "#,##0"

    ws[f"E{r_tot}"] = f"=SUM(E5:E{r_tot-1})"
    ws[f"E{r_tot}"].font = font_bold
    ws[f"E{r_tot}"].alignment = Alignment(horizontal="right", vertical="center")
    ws[f"E{r_tot}"].number_format = "#,##0"

    ws[f"F{r_tot}"] = f"=SUM(F5:F{r_tot-1})"
    ws[f"F{r_tot}"].font = font_bold
    ws[f"F{r_tot}"].alignment = Alignment(horizontal="right", vertical="center")
    ws[f"F{r_tot}"].number_format = "#,##0"

    ws[f"G{r_tot}"] = f"=F{r_tot}-D{r_tot}"
    ws[f"G{r_tot}"].font = font_bold
    ws[f"G{r_tot}"].alignment = Alignment(horizontal="right", vertical="center")
    ws[f"G{r_tot}"].number_format = "+#,##0"

    for c in ["A", "B", "C", "D", "E", "F", "G"]:
        ws[f"{c}{r_tot}"].border = thick_border

    # Ligne Pourcentage
    r_pct = r_tot + 1
    ws.row_dimensions[r_pct].height = 18
    ws.merge_cells(f"A{r_pct}:C{r_pct}")
    ws[f"A{r_pct}"] = "Écart en % vs Offre Moins-Disante"
    ws[f"A{r_pct}"].font = font_bold
    ws[f"A{r_pct}"].alignment = Alignment(horizontal="right", vertical="center")

    ws[f"D{r_pct}"] = "RÉFÉRENCE (0%)"
    ws[f"D{r_pct}"].font = font_bold
    ws[f"D{r_pct}"].alignment = Alignment(horizontal="center", vertical="center")
    ws[f"D{r_pct}"].fill = fill_winner

    ws[f"E{r_pct}"] = f"=(E{r_tot}-D{r_tot})/D{r_tot}"
    ws[f"E{r_pct}"].font = font_bold
    ws[f"E{r_pct}"].alignment = Alignment(horizontal="right", vertical="center")
    ws[f"E{r_pct}"].number_format = "+0.0%"

    ws[f"F{r_pct}"] = f"=(F{r_tot}-D{r_tot})/D{r_tot}"
    ws[f"F{r_pct}"].font = font_bold
    ws[f"F{r_pct}"].alignment = Alignment(horizontal="right", vertical="center")
    ws[f"F{r_pct}"].number_format = "+0.0%"

    ws[f"G{r_pct}"] = "Économie ANMC"
    ws[f"G{r_pct}"].font = font_bold
    ws[f"G{r_pct}"].alignment = Alignment(horizontal="center", vertical="center")

    # Conclusion de l'évaluation
    r_concl = r_pct + 2
    ws.row_dimensions[r_pct+1].height = 6
    ws.merge_cells(f"A{r_concl}:G{r_concl}")
    ws[f"A{r_concl}"] = "CONCLUSION & RECOMMANDATION D'ATTRIBUTION :"
    ws[f"A{r_concl}"].font = font_bold
    ws.row_dimensions[r_concl].height = 16

    recom_text = (
        "L'offre soumise par Niger CERTIFY d'un montant de 3 645 000 FCFA HT est l'offre la moins-disante et la plus avantageuse pour l'ANMC. "
        "Elle dégage une économie de 1 093 500 FCFA (-23,1%) par rapport à l'Offre A (IMS SARL) et de 1 275 000 FCFA (-25,9%) par rapport à l'Offre B (SGSI SA). "
        "Recommandation : Attribution définitive du marché à Niger CERTIFY."
    )
    ws.merge_cells(f"A{r_concl+1}:G{r_concl+2}")
    ws[f"A{r_concl+1}"] = recom_text
    ws[f"A{r_concl+1}"].font = font_bold
    ws[f"A{r_concl+1}"].fill = fill_winner
    ws[f"A{r_concl+1}"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
    ws.row_dimensions[r_concl+1].height = 18
    ws.row_dimensions[r_concl+2].height = 18

    # Configuration Impression A4 Paysage
    apply_print_setup(ws, orientation="landscape", print_area=f"A1:G{r_concl+2}")

    wb.save(filepath)
    print(f"[OK] Classeur comparatif adapté pour impression A4 : {filepath}")


if __name__ == "__main__":
    create_proforma_anper()
    create_proforma_giz()
    create_comparative_table()
