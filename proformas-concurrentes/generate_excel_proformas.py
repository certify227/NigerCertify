"""
Script de génération des deux factures proforma concurrentes :
- Facture A (Modèle ANPER / Entreprise A, majoration +30% : 4 738 500 FCFA HT)
- Facture B (Modèle GIZ / Entreprise B, majoration +35% : 4 920 000 FCFA HT)
Et du tableau comparatif d'analyse des offres.
"""

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

def create_proforma_anper(filepath="/workspace/proformas-concurrentes/Proforma_Anper.xlsx"):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Facture Proforma A"
    ws.views.sheetView[0].showGridLines = True

    # Palette ANPER / Entreprise A : Bleu Roi (#1F4E79), Bleu Ciel (#D9E1F2), Accent Or (#C55A11)
    color_primary = "1F4E79"
    color_light = "EDF2F8"
    color_accent = "C55A11"
    color_border = "D9D9D9"
    
    font_header_org = Font(name="Calibri", size=14, bold=True, color=color_primary)
    font_sub_org = Font(name="Calibri", size=9, italic=True, color="595959")
    font_title = Font(name="Calibri", size=16, bold=True, color=color_primary)
    font_bold = Font(name="Calibri", size=10, bold=True, color="000000")
    font_normal = Font(name="Calibri", size=10, color="000000")
    font_small = Font(name="Calibri", size=8.5, color="595959")
    font_th = Font(name="Calibri", size=10, bold=True, color="FFFFFF")
    font_total = Font(name="Calibri", size=11, bold=True, color="1F4E79")

    fill_th = PatternFill(start_color=color_primary, end_color=color_primary, fill_type="solid")
    fill_subth = PatternFill(start_color="2F5597", end_color="2F5597", fill_type="solid")
    fill_zebra = PatternFill(start_color="F2F5F9", end_color="F2F5F9", fill_type="solid")
    fill_total = PatternFill(start_color="D9E1F2", end_color="D9E1F2", fill_type="solid")
    fill_box = PatternFill(start_color="F9FAFB", end_color="F9FAFB", fill_type="solid")

    thin_border = Border(
        left=Side(style='thin', color="BFBFBF"),
        right=Side(style='thin', color="BFBFBF"),
        top=Side(style='thin', color="BFBFBF"),
        bottom=Side(style='thin', color="BFBFBF")
    )
    total_border = Border(
        top=Side(style='thin', color="1F4E79"),
        bottom=Side(style='double', color="1F4E79")
    )

    # Ligne 1-3 : En-tête émetteur
    ws.merge_cells("A1:C1")
    ws["A1"] = "IMPRIMERIE & MULTISERVICES DU SAHEL (IMS SARL)"
    ws["A1"].font = font_header_org
    
    ws.merge_cells("A2:C2")
    ws["A2"] = "Imprimerie Offset, Sérigraphie Industrielle & Fournitures Générales"
    ws["A2"].font = font_sub_org
    
    ws.merge_cells("A3:C3")
    ws["A3"] = "Quartier Nouveau Marché, BP 11 204 Niamey — Niger | Tél: (+227) 20 73 45 12 / 96 45 10 20"
    ws["A3"].font = font_small

    ws.merge_cells("A4:C4")
    ws["A4"] = "NIF: 45128/R | RCCM: NI-NIA-2021-B-1420 | Régime: Réel Simplifié"
    ws["A4"].font = font_small

    # Bloc Meta Proforma (Droite)
    ws.merge_cells("D1:E1")
    ws["D1"] = "FACTURE PROFORMA"
    ws["D1"].font = font_title
    ws["D1"].alignment = Alignment(horizontal="right")

    ws["D2"] = "N° Proforma :"
    ws["D2"].font = font_bold
    ws["D2"].alignment = Alignment(horizontal="right")
    ws["E2"] = "FP-2026/09-084"
    ws["E2"].font = font_bold

    ws["D3"] = "Date :"
    ws["D3"].font = font_normal
    ws["D3"].alignment = Alignment(horizontal="right")
    ws["E3"] = "15/09/2026"
    ws["E3"].font = font_normal

    ws["D4"] = "Validité de l'offre :"
    ws["D4"].font = font_normal
    ws["D4"].alignment = Alignment(horizontal="right")
    ws["E4"] = "60 jours"
    ws["E4"].font = font_normal

    # Ligne 6-8 : Client ANMC
    ws.merge_cells("A6:E6")
    ws["A6"] = "CLIENT / BÉNÉFICIAIRE : AGENCE NATIONALE DE LA MÉTROLOGIE ET DE LA CONFORMITÉ (ANMC)"
    ws["A6"].font = font_bold
    ws["A6"].fill = fill_box
    ws["A6"].alignment = Alignment(horizontal="left", vertical="center")

    ws.merge_cells("A7:C7")
    ws["A7"] = "Adresse : BP 10 700 Niamey — République du Niger"
    ws["A7"].font = font_normal

    ws.merge_cells("D7:E7")
    ws["D7"] = "NIF Client : 82397/P"
    ws["D7"].font = font_bold

    ws.merge_cells("A8:E8")
    ws["A8"] = "Objet : Fourniture d'étiquettes de contrôle métrologique et de scellés de sécurité (Exercices 2027 - 2028)"
    ws["A8"].font = font_normal
    ws["A8"].alignment = Alignment(vertical="center")

    # Ligne 10 : En-têtes du tableau
    headers = [
        ("A10", "N°", 5),
        ("B10", "Désignation / Nature de la commande", 52),
        ("C10", "Quantité", 14),
        ("D10", "Prix Unitaire HT (FCFA)", 22),
        ("E10", "Montant Total HT (FCFA)", 24)
    ]
    for cell_ref, text, width in headers:
        cell = ws[cell_ref]
        cell.value = text
        cell.font = font_th
        cell.fill = fill_th
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        col_letter = cell_ref[0]
        ws.column_dimensions[col_letter].width = width

    ws.row_dimensions[10].height = 26

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
        (11, "Scellé de sécurité personnalisés (gravure laser / numérotation consécutive)", 1000, 1300),
    ]

    start_row = 11
    for i, (num, desc, qty, pu) in enumerate(items_A):
        r = start_row + i
        ws.row_dimensions[r].height = 22
        
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
    ws.row_dimensions[tot_row].height = 25
    
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
    ws.merge_cells(f"A{r_words}:E{r_words}")
    ws[f"A{r_words}"] = "Arrêtée la présente facture proforma à la somme de : QUATRE MILLIONS SEPT CENT TRENTE-HUIT MILLE CINQ CENTS (4 738 500) FRANCS CFA HORS TAXES."
    ws[f"A{r_words}"].font = font_bold
    ws[f"A{r_words}"].alignment = Alignment(horizontal="left", vertical="center")

    # Conditions commerciales
    r_cond = r_words + 2
    ws[f"A{r_cond}"] = "MODALITÉS ET CONDITIONS COMMERCIALES :"
    ws[f"A{r_cond}"].font = font_bold

    conds = [
        "• Délai de livraison : 30 à 45 jours ouvrables après réception du bon de commande officiel et validation des maquettes (BAT).",
        "• Modalités de paiement : 40% d'acompte à la commande, 60% solde par chèque ou virement bancaire après livraison et réception.",
        "• Spécifications techniques : Papier vinyle adhésif haute résistance, encres traitées anti-UV pour étiquettes métrologiques.",
        "• Coordonnées Bancaires : BIA-NIGER Niamey | Code Banque: NE034 | Guichet: 01001 | Compte: 02511488901 | Clé: 42"
    ]
    for idx, ctext in enumerate(conds):
        row_c = r_cond + 1 + idx
        ws.merge_cells(f"A{row_c}:E{row_c}")
        ws[f"A{row_c}"] = ctext
        ws[f"A{row_c}"].font = font_small

    # Bloc signature
    r_sig = r_cond + 6
    ws[f"D{r_sig}"] = "Pour l'Imprimerie IMS SARL,"
    ws[f"D{r_sig}"].font = font_bold
    ws[f"D{r_sig+1}"] = "La Direction Commerciale"
    ws[f"D{r_sig+1}"].font = font_normal
    ws[f"D{r_sig+2}"] = "[Cachet & Signature]"
    ws[f"D{r_sig+2}"].font = font_sub_org

    wb.save(filepath)
    print(f"[OK] Classeur généré : {filepath}")


def create_proforma_giz(filepath="/workspace/proformas-concurrentes/Pro_forma_GIZ.xlsx"):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Facture Proforma B"
    ws.views.sheetView[0].showGridLines = True

    # Palette GIZ / Entreprise B : Vert Forêt Institutionnel (#006633), Vert Sauge (#E2EFDA), Gris Pro
    color_primary = "006633"
    color_sub = "375623"
    color_light = "F2F8F4"
    color_total = "E2EFDA"

    font_header_org = Font(name="Arial", size=13, bold=True, color=color_primary)
    font_sub_org = Font(name="Arial", size=9, italic=True, color="404040")
    font_title = Font(name="Arial", size=15, bold=True, color=color_primary)
    font_bold = Font(name="Arial", size=9.5, bold=True, color="000000")
    font_normal = Font(name="Arial", size=9.5, color="000000")
    font_small = Font(name="Arial", size=8.5, color="505050")
    font_th = Font(name="Arial", size=9.5, bold=True, color="FFFFFF")
    font_total = Font(name="Arial", size=10.5, bold=True, color=color_primary)

    fill_th = PatternFill(start_color=color_primary, end_color=color_primary, fill_type="solid")
    fill_zebra = PatternFill(start_color="F7FAF8", end_color="F7FAF8", fill_type="solid")
    fill_total = PatternFill(start_color=color_total, end_color=color_total, fill_type="solid")
    fill_box = PatternFill(start_color="F0F4F1", end_color="F0F4F1", fill_type="solid")

    thin_border = Border(
        left=Side(style='thin', color="C0C0C0"),
        right=Side(style='thin', color="C0C0C0"),
        top=Side(style='thin', color="C0C0C0"),
        bottom=Side(style='thin', color="C0C0C0")
    )
    total_border = Border(
        top=Side(style='thin', color=color_primary),
        bottom=Side(style='double', color=color_primary)
    )

    # En-tête Prestataire B (Graphique & Sécurité)
    ws.merge_cells("A1:C1")
    ws["A1"] = "SAHEL GRAPHIQUE & SÉCURITÉ INDUSTRIELLE (SGSI SA)"
    ws["A1"].font = font_header_org
    
    ws.merge_cells("A2:C2")
    ws["A2"] = "Solutions d'Étiquetage Technique, Marquage Métrologique & Systèmes de Sécurité"
    ws["A2"].font = font_sub_org
    
    ws.merge_cells("A3:C3")
    ws["A3"] = "Zone Industrielle Yantala, Rue ZI-14, BP 12 850 Niamey — Niger | Tél: (+227) 20 75 18 90 / 90 22 34 56"
    ws["A3"].font = font_small

    ws.merge_cells("A4:C4")
    ws["A4"] = "NIF: 52189/S | RCCM: NI-NIA-2019-B-0895 | Email: commercial@sahel-graphique.ne"
    ws["A4"].font = font_small

    # Meta Proforma
    ws.merge_cells("D1:E1")
    ws["D1"] = "PROFORMA INVOICE"
    ws["D1"].font = font_title
    ws["D1"].alignment = Alignment(horizontal="right")

    ws["D2"] = "Référence N° :"
    ws["D2"].font = font_bold
    ws["D2"].alignment = Alignment(horizontal="right")
    ws["E2"] = "SGSI/2026/PF-091"
    ws["E2"].font = font_bold

    ws["D3"] = "Date d'émission :"
    ws["D3"].font = font_normal
    ws["D3"].alignment = Alignment(horizontal="right")
    ws["E3"] = "16/09/2026"
    ws["E3"].font = font_normal

    ws["D4"] = "Délai de validité :"
    ws["D4"].font = font_normal
    ws["D4"].alignment = Alignment(horizontal="right")
    ws["E4"] = "90 jours"
    ws["E4"].font = font_normal

    # Bloc Destinataire
    ws.merge_cells("A6:E6")
    ws["A6"] = "ORGANISME DESTINATAIRE : AGENCE NATIONALE DE LA MÉTROLOGIE ET DE LA CONFORMITÉ (ANMC)"
    ws["A6"].font = font_bold
    ws["A6"].fill = fill_box
    ws["A6"].alignment = Alignment(horizontal="left", vertical="center")

    ws.merge_cells("A7:C7")
    ws["A7"] = "Direction Générale — BP 10 700 Niamey (Niger)"
    ws["A7"].font = font_normal

    ws.merge_cells("D7:E7")
    ws["D7"] = "Identifiant Fiscal NIF : 82397/P"
    ws["D7"].font = font_bold

    ws.merge_cells("A8:E8")
    ws["A8"] = "Objet : Offre de prix pour étiquettes de métrologie et scellés de sécurité personnalisés (campagnes 2027/2028)"
    ws["A8"].font = font_normal
    ws["A8"].alignment = Alignment(vertical="center")

    # En-têtes colonnes
    headers = [
        ("A10", "Item", 6),
        ("B10", "Description détaillée de la prestation / fourniture", 54),
        ("C10", "Quantité", 14),
        ("D10", "Prix Unitaire HT (FCFA)", 22),
        ("E10", "Montant Total HT (FCFA)", 24)
    ]
    for cell_ref, text, width in headers:
        cell = ws[cell_ref]
        cell.value = text
        cell.font = font_th
        cell.fill = fill_th
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        col_letter = cell_ref[0]
        ws.column_dimensions[col_letter].width = width

    ws.row_dimensions[10].height = 26

    # Articles Facture B : +35% (Prix unitaire 200, 140, 120, 1370 -> Total exact 4 920 000 FCFA HT)
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
        ws.row_dimensions[r].height = 22
        
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
    ws.row_dimensions[tot_row].height = 25
    
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

    # Montant en toutes lettres
    r_words = tot_row + 2
    ws.merge_cells(f"A{r_words}:E{r_words}")
    ws[f"A{r_words}"] = "Arrêtée la présente facture proforma à la somme de : QUATRE MILLIONS NEUF CENT VINGT MILLE (4 920 000) FRANCS CFA HORS TAXES."
    ws[f"A{r_words}"].font = font_bold
    ws[f"A{r_words}"].alignment = Alignment(horizontal="left", vertical="center")

    # Conditions de livraison & paiement
    r_cond = r_words + 2
    ws[f"A{r_cond}"] = "TERMES ET CONDITIONS D'EXÉCUTION :"
    ws[f"A{r_cond}"].font = font_bold

    conds = [
        "• Délai de livraison : 35 à 50 jours calendaires après validation définitive du Bon À Tirer (BAT) et signature du marché.",
        "• Conditions de règlement : 50% d'acompte à la commande, solde à la livraison sur présentation de la facture définitive.",
        "• Garantie qualité : Matière polyester indéchirable, adhésif renforcé résistant aux solvants, intempéries et écarts thermiques.",
        "• Domiciliation bancaire : BANK OF AFRICA (BOA NIGER) Niamey | N° Compte: 00125478901-54 | Clé: 18"
    ]
    for idx, ctext in enumerate(conds):
        row_c = r_cond + 1 + idx
        ws.merge_cells(f"A{row_c}:E{row_c}")
        ws[f"A{row_c}"] = ctext
        ws[f"A{row_c}"].font = font_small

    # Signature
    r_sig = r_cond + 6
    ws[f"D{r_sig}"] = "Pour SGSI SA,"
    ws[f"D{r_sig}"].font = font_bold
    ws[f"D{r_sig+1}"] = "Le Directeur Général"
    ws[f"D{r_sig+1}"].font = font_normal
    ws[f"D{r_sig+2}"] = "[Cachet & Signature Électronique]"
    ws[f"D{r_sig+2}"].font = font_sub_org

    wb.save(filepath)
    print(f"[OK] Classeur généré : {filepath}")


def create_comparative_table(filepath="/workspace/proformas-concurrentes/Tableau_Comparatif_Offres_ANMC.xlsx"):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Comparatif des 3 Offres"
    ws.views.sheetView[0].showGridLines = True

    font_title = Font(name="Calibri", size=15, bold=True, color="1F4E79")
    font_bold = Font(name="Calibri", size=10, bold=True, color="000000")
    font_normal = Font(name="Calibri", size=9.5, color="000000")
    font_th = Font(name="Calibri", size=10, bold=True, color="FFFFFF")
    font_recom = Font(name="Calibri", size=11, bold=True, color="006600")

    fill_th = PatternFill(start_color="1F4E79", end_color="1F4E79", fill_type="solid")
    fill_winner = PatternFill(start_color="E2EFDA", end_color="E2EFDA", fill_type="solid")
    fill_a = PatternFill(start_color="F2F5F9", end_color="F2F5F9", fill_type="solid")
    fill_b = PatternFill(start_color="FFF2CC", end_color="FFF2CC", fill_type="solid")

    thin_border = Border(
        left=Side(style='thin', color="BFBFBF"),
        right=Side(style='thin', color="BFBFBF"),
        top=Side(style='thin', color="BFBFBF"),
        bottom=Side(style='thin', color="BFBFBF")
    )
    thick_border = Border(
        top=Side(style='medium', color="1F4E79"),
        bottom=Side(style='double', color="1F4E79")
    )

    # Titre
    ws.merge_cells("A1:G1")
    ws["A1"] = "TABLEAU COMPARATIF D'ANALYSE DES OFFRES FINANCIÈRES — FOURNITURE ÉTIQUETTES & SCELLÉS ANMC"
    ws["A1"].font = font_title
    ws["A1"].alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 30

    ws.merge_cells("A2:G2")
    ws["A2"] = "Dossier de consultation / Procédure de mise en concurrence à 3 devis contradictoires (Réf. Client : NIF 82397/P)"
    ws["A2"].font = Font(name="Calibri", size=10, italic=True, color="595959")
    ws["A2"].alignment = Alignment(horizontal="center", vertical="center")

    # En-têtes
    headers = [
        ("A4", "N°", 5),
        ("B4", "Désignation des Fournitures", 48),
        ("C4", "Quantité", 12),
        ("D4", "Offre 1 : Niger CERTIFY\n(Moins-disant / Retenu)", 22),
        ("E4", "Offre 2 : Imprimerie IMS SARL\n(Facture A : +30%)", 22),
        ("F4", "Offre 3 : SGSI SA\n(Facture B : +35%)", 22),
        ("G4", "Écart Financier\n(Offre 1 vs Offre 3)", 18)
    ]

    for cell_ref, text, width in headers:
        cell = ws[cell_ref]
        cell.value = text
        cell.font = font_th
        cell.fill = fill_th
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        col_letter = cell_ref[0]
        ws.column_dimensions[col_letter].width = width

    ws.row_dimensions[4].height = 34

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
        ws.row_dimensions[r].height = 20
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

    # Ligne Totaux
    r_tot = 5 + len(items_comp)
    ws.row_dimensions[r_tot].height = 24
    
    ws.merge_cells(f"A{r_tot}:C{r_tot}")
    ws[f"A{r_tot}"] = "TOTAL MONTANT HORS TAXES (HT)"
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

    # Ligne Pourcentage d'écart
    r_pct = r_tot + 1
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

    # Conclusion / Recommandation de sélection
    r_concl = r_pct + 2
    ws.merge_cells(f"A{r_concl}:G{r_concl}")
    ws[f"A{r_concl}"] = "CONCLUSION DE L'ÉVALUATION FINANCIÈRE :"
    ws[f"A{r_concl}"].font = font_bold

    recom_text = (
        "L'offre soumise par Niger CERTIFY d'un montant de 3 645 000 FCFA HT est l'offre la moins-disante et la plus avantageuse pour l'ANMC.\n"
        "Elle présente une économie de 1 093 500 FCFA (-23,1%) par rapport à l'Offre A (IMS SARL) et de 1 275 000 FCFA (-25,9%) par rapport à l'Offre B (SGSI SA).\n"
        "Recommandation : Attribution définitive du marché de confection des étiquettes et scellés à Niger CERTIFY."
    )
    ws.merge_cells(f"A{r_concl+1}:G{r_concl+3}")
    ws[f"A{r_concl+1}"] = recom_text
    ws[f"A{r_concl+1}"].font = font_bold
    ws[f"A{r_concl+1}"].fill = fill_winner
    ws[f"A{r_concl+1}"].alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

    wb.save(filepath)
    print(f"[OK] Classeur comparatif généré : {filepath}")


if __name__ == "__main__":
    create_proforma_anper()
    create_proforma_giz()
    create_comparative_table()
