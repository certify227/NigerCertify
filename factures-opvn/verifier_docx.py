# -*- coding: utf-8 -*-
"""Vérifie qu'un DOCX généré respecte l'ordre des balises WordprocessingML.

Word refuse d'ouvrir un document dont les propriétés (rPr, pPr, tcPr…) ne
suivent pas l'ordre du schéma, là où LibreOffice reste tolérant. Ce contrôle
évite de livrer un fichier « illisible » sans s'en apercevoir.

    python3 verifier_docx.py fichier1.docx [fichier2.docx ...]
"""

import sys
import zipfile

from lxml import etree

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

SEQUENCES = {
    "rPr": ("rStyle rFonts b bCs i iCs caps smallCaps strike dstrike outline "
            "shadow emboss imprint noProof snapToGrid vanish webHidden color "
            "spacing w kern position sz szCs highlight u effect bdr shd "
            "fitText vertAlign rtl cs em lang eastAsianLayout specVanish "
            "oMath"),
    "pPr": ("pStyle keepNext keepLines pageBreakBefore framePr widowControl "
            "numPr suppressLineNumbers pBdr shd tabs suppressAutoHyphens "
            "kinsoku wordWrap overflowPunct topLinePunct autoSpaceDE "
            "autoSpaceDN bidi adjustRightInd snapToGrid spacing ind "
            "contextualSpacing mirrorIndents suppressOverlap jc "
            "textDirection textAlignment textboxTightWrap outlineLvl divId "
            "cnfStyle rPr sectPr pPrChange"),
    "tcPr": ("cnfStyle tcW gridSpan hMerge vMerge tcBorders shd noWrap tcMar "
             "textDirection tcFitText vAlign hideMark cellIns cellDel "
             "cellMerge tcPrChange"),
    "tblPr": ("tblStyle tblpPr tblOverlap bidiVisual tblStyleRowBandSize "
              "tblStyleColBandSize tblW tblJc tblCellSpacing tblInd "
              "tblBorders shd tblLayout tblCellMar tblLook tblCaption "
              "tblDescription tblPrChange"),
    "trPr": ("cnfStyle divId gridBefore gridAfter wBefore wAfter cantSplit "
             "trHeight tblHeader tblCellSpacing jc hidden ins del "
             "trPrChange"),
    "tcBorders": "top start left bottom end right insideH insideV tl2br tr2bl",
    "pBdr": "top left bottom right between bar",
    "tcMar": "top start left bottom end right",
}

PARTIES = ("word/document.xml", "word/header1.xml", "word/footer1.xml",
           "word/styles.xml")


def anomalies_dans(arbre, partie):
    """Renvoie la liste des ruptures d'ordre détectées dans un arbre XML."""
    problemes = []
    for nom, sequence in SEQUENCES.items():
        attendu = sequence.split()
        for parent in arbre.iter(f"{W}{nom}"):
            rang_precedent = -1
            precedent = None
            for enfant in parent:
                if not isinstance(enfant.tag, str):
                    continue  # commentaire ou instruction
                balise = enfant.tag.replace(W, "")
                if balise not in attendu:
                    continue
                rang = attendu.index(balise)
                if rang < rang_precedent:
                    problemes.append(
                        f"{partie} : dans <w:{nom}>, <w:{balise}> apparaît "
                        f"après <w:{precedent}>")
                rang_precedent, precedent = rang, balise
    return problemes


def verifier(chemin):
    problemes = []
    with zipfile.ZipFile(chemin) as archive:
        presentes = set(archive.namelist())
        for partie in PARTIES:
            if partie not in presentes:
                continue
            arbre = etree.fromstring(archive.read(partie))
            problemes += anomalies_dans(arbre, partie)
    return problemes


def main():
    fichiers = sys.argv[1:]
    if not fichiers:
        raise SystemExit("Usage : python3 verifier_docx.py fichier.docx ...")
    code = 0
    for chemin in fichiers:
        problemes = verifier(chemin)
        if problemes:
            code = 1
            print(f"✗ {chemin} — {len(problemes)} anomalie(s) :")
            for probleme in problemes:
                print("   ", probleme)
        else:
            print(f"✓ {chemin} — ordre des balises conforme")
    sys.exit(code)


if __name__ == "__main__":
    main()
