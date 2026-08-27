#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Génère les PDF d'examen blanc CCNA — propriété Niger Certify."""

from pathlib import Path

from enonce_a import EXAM_A
from enonce_b import EXAM_B
from pdf_engine import build_corrige_pdf, build_pdf

ROOT = Path(__file__).resolve().parent
PDF_DIR = ROOT / "pdf"


def main() -> None:
    a = build_pdf(EXAM_A, PDF_DIR / "NigerCertify-CCNA-200-301-Examen-Blanc-A-Enonce.pdf")
    b = build_pdf(EXAM_B, PDF_DIR / "NigerCertify-CCNA-200-301-Examen-Blanc-B-Enonce.pdf")
    c = build_corrige_pdf(
        [EXAM_A, EXAM_B],
        PDF_DIR / "NigerCertify-CCNA-200-301-Examen-Blanc-AB-Corrige-FORMATEUR.pdf",
    )
    for path in (a, b, c):
        print(f"OK  {path.name}  ({path.stat().st_size / 1024:.1f} Ko)")


if __name__ == "__main__":
    main()
