#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Génère les PDF d'examen blanc Linux Essentials — propriété Niger Certify."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _load_engine():
    path = ROOT.parent / "ccna-200-301" / "pdf_engine.py"
    spec = importlib.util.spec_from_file_location("nc_pdf_engine", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


from enonce_a import EXAM_A
from enonce_b import EXAM_B

engine = _load_engine()
PDF_DIR = ROOT / "pdf"


def main() -> None:
    assert "Linux Essentials" in EXAM_A["title"], EXAM_A["title"]
    assert EXAM_A["n_questions"] == 40
    a = engine.build_pdf(
        EXAM_A,
        PDF_DIR / "NigerCertify-Linux-Essentials-010-160-Examen-Blanc-A-Enonce.pdf",
    )
    b = engine.build_pdf(
        EXAM_B,
        PDF_DIR / "NigerCertify-Linux-Essentials-010-160-Examen-Blanc-B-Enonce.pdf",
    )
    c = engine.build_corrige_pdf(
        [EXAM_A, EXAM_B],
        PDF_DIR
        / "NigerCertify-Linux-Essentials-010-160-Examen-Blanc-AB-Corrige-FORMATEUR.pdf",
    )
    for path in (a, b, c):
        print(f"OK  {path.name}  ({path.stat().st_size / 1024:.1f} Ko)")


if __name__ == "__main__":
    main()
