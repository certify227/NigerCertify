"""Générateur de facture proforma PDF pour les tenues de travail OPVN."""

import os
import subprocess
import time


def generate_pdf(
    html_path="/workspace/factures-proforma/facture-proforma-opvn.html",
    pdf_path="/workspace/factures-proforma/facture-proforma-opvn.pdf",
):
    """Génère la facture proforma au format PDF via headless Chrome."""
    if os.path.exists(pdf_path):
        os.remove(pdf_path)

    cmd = [
        "google-chrome",
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-software-rasterizer",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
        "--user-data-dir=/tmp/c_data_proforma",
        f"--print-to-pdf={pdf_path}",
        "--print-to-pdf-no-header",
        html_path,
    ]

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(30):
        time.sleep(0.5)
        if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 50000:
            time.sleep(1)
            p.kill()
            print(f"[OK] PDF généré : {pdf_path} ({os.path.getsize(pdf_path)} octets)")
            return pdf_path
    else:
        p.kill()
        raise TimeoutError("Délai dépassé lors de la génération du PDF")


if __name__ == "__main__":
    generate_pdf()
