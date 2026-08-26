"""Export PDF des rapports (reportlab)."""

from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas


def build_reports_pdf(operator_name: str, total_vouchers: int, total_revenue, by_profile: list) -> bytes:
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 2 * cm

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(2 * cm, y, f"Rapport WiFiZone — {operator_name}")
    y -= 1.2 * cm

    pdf.setFont("Helvetica", 11)
    pdf.drawString(2 * cm, y, f"Total vouchers : {total_vouchers}")
    y -= 0.6 * cm
    pdf.drawString(2 * cm, y, f"Revenus estimés : {int(total_revenue)} FCFA")
    y -= 1 * cm

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(2 * cm, y, "Par profil")
    y -= 0.8 * cm
    pdf.setFont("Helvetica", 10)
    for row in by_profile:
        name = row.get("profile__name") or "—"
        count = row.get("count", 0)
        revenue = int(row.get("revenue") or 0)
        pdf.drawString(2 * cm, y, f"{name}: {count} vouchers — {revenue} FCFA")
        y -= 0.5 * cm
        if y < 2 * cm:
            pdf.showPage()
            y = height - 2 * cm

    pdf.save()
    return buffer.getvalue()
