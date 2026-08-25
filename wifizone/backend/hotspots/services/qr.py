"""Génération de QR codes pour vouchers hotspot."""

import base64
import io

import qrcode


def voucher_login_payload(username: str, password: str) -> str:
    """Contenu QR : identifiants pour login hotspot (compatible scanners type MYQR)."""
    return f"username={username}&password={password}"


def qr_code_base64(data: str, box_size: int = 4) -> str:
    """Retourne une image PNG QR encodée en base64."""
    qr = qrcode.QRCode(box_size=box_size, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")
