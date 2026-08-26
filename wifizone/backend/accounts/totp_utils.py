"""Utilitaires TOTP (2FA)."""

import pyotp


def ensure_totp_secret(user):
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        user.save(update_fields=["totp_secret"])
    return user.totp_secret


def get_provisioning_uri(user):
    secret = ensure_totp_secret(user)
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email or user.username,
        issuer_name="WiFiZone Pro",
    )


def verify_totp_code(user, code: str) -> bool:
    if not user.totp_secret:
        return False
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(code, valid_window=1)
