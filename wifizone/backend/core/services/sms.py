"""Envoi SMS (console ou passerelle HTTP)."""

import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


def send_sms(phone: str, message: str) -> bool:
    if not phone:
        return False

    backend = settings.SMS_BACKEND
    if backend == "http" and settings.SMS_API_URL:
        return _send_http(phone, message)

    logger.info("SMS [%s] %s: %s", backend, phone, message[:120])
    return True


def _send_http(phone: str, message: str) -> bool:
    try:
        response = requests.post(
            settings.SMS_API_URL,
            json={
                "to": phone,
                "message": message,
                "sender": settings.SMS_SENDER_ID,
            },
            headers={"Authorization": f"Bearer {settings.SMS_API_KEY}"},
            timeout=15,
        )
        return response.status_code < 400
    except Exception as exc:
        logger.warning("SMS HTTP failed: %s", exc)
        return False
