"""Provider SMS / OTP — sandbox prêt à brancher (Twilio, Orange SMS, etc.)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.config import get_settings


@dataclass
class SmsSendResult:
    message_id: str
    channel: str
    to: str
    body: str
    provider: str
    sandbox: bool = True
    sent_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# Journal mémoire pour QA / admin (process local)
_SMS_LOG: list[SmsSendResult] = []


def get_sms_log(limit: int = 20) -> list[SmsSendResult]:
    return list(reversed(_SMS_LOG[-limit:]))


class SmsProvider:
    def send(self, *, to: str, body: str) -> SmsSendResult:
        raise NotImplementedError


class SandboxSmsProvider(SmsProvider):
    """Simule un agrégateur SMS (pas d'envoi réseau)."""

    def send(self, *, to: str, body: str) -> SmsSendResult:
        settings = get_settings()
        result = SmsSendResult(
            message_id=f"SMS-{uuid.uuid4().hex[:12].upper()}",
            channel="sms",
            to=to,
            body=body,
            provider=settings.sms_provider_name,
            sandbox=True,
        )
        _SMS_LOG.append(result)
        if len(_SMS_LOG) > 200:
            del _SMS_LOG[:-100]
        return result


def get_sms_provider() -> SmsProvider:
    # V1 : sandbox. Brancher Twilio/Orange ici selon settings.sms_provider_name.
    return SandboxSmsProvider()


def send_otp_sms(*, phone: str, code: str) -> SmsSendResult:
    settings = get_settings()
    body = (
        f"ZumunciTravel: code OTP {code}. Valable 5 min. "
        f"Ne partagez pas ce code. ({settings.sms_provider_name})"
    )
    return get_sms_provider().send(to=phone, body=body)


def send_booking_sms(*, phone: str, body: str) -> SmsSendResult:
    return get_sms_provider().send(to=phone, body=body)
