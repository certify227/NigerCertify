"""Adapters Mobile Money — mock prêts à brancher sur les APIs réelles."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.models.entities import PaymentProvider


@dataclass
class PaymentInitResult:
    external_ref: str
    status: str
    instructions: str


class PaymentProviderAdapter:
    provider: PaymentProvider

    def initiate(self, *, amount: int, phone: str, booking_id: int) -> PaymentInitResult:
        raise NotImplementedError


class MockMobileMoneyAdapter(PaymentProviderAdapter):
    def __init__(self, provider: PaymentProvider):
        self.provider = provider

    def initiate(self, *, amount: int, phone: str, booking_id: int) -> PaymentInitResult:
        ref = f"TFY-{self.provider.value[:3].upper()}-{uuid.uuid4().hex[:10].upper()}"
        label = {
            PaymentProvider.ORANGE_MONEY: "Orange Money",
            PaymentProvider.AIRTEL_MONEY: "Airtel Money",
            PaymentProvider.MOOV_MONEY: "Moov Money",
            PaymentProvider.CASH: "Paiement en espèces",
        }[self.provider]

        if self.provider == PaymentProvider.CASH:
            instructions = (
                f"Payez {amount:,} XOF en espèces au conducteur le jour du départ "
                f"(réservation #{booking_id})."
            ).replace(",", " ")
        else:
            instructions = (
                f"Validez le paiement {label} de {amount:,} XOF depuis {phone}. "
                f"Référence : {ref}. En MVP, confirmez via l'API /payments/{{id}}/confirm."
            ).replace(",", " ")

        return PaymentInitResult(external_ref=ref, status="pending", instructions=instructions)


def get_payment_adapter(provider: PaymentProvider) -> PaymentProviderAdapter:
    return MockMobileMoneyAdapter(provider)