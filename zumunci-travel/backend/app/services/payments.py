"""Adapters Mobile Money — sandbox style agrégateur (PayGate / Hub2 / CinetPay)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.core.config import get_settings
from app.models.entities import PaymentProvider


@dataclass
class PaymentInitResult:
    external_ref: str
    status: str
    instructions: str
    checkout_url: str | None = None
    ussd_hint: str | None = None
    provider_label: str = ""
    sandbox: bool = True


class PaymentProviderAdapter:
    provider: PaymentProvider

    def initiate(self, *, amount: int, phone: str, booking_id: int) -> PaymentInitResult:
        raise NotImplementedError


PROVIDER_LABELS = {
    PaymentProvider.ORANGE_MONEY: "Orange Money",
    PaymentProvider.AIRTEL_MONEY: "Airtel Money",
    PaymentProvider.MOOV_MONEY: "Moov Money",
    PaymentProvider.CASH: "Paiement en espèces",
}

USSD_HINTS = {
    PaymentProvider.ORANGE_MONEY: "#144#",
    PaymentProvider.AIRTEL_MONEY: "*202#",
    PaymentProvider.MOOV_MONEY: "*555#",
}


class SandboxMobileMoneyAdapter(PaymentProviderAdapter):
    """Sandbox : références + URL checkout fictive + hint USSD opérateur."""

    def __init__(self, provider: PaymentProvider):
        self.provider = provider

    def initiate(self, *, amount: int, phone: str, booking_id: int) -> PaymentInitResult:
        settings = get_settings()
        label = PROVIDER_LABELS[self.provider]
        ref = f"ZMT-{self.provider.value[:3].upper()}-{uuid.uuid4().hex[:10].upper()}"
        amount_fmt = f"{amount:,}".replace(",", " ")

        if self.provider == PaymentProvider.CASH:
            return PaymentInitResult(
                external_ref=ref,
                status="pending",
                instructions=(
                    f"Payez {amount_fmt} XOF en espèces au conducteur le jour du départ "
                    f"(réservation #{booking_id})."
                ),
                provider_label=label,
                sandbox=True,
            )

        checkout = (
            f"https://sandbox.zumunci.pay/checkout/{ref}"
            f"?provider={self.provider.value}&amount={amount}&booking={booking_id}"
        )
        ussd = USSD_HINTS.get(self.provider)
        instructions = (
            f"[SANDBOX {settings.payment_aggregator}] {label} — {amount_fmt} XOF depuis {phone}. "
            f"Réf. {ref}. Validez sur le téléphone (USSD {ussd}) ou via "
            f"/payments/{{id}}/confirm. Checkout: {checkout}"
        )
        return PaymentInitResult(
            external_ref=ref,
            status="pending",
            instructions=instructions,
            checkout_url=checkout,
            ussd_hint=ussd,
            provider_label=label,
            sandbox=True,
        )


def get_payment_adapter(provider: PaymentProvider) -> PaymentProviderAdapter:
    return SandboxMobileMoneyAdapter(provider)
