"""Règles de confiance : vérification avant mise en relation."""

from __future__ import annotations

from urllib.parse import quote

from fastapi import HTTPException

from app.core.config import get_settings
from app.models.entities import BookingStatus, RideMode, User, VerificationStatus

SAFETY_CHARTER = {
    "title": "Charte de sécurité ZumunciTravel",
    "version": "1.1",
    "rules": [
        "ZumunciTravel est uniquement une plateforme de transport (pas de rencontres).",
        "Toute mise en relation exige une vérification d'identité validée (délai cible ≤ 24 h).",
        "Le numéro de téléphone reste masqué jusqu'au paiement confirmé de la réservation.",
        "Après paiement, le contact peut se faire par appel ou WhatsApp — uniquement pour ce trajet.",
        "En covoiturage, le paiement cash hors Mobile Money est interdit (anti-arnaque).",
        "Interdiction de harcèlement, propos déplacés, demandes personnelles ou relations hors trajet.",
        "Les trajets « priorité femmes » doivent être respectés : ambiance professionnelle uniquement.",
        "Signalez immédiatement toute tentative d'arnaque ou comportement inapproprié.",
        "Les comptes signalés peuvent être suspendus sans préavis.",
    ],
}


def ensure_active(user: User) -> None:
    if user.is_suspended:
        raise HTTPException(status_code=403, detail="Compte suspendu pour raison de sécurité")


def ensure_can_transact(user: User) -> None:
    """Publier ou réserver nécessite vérification + charte."""
    ensure_active(user)
    if not user.accepted_safety_charter:
        raise HTTPException(
            status_code=403,
            detail="Vous devez accepter la charte de sécurité avant toute mise en relation",
        )
    if user.verification_status != VerificationStatus.VERIFIED or not user.is_verified:
        raise HTTPException(
            status_code=403,
            detail="Vérification d'identité requise avant de publier ou réserver un trajet",
        )


def mask_phone(phone: str | None) -> str:
    if not phone:
        return "••••••••"
    digits = "".join(ch for ch in phone if ch.isdigit())
    if len(digits) < 4:
        return "••••••••"
    return f"+••• •• •• {digits[-2:]}"


def contact_may_be_revealed(booking_status: BookingStatus, contact_unlocked: bool) -> bool:
    return contact_unlocked and booking_status in {BookingStatus.PAID, BookingStatus.COMPLETED}


def whatsapp_link(phone: str | None, message: str) -> str | None:
    if not phone:
        return None
    digits = "".join(ch for ch in phone if ch.isdigit())
    if not digits:
        return None
    return f"https://wa.me/{digits}?text={quote(message)}"


def compute_fees(total_amount: int) -> tuple[int, int]:
    settings = get_settings()
    fee = int(round(total_amount * settings.commission_rate))
    driver_amount = max(total_amount - fee, 0)
    return fee, driver_amount


def assert_payment_allowed(mode: RideMode, provider_value: str) -> None:
    settings = get_settings()
    if provider_value != "cash":
        return
    if mode.value not in settings.cash_allowed_mode_list:
        raise HTTPException(
            status_code=400,
            detail=(
                "Le paiement cash est interdit en covoiturage. "
                "Utilisez Orange Money, Airtel Money ou Moov Money."
            ),
        )


def is_night_departure(departure_time: str) -> bool:
    settings = get_settings()
    try:
        hour = int(departure_time.split(":")[0])
    except (ValueError, IndexError):
        return False
    return hour >= settings.night_start_hour or hour < settings.night_end_hour


def corridor_allowed(origin: str, destination: str) -> bool:
    settings = get_settings()
    if not settings.pilot_mode:
        return True
    o = origin.strip().casefold()
    d = destination.strip().casefold()
    for a, b in settings.pilot_corridor_pairs:
        if o == a.casefold() and d == b.casefold():
            return True
    return False
