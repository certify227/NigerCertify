"""Règles de confiance : vérification avant mise en relation."""

from __future__ import annotations

from fastapi import HTTPException

from app.models.entities import BookingStatus, User, VerificationStatus

SAFETY_CHARTER = {
    "title": "Charte de sécurité ZumunciTravel",
    "version": "1.0",
    "rules": [
        "ZumunciTravel est uniquement une plateforme de transport (pas de rencontres).",
        "Toute mise en relation exige une vérification d'identité validée.",
        "Le numéro de téléphone reste masqué jusqu'au paiement confirmé de la réservation.",
        "Interdiction de proposer ou d'accepter un paiement hors plateforme.",
        "Interdiction de harcèlement, propos déplacés, demandes personnelles ou relations hors trajet.",
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