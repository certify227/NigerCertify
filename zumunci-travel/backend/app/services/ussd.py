"""Simulateur USSD bas débit — recherche de trajets sans smartphone."""

from __future__ import annotations

from datetime import date

from sqlalchemy.orm import Session, joinedload

from app.core.config import get_settings
from app.models.entities import Ride, User, VerificationStatus

# Codes courts villes (USSD)
CITY_CODES: dict[str, str] = {
    "1": "Niamey",
    "2": "Maradi",
    "3": "Zinder",
    "4": "Tahoua",
    "5": "Agadez",
    "6": "Dosso",
    "7": "Diffa",
    "8": "Tillabéri",
}


def _menu() -> str:
    settings = get_settings()
    lines = [
        f"ZumunciTravel {settings.ussd_service_code}",
        "1. Chercher un trajet",
        "2. Codes villes",
        "3. Aide / agent",
        "0. Quitter",
    ]
    return "\n".join(lines)


def _city_list() -> str:
    return "Codes villes:\n" + "\n".join(f"{k}. {v}" for k, v in CITY_CODES.items())


def _search(db: Session, origin_code: str, dest_code: str) -> str:
    origin = CITY_CODES.get(origin_code)
    dest = CITY_CODES.get(dest_code)
    if not origin or not dest:
        return "END Code ville invalide. Composez 2 pour la liste."
    if origin == dest:
        return "END Depart et arrivee identiques."
    today = date.today()
    rides = (
        db.query(Ride)
        .options(joinedload(Ride.driver))
        .join(User, Ride.driver_id == User.id)
        .filter(
            Ride.is_active.is_(True),
            Ride.seats_available > 0,
            Ride.origin_city.ilike(origin),
            Ride.destination_city.ilike(dest),
            Ride.departure_date >= today,
            User.is_suspended.is_(False),
            User.verification_status == VerificationStatus.VERIFIED,
        )
        .order_by(Ride.departure_date, Ride.departure_time)
        .limit(5)
        .all()
    )
    if not rides:
        return f"END Aucun trajet {origin}->{dest} ouvert. Essayez demain ou un agent gare."
    lines = [f"CON {origin}->{dest} ({len(rides)})"]
    for i, r in enumerate(rides, start=1):
        lines.append(
            f"{i}. {r.departure_date} {r.departure_time} "
            f"{r.price_per_seat}F {r.seats_available}pl"
        )
    lines.append("Reservez via app ou agent gare.")
    return "\n".join(lines)


def handle_ussd(db: Session, *, text: str, phone: str | None = None) -> dict:
    """
    Protocole type Africa's Talking / Orange:
    - CON = continuer la session
    - END = terminer
    text: saisie cumulée séparée par * (ex: '1*1*2')
    """
    raw = (text or "").strip()
    parts = [p for p in raw.split("*") if p != ""] if raw else []

    if not parts:
        return {
            "response": f"CON {_menu()}",
            "action": "menu",
            "phone": phone,
        }

    choice = parts[0]
    if choice == "0":
        return {"response": "END Merci. Voyagez en confiance.", "action": "quit", "phone": phone}

    if choice == "2":
        return {"response": f"END {_city_list()}", "action": "cities", "phone": phone}

    if choice == "3":
        return {
            "response": (
                "END Agents gares: Niamey Gare centrale, Maradi Station, "
                "Zinder Gare. Appelez un ambassadeur via l'app ZumunciTravel."
            ),
            "action": "help",
            "phone": phone,
        }

    if choice == "1":
        if len(parts) == 1:
            return {
                "response": (
                    "CON Recherche\n"
                    "Entrez: code_depart*code_arrivee\n"
                    "Ex: 1*2 (Niamey->Maradi)\n"
                    "2=liste codes"
                ),
                "action": "search_prompt",
                "phone": phone,
            }
        if len(parts) >= 3:
            return {
                "response": _search(db, parts[1], parts[2]),
                "action": "search",
                "phone": phone,
            }
        return {
            "response": "CON Format: 1*depart*arrivee (ex 1*1*2)",
            "action": "search_prompt",
            "phone": phone,
        }

    return {"response": f"CON Choix invalide.\n{_menu()}", "action": "menu", "phone": phone}
