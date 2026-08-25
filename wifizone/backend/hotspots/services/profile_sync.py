"""Synchronisation des profils hotspot depuis MikroTik."""

import re
from decimal import Decimal

from hotspots.models import HotspotProfile
from routers.services.mikrotik import get_service_for_router


def parse_session_timeout(value: str) -> int:
    """Convertit session-timeout RouterOS (ex: 1h, 1d, 30m) en secondes."""
    if not value:
        return 3600
    value = value.strip().lower()
    if value.isdigit():
        return int(value)

    match = re.match(r"^(\d+)([smhdw])?$", value)
    if not match:
        return 3600

    amount = int(match.group(1))
    unit = match.group(2) or "s"
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    return amount * multipliers.get(unit, 1)


def sync_profiles_from_router(router, owner) -> tuple[int, int, list[str]]:
    """
    Importe les profils MikroTik non encore enregistrés.
    Retourne (créés, ignorés, messages).
    """
    from billing.services import get_user_subscription

    sub = get_user_subscription(owner)
    max_profiles = sub.plan.max_profiles if sub else 5
    current_count = HotspotProfile.objects.filter(router__owner=owner).count()

    service = get_service_for_router(router)
    mt_profiles = service.list_profiles()
    created = 0
    skipped = 0
    messages = []

    existing = set(
        HotspotProfile.objects.filter(router=router).values_list("mikrotik_profile", flat=True)
    )

    for mt in mt_profiles:
        name = mt.get("name", "")
        if not name or name in existing:
            skipped += 1
            continue

        if current_count + created >= max_profiles:
            messages.append(f"Limite de profils atteinte ({max_profiles} max).")
            break

        timeout = mt.get("session-timeout") or mt.get("session_timeout") or "1h"
        validity = parse_session_timeout(str(timeout))

        HotspotProfile.objects.create(
            router=router,
            name=name.replace("_", " ").title(),
            mikrotik_profile=name,
            validity_seconds=validity,
            price=Decimal("500"),
            is_active=True,
        )
        existing.add(name)
        created += 1
        messages.append(f"Profil importé : {name}")

    if not messages and skipped:
        messages.append("Tous les profils MikroTik sont déjà synchronisés.")

    return created, skipped, messages
