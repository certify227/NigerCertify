"""Export utilisateurs hotspot pour FreeRADIUS / MikroTik RADIUS."""

import os
from pathlib import Path

from django.conf import settings

from hotspots.models import Voucher


def export_radius_users_file(operator, radius_server) -> tuple[str, int]:
    """
    Génère un fichier radcheck (format FreeRADIUS) pour les vouchers actifs.
    Retourne (chemin, nombre de lignes).
    """
    export_dir = Path(settings.MEDIA_ROOT) / "radius_exports" / str(operator.pk)
    export_dir.mkdir(parents=True, exist_ok=True)
    path = export_dir / f"radcheck_{radius_server.pk}.txt"

    vouchers = Voucher.objects.filter(
        router__owner=operator,
        status__in=[Voucher.Status.UNUSED, Voucher.Status.ACTIVE],
    ).select_related("profile")

    lines = []
    for v in vouchers:
        lines.append(f"{v.username} Cleapasswd := \"{v.password}\"")
        if v.profile.validity_seconds:
            lines.append(
                f"{v.username} Session-Timeout := {v.profile.validity_seconds}"
            )

    content = "\n".join(lines) + ("\n" if lines else "")
    path.write_text(content, encoding="utf-8")

    radius_server.last_export_path = str(path.relative_to(settings.MEDIA_ROOT))
    radius_server.last_export_count = len(vouchers)
    radius_server.save(update_fields=["last_export_path", "last_export_count"])

    return str(path), len(vouchers)
