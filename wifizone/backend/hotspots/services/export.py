"""Export des vouchers."""

import csv
from io import StringIO

from hotspots.models import Voucher, VoucherBatch


def batch_csv_content(batch: VoucherBatch) -> str:
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "code",
            "username",
            "password",
            "profil",
            "routeur",
            "prix_fcfa",
            "statut",
            "sync_mikrotik",
            "date_creation",
        ]
    )
    for v in batch.vouchers.select_related("profile", "router").all():
        writer.writerow(
            [
                v.code,
                v.username,
                v.password,
                v.profile.name,
                v.router.name,
                int(v.sold_price),
                v.get_status_display(),
                "oui" if v.synced_to_mikrotik else "non",
                v.created_at.strftime("%Y-%m-%d %H:%M"),
            ]
        )
    return output.getvalue()


def vouchers_csv_content(vouchers) -> str:
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["code", "username", "password", "profil", "routeur", "prix", "statut", "date"])
    for v in vouchers:
        writer.writerow(
            [
                v.code,
                v.username,
                v.password,
                v.profile.name,
                v.router.name,
                int(v.sold_price),
                v.get_status_display(),
                v.created_at.strftime("%Y-%m-%d %H:%M"),
            ]
        )
    return output.getvalue()
