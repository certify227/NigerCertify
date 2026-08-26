"""Analytics pour le tableau de bord."""

from datetime import timedelta

from django.db.models import Count, Sum
from django.db.models.functions import TruncDate
from django.utils import timezone

from hotspots.models import Voucher, VoucherBatch


def get_dashboard_chart_data(user, days: int = 7) -> dict:
    """Vouchers générés et revenus par jour (derniers N jours)."""
    start = timezone.now() - timedelta(days=days - 1)
    start = start.replace(hour=0, minute=0, second=0, microsecond=0)

    daily = (
        Voucher.objects.filter(router__owner=user, created_at__gte=start)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(count=Count("id"), revenue=Sum("sold_price"))
        .order_by("day")
    )

    labels = []
    counts = []
    revenues = []
    daily_map = {row["day"]: row for row in daily}

    for i in range(days):
        day = (start + timedelta(days=i)).date()
        labels.append(day.strftime("%d/%m"))
        row = daily_map.get(day)
        counts.append(row["count"] if row else 0)
        revenues.append(int(row["revenue"] or 0) if row else 0)

    return {"labels": labels, "counts": counts, "revenues": revenues}


def get_subscription_days_left(subscription) -> int | None:
    if not subscription:
        return None
    delta = subscription.expires_at - timezone.now()
    return max(0, delta.days)
