"""Prévisions simples basées sur l'historique de ventes."""

from datetime import timedelta

from django.utils import timezone

from dashboard.services.analytics import get_dashboard_chart_data


def predict_voucher_sales(operator, history_days: int = 14, forecast_days: int = 7) -> dict:
    """
    Prévision par moyenne mobile des vouchers générés.
    Retourne labels, historique et prévisions.
    """
    chart = get_dashboard_chart_data(operator, days=history_days)
    counts = chart["counts"]
    avg = sum(counts) / len(counts) if counts else 0
    trend = 0
    if len(counts) >= 2:
        trend = (counts[-1] - counts[0]) / max(len(counts) - 1, 1)

    forecast_labels = []
    forecast_counts = []
    start = timezone.now()
    for i in range(forecast_days):
        day = (start + timedelta(days=i + 1)).date()
        forecast_labels.append(day.strftime("%d/%m"))
        predicted = max(0, round(avg + trend * (i + 1)))
        forecast_counts.append(predicted)

    total_forecast = sum(forecast_counts)
    avg_revenue = (
        sum(chart["revenues"]) / sum(counts) if sum(counts) > 0 else 0
    )
    revenue_forecast = int(total_forecast * avg_revenue)

    return {
        "history_labels": chart["labels"],
        "history_counts": counts,
        "forecast_labels": forecast_labels,
        "forecast_counts": forecast_counts,
        "total_forecast": total_forecast,
        "revenue_forecast": revenue_forecast,
        "method": "moving_average_trend",
    }
