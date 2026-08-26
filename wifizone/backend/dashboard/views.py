from django.contrib.auth.decorators import login_required
from django.db.models import Sum
from django.shortcuts import render

from accounts.tenant import get_operator

from billing.models import Plan
from billing.services import get_user_subscription
from dashboard.services.analytics import get_dashboard_chart_data, get_subscription_days_left
from dashboard.services.predictions import predict_voucher_sales
from hotspots.models import Voucher, VoucherBatch
from routers.models import Router
from routers.services.mikrotik import get_service_for_router


def landing(request):
    plans = Plan.objects.filter(is_active=True)
    return render(request, "dashboard/landing.html", {"plans": plans})


@login_required
def home(request):
    user = request.user
    operator = get_operator(user)
    sub = get_user_subscription(operator)
    routers = Router.objects.filter(owner=operator)
    router_count = routers.count()
    online_count = routers.filter(connection_status=Router.ConnectionStatus.ONLINE).count()

    vouchers_month = sub.vouchers_used_this_month if sub else 0
    total_vouchers = Voucher.objects.filter(router__owner=operator).count()
    revenue = Voucher.objects.filter(router__owner=operator).aggregate(s=Sum("sold_price"))["s"] or 0
    recent_batches = VoucherBatch.objects.filter(router__owner=operator).select_related(
        "profile", "router"
    )[:5]

    chart = get_dashboard_chart_data(operator)
    days_left = get_subscription_days_left(sub)
    forecast = predict_voucher_sales(operator)

    return render(
        request,
        "dashboard/home.html",
        {
            "subscription": sub,
            "subscription_days_left": days_left,
            "router_count": router_count,
            "online_count": online_count,
            "vouchers_month": vouchers_month,
            "total_vouchers": total_vouchers,
            "revenue": revenue,
            "recent_batches": recent_batches,
            "routers": routers[:5],
            "chart_labels": chart["labels"],
            "chart_counts": chart["counts"],
            "chart_revenues": chart["revenues"],
            "forecast_labels": forecast["forecast_labels"],
            "forecast_counts": forecast["forecast_counts"],
            "forecast_total": forecast["total_forecast"],
            "forecast_revenue": forecast["revenue_forecast"],
        },
    )


@login_required
def active_users(request):
    """Utilisateurs hotspot actifs sur tous les routeurs de l'opérateur."""
    operator = get_operator(request.user)
    routers = Router.objects.filter(owner=operator, is_active=True)
    all_active = []
    errors = []

    for router in routers:
        try:
            service = get_service_for_router(router)
            users = service.list_active_users()
            for u in users:
                all_active.append(
                    {
                        "router": router,
                        "user": u.get("user") or u.get("name", "—"),
                        "address": u.get("address", "—"),
                        "uptime": u.get("uptime", "—"),
                        "mac": u.get("mac-address") or u.get("mac_address", ""),
                    }
                )
        except Exception as exc:
            errors.append(f"{router.name}: {exc}")

    return render(
        request,
        "dashboard/active_users.html",
        {"active_users": all_active, "errors": errors, "router_count": routers.count()},
    )
