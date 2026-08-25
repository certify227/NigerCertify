from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from .models import Plan
from .services import activate_plan, get_user_subscription


def pricing(request):
    plans = Plan.objects.filter(is_active=True)
    subscription = get_user_subscription(request.user) if request.user.is_authenticated else None
    return render(
        request,
        "billing/pricing.html",
        {"plans": plans, "subscription": subscription},
    )


@login_required
def subscribe(request, slug):
    plan = get_object_or_404(Plan, slug=slug, is_active=True)
    if request.method == "POST":
        activate_plan(request.user, slug)
        return redirect("billing:success", slug=slug)
    subscription = get_user_subscription(request.user)
    return render(
        request,
        "billing/subscribe.html",
        {"plan": plan, "subscription": subscription},
    )


@login_required
def success(request, slug):
    plan = get_object_or_404(Plan, slug=slug)
    subscription = get_user_subscription(request.user)
    return render(
        request,
        "billing/success.html",
        {"plan": plan, "subscription": subscription},
    )
