import json

from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib import messages

from accounts.tenant import get_operator, is_team_owner
from core.models import (
    AuditLog,
    Notification,
    NotificationPreference,
    OnboardingProgress,
    OperatorBranding,
    WebhookEndpoint,
)
from core.services.audit import log_action


@login_required
def settings_hub(request):
    operator = get_operator(request.user)
    branding = OperatorBranding.objects.filter(operator=operator).first()
    onboarding = OnboardingProgress.objects.filter(operator=operator).first()
    return render(
        request,
        "core/settings_hub.html",
        {"branding": branding, "onboarding": onboarding, "is_owner": is_team_owner(request.user)},
    )


@login_required
def branding_edit(request):
    operator = get_operator(request.user)
    if not is_team_owner(request.user):
        return redirect("core:settings")
    branding, _ = OperatorBranding.objects.get_or_create(operator=operator)
    if request.method == "POST":
        branding.app_name = request.POST.get("app_name", branding.app_name)
        branding.logo_url = request.POST.get("logo_url", "")
        branding.primary_color = request.POST.get("primary_color", branding.primary_color)
        branding.custom_domain = request.POST.get("custom_domain", "")
        branding.support_email = request.POST.get("support_email", "")
        branding.public_map_enabled = request.POST.get("public_map_enabled") == "on"
        branding.latitude = request.POST.get("latitude") or None
        branding.longitude = request.POST.get("longitude") or None
        branding.save()
        log_action(operator, request.user, "settings", "Branding mis à jour", request)
        messages.success(request, "Branding enregistré.")
        return redirect("core:settings")
    return render(request, "core/branding_form.html", {"branding": branding})


@login_required
def notifications_list(request):
    operator = get_operator(request.user)
    items = Notification.objects.filter(operator=operator)[:50]
    return render(request, "core/notifications.html", {"notifications": items})


@login_required
def audit_log(request):
    operator = get_operator(request.user)
    logs = AuditLog.objects.filter(operator=operator).select_related("actor")[:100]
    return render(request, "core/audit_log.html", {"logs": logs})


@login_required
def webhooks_list(request):
    operator = get_operator(request.user)
    hooks = WebhookEndpoint.objects.filter(operator=operator)
    if request.method == "POST" and is_team_owner(request.user):
        WebhookEndpoint.objects.create(
            operator=operator,
            url=request.POST["url"],
            events=request.POST.get("events", "voucher.created").split(","),
        )
        messages.success(request, "Webhook ajouté.")
        return redirect("core:webhooks")
    return render(request, "core/webhooks.html", {"webhooks": hooks})


@login_required
def onboarding(request):
    operator = get_operator(request.user)
    prog, _ = OnboardingProgress.objects.get_or_create(operator=operator)
    from routers.models import Router
    from hotspots.models import HotspotProfile, Voucher, HotspotLoginTemplate

    prog.router_added = Router.objects.filter(owner=operator).exists()
    prog.profile_created = HotspotProfile.objects.filter(router__owner=operator).exists()
    prog.voucher_generated = Voucher.objects.filter(router__owner=operator).exists()
    prog.template_customized = HotspotLoginTemplate.objects.filter(owner=operator).exists()
    prog.team_invited = operator.team_members.exists()
    prog.completed = prog.percent >= 80
    prog.save()
    return render(request, "core/onboarding.html", {"progress": prog})


def wifi_map(request):
    from core.models import OperatorBranding

    operators = []
    for b in OperatorBranding.objects.filter(public_map_enabled=True).select_related("operator"):
        if b.latitude and b.longitude:
            operators.append({
                "name": b.operator.display_name,
                "lat": float(b.latitude),
                "lng": float(b.longitude),
                "city": b.operator.city,
            })
    return render(
        request,
        "core/wifi_map.html",
        {"operators": operators, "operators_json": json.dumps(operators)},
    )
