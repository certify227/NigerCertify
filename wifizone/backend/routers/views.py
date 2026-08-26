from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from billing.decorators import subscription_required
from accounts.tenant import get_operator
from billing.services import get_user_subscription
from hotspots.services.profile_sync import sync_profiles_from_router

from .forms import RadiusServerForm, RouterForm
from .models import RadiusServer, Router
from .services.mikrotik import get_service_for_router, test_router_connection
from .services.snmp import get_snmp_stats
from .services.radius import export_radius_users_file


def _router_limit_ok(user):
    operator = get_operator(user)
    sub = get_user_subscription(operator)
    if not sub or not sub.is_valid:
        return False, "Abonnement invalide ou expiré."
    count = Router.objects.filter(owner=operator).count()
    if count >= sub.plan.max_routers:
        return False, f"Limite atteinte : {sub.plan.max_routers} routeur(s) max."
    return True, ""


@login_required
def router_list(request):
    operator = get_operator(request.user)
    routers = Router.objects.filter(owner=operator)
    sub = get_user_subscription(operator)
    return render(
        request,
        "routers/list.html",
        {
            "routers": routers,
            "subscription": sub,
            "can_add": sub and sub.is_valid and routers.count() < sub.plan.max_routers,
        },
    )


@login_required
def router_create(request):
    ok, msg = _router_limit_ok(request.user)
    if not ok:
        messages.error(request, msg)
        return redirect("routers:list")

    if request.method == "POST":
        form = RouterForm(get_operator(request.user), request.POST)
        if form.is_valid():
            router = form.save(commit=False)
            router.owner = get_operator(request.user)
            router.save()
            messages.success(request, f"Routeur « {router.name} » ajouté.")
            return redirect("routers:detail", pk=router.pk)
    else:
        form = RouterForm(owner=get_operator(request.user))

    return render(request, "routers/form.html", {"form": form, "title": "Ajouter un routeur"})


@login_required
def router_detail(request, pk):
    router = get_object_or_404(Router, pk=pk, owner=get_operator(request.user))
    info = None
    active_users = []
    if router.connection_status == Router.ConnectionStatus.ONLINE or settings.MIKROTIK_MOCK_MODE:
        try:
            service = get_service_for_router(router)
            info = service.get_system_info()
            raw_active = service.list_active_users()
            for u in raw_active:
                active_users.append(
                    {
                        "user": u.get("user") or u.get("name", "—"),
                        "address": u.get("address", "—"),
                        "uptime": u.get("uptime", "—"),
                    }
                )
        except Exception:
            pass

    snmp_stats = None
    if router.snmp_enabled:
        snmp_stats = get_snmp_stats(router.host, router.snmp_community or "public")

    return render(
        request,
        "routers/detail.html",
        {
            "router": router,
            "system_info": info,
            "active_users": active_users,
            "snmp_stats": snmp_stats,
        },
    )


@login_required
def router_edit(request, pk):
    router = get_object_or_404(Router, pk=pk, owner=get_operator(request.user))
    if request.method == "POST":
        form = RouterForm(get_operator(request.user), request.POST, instance=router)
        if form.is_valid():
            form.save()
            messages.success(request, "Routeur mis à jour.")
            return redirect("routers:detail", pk=router.pk)
    else:
        form = RouterForm(get_operator(request.user), instance=router)

    return render(
        request,
        "routers/form.html",
        {"form": form, "title": f"Modifier {router.name}", "router": router},
    )


@login_required
def router_delete(request, pk):
    router = get_object_or_404(Router, pk=pk, owner=get_operator(request.user))
    if request.method == "POST":
        name = router.name
        router.delete()
        messages.success(request, f"Routeur « {name} » supprimé.")
        return redirect("routers:list")
    return render(request, "routers/delete.html", {"router": router})


@login_required
def router_test(request, pk):
    router = get_object_or_404(Router, pk=pk, owner=get_operator(request.user))
    ok, message = test_router_connection(router)
    router.connection_status = (
        Router.ConnectionStatus.ONLINE if ok else Router.ConnectionStatus.ERROR
    )
    router.last_error = "" if ok else message
    if ok:
        router.last_connected_at = timezone.now()
    router.save()
    if ok:
        messages.success(request, message)
    else:
        messages.error(request, f"Échec : {message}")
    return redirect("routers:detail", pk=router.pk)


@login_required
@subscription_required
def router_sync_profiles(request, pk):
    router = get_object_or_404(Router, pk=pk, owner=get_operator(request.user))
    created, skipped, msgs = sync_profiles_from_router(router, request.user)
    if created:
        messages.success(request, f"{created} profil(s) importé(s) depuis MikroTik.")
    else:
        messages.info(request, msgs[0] if msgs else "Aucun nouveau profil.")
    return redirect("hotspots:profile_list")


@login_required
def radius_list(request):
    operator = get_operator(request.user)
    servers = RadiusServer.objects.filter(operator=operator)
    if request.method == "POST":
        form = RadiusServerForm(request.POST)
        if form.is_valid():
            server = form.save(commit=False)
            server.operator = operator
            server.save()
            messages.success(request, "Serveur RADIUS ajouté.")
            return redirect("routers:radius_list")
    else:
        form = RadiusServerForm()
    return render(
        request,
        "routers/radius_list.html",
        {"servers": servers, "form": form},
    )


@login_required
def radius_export(request, pk):
    operator = get_operator(request.user)
    server = get_object_or_404(RadiusServer, pk=pk, operator=operator)
    path, count = export_radius_users_file(operator, server)
    messages.success(request, f"{count} utilisateur(s) exporté(s) vers {path}")
    return redirect("routers:radius_list")
