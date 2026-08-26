from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q, Sum
from django.db.models import Q as DQ
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from accounts.tenant import get_operator, can_view_reports, is_team_owner
from billing.decorators import subscription_required
from billing.services import get_user_subscription
from routers.models import Router

from .forms import GenerateVoucherForm, HotspotLoginTemplateForm, HotspotProfileForm, VoucherFilterForm
from .models import HotspotLoginTemplate, HotspotProfile, Voucher, VoucherBatch
from .services.export import batch_csv_content, vouchers_csv_content
from .services.login_template import build_mikrotik_login_html, DEFAULT_LOGIN_HTML
from .services.qr import qr_code_base64, voucher_login_payload
from .services.voucher import generate_vouchers


@login_required
def profile_list(request):
    operator = get_operator(request.user)
    profiles = HotspotProfile.objects.filter(router__owner=operator).select_related("router")
    sub = get_user_subscription(operator)
    return render(
        request,
        "hotspots/profile_list.html",
        {"profiles": profiles, "subscription": sub},
    )


@login_required
@subscription_required
def profile_create(request):
    operator = get_operator(request.user)
    routers = Router.objects.filter(owner=operator)
    if not routers.exists():
        messages.warning(request, "Ajoutez d'abord un routeur MikroTik.")
        return redirect("routers:create")

    sub = get_user_subscription(operator)
    if sub and HotspotProfile.objects.filter(router__owner=operator).count() >= sub.plan.max_profiles:
        messages.error(request, f"Limite de profils atteinte ({sub.plan.max_profiles} max).")
        return redirect("hotspots:profile_list")

    if request.method == "POST":
        form = HotspotProfileForm(operator, request.POST)
        if form.is_valid():
            profile = form.save()
            messages.success(request, f"Profil « {profile.name} » créé.")
            return redirect("hotspots:profile_list")
    else:
        form = HotspotProfileForm(user=operator)

    return render(request, "hotspots/profile_form.html", {"form": form, "title": "Nouveau profil"})


@login_required
def profile_edit(request, pk):
    profile = get_object_or_404(HotspotProfile, pk=pk, router__owner=get_operator(request.user))
    if request.method == "POST":
        form = HotspotProfileForm(get_operator(request.user), request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, "Profil mis à jour.")
            return redirect("hotspots:profile_list")
    else:
        form = HotspotProfileForm(user=get_operator(request.user), instance=profile)

    return render(
        request,
        "hotspots/profile_form.html",
        {"form": form, "title": f"Modifier {profile.name}", "profile": profile},
    )


@login_required
def voucher_list(request):
    operator = get_operator(request.user)
    form = VoucherFilterForm(operator, request.GET or None)
    vouchers = Voucher.objects.filter(router__owner=operator).select_related("router", "profile")

    if form.is_valid():
        q = form.cleaned_data.get("q")
        if q:
            vouchers = vouchers.filter(
                Q(code__icontains=q) | Q(username__icontains=q) | Q(password__icontains=q)
            )
        status = form.cleaned_data.get("status")
        if status:
            vouchers = vouchers.filter(status=status)
        router = form.cleaned_data.get("router")
        if router:
            vouchers = vouchers.filter(router=router)

    vouchers = vouchers[:500]
    return render(request, "hotspots/voucher_list.html", {"vouchers": vouchers, "filter_form": form})


@login_required
@subscription_required
def voucher_generate(request):
    operator = get_operator(request.user)
    if request.method == "POST":
        form = GenerateVoucherForm(operator, request.POST)
        if form.is_valid():
            router = form.cleaned_data["router"]
            profile = form.cleaned_data["profile"]
            batch, msg = generate_vouchers(
                router=router,
                profile=profile,
                quantity=form.cleaned_data["quantity"],
                user=request.user,
                prefix=form.cleaned_data.get("prefix", ""),
                sync_mikrotik=form.cleaned_data.get("sync_mikrotik", True),
            )
            if batch:
                messages.success(request, msg)
                return redirect("hotspots:batch_detail", pk=batch.pk)
            messages.error(request, msg)
    else:
        form = GenerateVoucherForm(operator)

    sub = get_user_subscription(operator)
    return render(
        request,
        "hotspots/voucher_generate.html",
        {"form": form, "subscription": sub},
    )


@login_required
def batch_list(request):
    operator = get_operator(request.user)
    batches = VoucherBatch.objects.filter(router__owner=operator).select_related(
        "router", "profile"
    )
    return render(request, "hotspots/batch_list.html", {"batches": batches})


@login_required
def batch_detail(request, pk):
    batch = get_object_or_404(VoucherBatch, pk=pk, router__owner=get_operator(request.user))
    vouchers = batch.vouchers.all()
    voucher_rows = []
    for v in vouchers:
        payload = voucher_login_payload(v.username, v.password)
        voucher_rows.append(
            {
                "voucher": v,
                "qr_base64": qr_code_base64(payload),
            }
        )
    return render(
        request,
        "hotspots/batch_detail.html",
        {"batch": batch, "vouchers": vouchers, "voucher_rows": voucher_rows},
    )


@login_required
def batch_export_csv(request, pk):
    batch = get_object_or_404(VoucherBatch, pk=pk, router__owner=get_operator(request.user))
    content = batch_csv_content(batch)
    response = HttpResponse(content, content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="wifizone-lot-{batch.pk}.csv"'
    return response


@login_required
def voucher_export_csv(request):
    operator = get_operator(request.user)
    form = VoucherFilterForm(operator, request.GET or None)
    vouchers = Voucher.objects.filter(router__owner=operator).select_related("router", "profile")
    if form.is_valid():
        q = form.cleaned_data.get("q")
        if q:
            vouchers = vouchers.filter(
                Q(code__icontains=q) | Q(username__icontains=q)
            )
        status = form.cleaned_data.get("status")
        if status:
            vouchers = vouchers.filter(status=status)
        router = form.cleaned_data.get("router")
        if router:
            vouchers = vouchers.filter(router=router)

    content = vouchers_csv_content(vouchers[:5000])
    response = HttpResponse(content, content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = "attachment; filename=wifizone-vouchers.csv"
    return response


@login_required
def reports(request):
    operator = get_operator(request.user)
    total_vouchers = Voucher.objects.filter(router__owner=operator).count()
    total_revenue = (
        Voucher.objects.filter(router__owner=operator).aggregate(s=Sum("sold_price"))["s"] or 0
    )
    by_profile = (
        Voucher.objects.filter(router__owner=operator)
        .values("profile__name")
        .annotate(count=Count("id"), revenue=Sum("sold_price"))
        .order_by("-count")
    )
    recent_batches = VoucherBatch.objects.filter(router__owner=operator).select_related(
        "profile", "router"
    )[:10]

    return render(
        request,
        "hotspots/reports.html",
        {
            "total_vouchers": total_vouchers,
            "total_revenue": total_revenue,
            "by_profile": by_profile,
            "recent_batches": recent_batches,
        },
    )


@login_required
def login_template_list(request):
    operator = get_operator(request.user)
    templates = HotspotLoginTemplate.objects.filter(
        DQ(owner=operator) | DQ(is_system=True),
        is_active=True,
    ).distinct()
    return render(request, "hotspots/login_template_list.html", {"templates": templates})


@login_required
def login_template_create(request):
    operator = get_operator(request.user)
    if request.method == "POST":
        form = HotspotLoginTemplateForm(request.POST)
        if form.is_valid():
            template = form.save(commit=False)
            template.owner = operator
            template.is_system = False
            template.save()
            messages.success(request, f"Template « {template.name} » créé.")
            return redirect("hotspots:login_template_list")
    else:
        form = HotspotLoginTemplateForm(initial={"html_body": DEFAULT_LOGIN_HTML})

    return render(request, "hotspots/login_template_form.html", {"form": form, "title": "Nouveau template"})


@login_required
def login_template_edit(request, pk):
    operator = get_operator(request.user)
    template = get_object_or_404(HotspotLoginTemplate, pk=pk, owner=operator)
    if request.method == "POST":
        form = HotspotLoginTemplateForm(request.POST, instance=template)
        if form.is_valid():
            form.save()
            messages.success(request, "Template mis à jour.")
            return redirect("hotspots:login_template_list")
    else:
        form = HotspotLoginTemplateForm(instance=template)

    return render(
        request,
        "hotspots/login_template_form.html",
        {"form": form, "title": f"Modifier {template.name}", "template": template},
    )


@login_required
def login_template_preview(request, pk):
    operator = get_operator(request.user)
    template = get_object_or_404(
        HotspotLoginTemplate,
        pk=pk,
    )
    if template.owner and template.owner != operator:
        return redirect("hotspots:login_template_list")
    html = build_mikrotik_login_html(template, operator=operator)
    return render(request, "hotspots/login_template_preview.html", {"template": template, "preview_html": html})


@login_required
def login_template_download(request, pk):
    operator = get_operator(request.user)
    template = get_object_or_404(HotspotLoginTemplate, pk=pk)
    if template.owner and template.owner != operator and not template.is_system:
        return redirect("hotspots:login_template_list")
    html = build_mikrotik_login_html(template, operator=operator)
    response = HttpResponse(html, content_type="text/html; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="login-{template.slug}.html"'
    return response


@login_required
def pos_list(request):
    operator = get_operator(request.user)
    from hotspots.models import PointOfSale
    pos_list_qs = PointOfSale.objects.filter(operator=operator)
    if request.method == "POST" and is_team_owner(request.user):
        PointOfSale.objects.create(
            operator=operator,
            name=request.POST["name"],
            location=request.POST.get("location", ""),
        )
        messages.success(request, "Point de vente créé.")
        return redirect("hotspots:pos_list")
    return render(request, "hotspots/pos_list.html", {"pos_list": pos_list_qs, "is_owner": is_team_owner(request.user)})


@login_required
def wallet_list(request):
    operator = get_operator(request.user)
    from hotspots.models import CustomerWallet, WalletTransaction
    wallets = CustomerWallet.objects.filter(operator=operator)
    if request.method == "POST":
        phone = request.POST["phone"]
        amount = int(request.POST.get("amount", 0))
        wallet, _ = CustomerWallet.objects.get_or_create(operator=operator, phone=phone)
        wallet.balance += amount
        wallet.save()
        WalletTransaction.objects.create(
            wallet=wallet,
            amount=amount,
            tx_type=WalletTransaction.TxType.TOPUP,
            note=request.POST.get("note", "Recharge manuelle"),
            created_by=request.user,
        )
        from core.services.audit import log_action
        log_action(operator, request.user, "wallet_topup", f"{phone} +{amount}", request)
        messages.success(request, f"Recharge {amount} FCFA pour {phone}")
        return redirect("hotspots:wallet_list")
    return render(request, "hotspots/wallet_list.html", {"wallets": wallets})


@login_required
def import_users(request):
    operator = get_operator(request.user)
    if request.method == "POST" and request.FILES.get("file"):
        import csv
        from io import TextIOWrapper
        from routers.models import Router
        from routers.services.mikrotik import MikroTikUser, get_service_for_router

        router = get_object_or_404(Router, pk=request.POST["router"], owner=operator)
        service = get_service_for_router(router)
        profile = request.POST.get("profile", "default")
        count = 0
        reader = csv.DictReader(TextIOWrapper(request.FILES["file"], encoding="utf-8"))
        for row in reader:
            u = row.get("username") or row.get("user")
            p = row.get("password") or row.get("pass")
            if u and p:
                service.add_hotspot_user(MikroTikUser(name=u, password=p, profile=profile))
                count += 1
        messages.success(request, f"{count} utilisateur(s) importé(s).")
        return redirect("hotspots:import_users")
    routers = Router.objects.filter(owner=operator)
    return render(request, "hotspots/import_users.html", {"routers": routers})


@login_required
def advanced_reports(request):
    if not can_view_reports(request.user):
        messages.error(request, "Permission refusée.")
        return redirect("dashboard:home")
    operator = get_operator(request.user)
    from django.db.models.functions import TruncHour
    from hotspots.models import Voucher

    hourly = (
        Voucher.objects.filter(router__owner=operator)
        .annotate(hour=TruncHour("created_at"))
        .values("hour")
        .annotate(count=Count("id"), revenue=Sum("sold_price"))
        .order_by("-hour")[:48]
    )
    by_staff = (
        Voucher.objects.filter(router__owner=operator, sold_by__isnull=False)
        .values("sold_by__username")
        .annotate(count=Count("id"), revenue=Sum("sold_price"), commission=Sum("commission_amount"))
    )
    return render(
        request,
        "hotspots/advanced_reports.html",
        {"hourly": hourly, "by_staff": by_staff},
    )


@login_required
def bluetooth_print(request):
    batch_id = request.GET.get("batch")
    batch = None
    vouchers = []
    if batch_id:
        batch = get_object_or_404(VoucherBatch, pk=batch_id, router__owner=get_operator(request.user))
        vouchers = batch.vouchers.all()
    return render(request, "hotspots/bluetooth_print.html", {"batch": batch, "vouchers": vouchers})


@login_required
def reports_pdf(request):
    if not can_view_reports(request.user):
        messages.error(request, "Permission refusée.")
        return redirect("dashboard:home")
    operator = get_operator(request.user)
    total_vouchers = Voucher.objects.filter(router__owner=operator).count()
    total_revenue = (
        Voucher.objects.filter(router__owner=operator).aggregate(s=Sum("sold_price"))["s"] or 0
    )
    by_profile = list(
        Voucher.objects.filter(router__owner=operator)
        .values("profile__name")
        .annotate(count=Count("id"), revenue=Sum("sold_price"))
        .order_by("-count")
    )
    from hotspots.services.report_pdf import build_reports_pdf

    pdf_bytes = build_reports_pdf(operator.display_name, total_vouchers, total_revenue, by_profile)
    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = "attachment; filename=wifizone-rapport.pdf"
    return response


@login_required
def loyalty_settings(request):
    operator = get_operator(request.user)
    from hotspots.models import LoyaltyProgram
    prog, _ = LoyaltyProgram.objects.get_or_create(operator=operator)
    if request.method == "POST":
        prog.points_per_voucher = int(request.POST.get("points_per_voucher", 1))
        prog.vouchers_per_reward = int(request.POST.get("vouchers_per_reward", 10))
        prog.reward_description = request.POST.get("reward_description", prog.reward_description)
        prog.is_active = request.POST.get("is_active") == "on"
        prog.save()
        messages.success(request, "Programme fidélité mis à jour.")
        return redirect("hotspots:loyalty")
    return render(request, "hotspots/loyalty.html", {"program": prog})
