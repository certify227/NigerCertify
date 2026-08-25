from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q, Sum
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from billing.decorators import subscription_required
from billing.services import get_user_subscription
from routers.models import Router

from .forms import GenerateVoucherForm, HotspotProfileForm, VoucherFilterForm
from .models import HotspotProfile, Voucher, VoucherBatch
from .services.export import batch_csv_content, vouchers_csv_content
from .services.qr import qr_code_base64, voucher_login_payload
from .services.voucher import generate_vouchers


@login_required
def profile_list(request):
    profiles = HotspotProfile.objects.filter(router__owner=request.user).select_related("router")
    sub = get_user_subscription(request.user)
    return render(
        request,
        "hotspots/profile_list.html",
        {"profiles": profiles, "subscription": sub},
    )


@login_required
@subscription_required
def profile_create(request):
    routers = Router.objects.filter(owner=request.user)
    if not routers.exists():
        messages.warning(request, "Ajoutez d'abord un routeur MikroTik.")
        return redirect("routers:create")

    sub = get_user_subscription(request.user)
    if sub and HotspotProfile.objects.filter(router__owner=request.user).count() >= sub.plan.max_profiles:
        messages.error(request, f"Limite de profils atteinte ({sub.plan.max_profiles} max).")
        return redirect("hotspots:profile_list")

    if request.method == "POST":
        form = HotspotProfileForm(request.user, request.POST)
        if form.is_valid():
            profile = form.save()
            messages.success(request, f"Profil « {profile.name} » créé.")
            return redirect("hotspots:profile_list")
    else:
        form = HotspotProfileForm(user=request.user)

    return render(request, "hotspots/profile_form.html", {"form": form, "title": "Nouveau profil"})


@login_required
def profile_edit(request, pk):
    profile = get_object_or_404(HotspotProfile, pk=pk, router__owner=request.user)
    if request.method == "POST":
        form = HotspotProfileForm(request.user, request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, "Profil mis à jour.")
            return redirect("hotspots:profile_list")
    else:
        form = HotspotProfileForm(user=request.user, instance=profile)

    return render(
        request,
        "hotspots/profile_form.html",
        {"form": form, "title": f"Modifier {profile.name}", "profile": profile},
    )


@login_required
def voucher_list(request):
    form = VoucherFilterForm(request.user, request.GET or None)
    vouchers = Voucher.objects.filter(router__owner=request.user).select_related("router", "profile")

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
    if request.method == "POST":
        form = GenerateVoucherForm(request.user, request.POST)
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
        form = GenerateVoucherForm(request.user)

    sub = get_user_subscription(request.user)
    return render(
        request,
        "hotspots/voucher_generate.html",
        {"form": form, "subscription": sub},
    )


@login_required
def batch_list(request):
    batches = VoucherBatch.objects.filter(router__owner=request.user).select_related(
        "router", "profile"
    )
    return render(request, "hotspots/batch_list.html", {"batches": batches})


@login_required
def batch_detail(request, pk):
    batch = get_object_or_404(VoucherBatch, pk=pk, router__owner=request.user)
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
    batch = get_object_or_404(VoucherBatch, pk=pk, router__owner=request.user)
    content = batch_csv_content(batch)
    response = HttpResponse(content, content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="wifizone-lot-{batch.pk}.csv"'
    return response


@login_required
def voucher_export_csv(request):
    form = VoucherFilterForm(request.user, request.GET or None)
    vouchers = Voucher.objects.filter(router__owner=request.user).select_related("router", "profile")
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
    user = request.user
    total_vouchers = Voucher.objects.filter(router__owner=user).count()
    total_revenue = (
        Voucher.objects.filter(router__owner=user).aggregate(s=Sum("sold_price"))["s"] or 0
    )
    by_profile = (
        Voucher.objects.filter(router__owner=user)
        .values("profile__name")
        .annotate(count=Count("id"), revenue=Sum("sold_price"))
        .order_by("-count")
    )
    recent_batches = VoucherBatch.objects.filter(router__owner=user).select_related(
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
