import random
import string
from decimal import Decimal

from django.db import transaction

from accounts.tenant import get_membership, get_operator
from billing.services import get_user_subscription
from core.models import AuditLog
from core.services.audit import log_action
from core.services.webhooks import fire_webhook
from routers.services.mikrotik import MikroTikUser, get_service_for_router

from hotspots.models import HotspotProfile, Voucher, VoucherBatch


def _generate_code(length=8, prefix=""):
    chars = string.ascii_uppercase + string.digits
    chars = chars.replace("0", "").replace("O", "").replace("1", "").replace("I", "")
    code = "".join(random.choices(chars, k=length))
    return f"{prefix}{code}" if prefix else code


def generate_vouchers(
    router,
    profile: HotspotProfile,
    quantity: int,
    user,
    prefix: str = "",
    sync_mikrotik: bool = True,
) -> tuple[VoucherBatch | None, str]:
    """Génère un lot de vouchers et pousse sur MikroTik si demandé."""
    operator = get_operator(user)
    sub = get_user_subscription(operator)
    if not sub or not sub.is_valid:
        return None, "Abonnement invalide ou expiré."

    if not sub.can_create_vouchers(quantity):
        remaining = sub.plan.max_vouchers_month - sub.vouchers_used_this_month
        return None, f"Limite mensuelle atteinte. Restant : {remaining} voucher(s)."

    profile_count = HotspotProfile.objects.filter(router__owner=operator).count()
    if profile_count > sub.plan.max_profiles:
        return None, f"Limite de profils atteinte ({sub.plan.max_profiles} max)."

    service = get_service_for_router(router)
    membership = get_membership(user)
    commission_per = Decimal("0")
    point_of_sale = None
    if membership and membership.commission_percent:
        commission_per = profile.price * membership.commission_percent / Decimal("100")
        point_of_sale = membership.point_of_sale

    batch = VoucherBatch(
        router=router,
        profile=profile,
        quantity=quantity,
        prefix=prefix,
        created_by=user,
        total_price=profile.price * quantity,
    )

    vouchers = []
    with transaction.atomic():
        batch.save()
        for _ in range(quantity):
            code = _generate_code(length=8, prefix=prefix)
            while Voucher.objects.filter(code=code).exists():
                code = _generate_code(length=8, prefix=prefix)

            username = code
            password = _generate_code(length=6)

            voucher = Voucher(
                batch=batch,
                router=router,
                profile=profile,
                code=code,
                username=username,
                password=password,
                sold_price=profile.price,
                sold_by=user,
                point_of_sale=point_of_sale,
                commission_amount=commission_per,
            )
            vouchers.append(voucher)

        Voucher.objects.bulk_create(vouchers)
        sub.record_voucher_usage(quantity)

    if sync_mikrotik:
        for voucher in Voucher.objects.filter(batch=batch):
            try:
                service.add_hotspot_user(
                    MikroTikUser(
                        name=voucher.username,
                        password=voucher.password,
                        profile=profile.mikrotik_profile,
                        comment=f"wifizone-{batch.pk}",
                    )
                )
                voucher.synced_to_mikrotik = True
                voucher.save(update_fields=["synced_to_mikrotik"])
            except Exception:
                pass

    log_action(
        operator,
        user,
        AuditLog.Action.VOUCHER_GENERATE,
        f"Lot #{batch.pk}: {quantity} × {profile.name}",
    )
    fire_webhook(
        operator,
        "voucher.created",
        {
            "batch_id": batch.pk,
            "router_id": router.pk,
            "profile_id": profile.pk,
            "quantity": quantity,
            "total_price": str(batch.total_price),
        },
    )

    return batch, f"{quantity} voucher(s) généré(s) avec succès."
