from celery import shared_task
from django.utils import timezone

from accounts.tenant import get_operator
from billing.services import get_user_subscription
from core.models import Notification, NotificationPreference
from core.services.webhooks import fire_webhook
from routers.models import Router
from routers.services.mikrotik import get_service_for_router, test_router_connection


@shared_task
def check_routers_health():
    for router in Router.objects.filter(is_active=True).select_related("owner"):
        ok, msg = test_router_connection(router)
        was_online = router.connection_status == Router.ConnectionStatus.ONLINE
        router.connection_status = (
            Router.ConnectionStatus.ONLINE if ok else Router.ConnectionStatus.ERROR
        )
        router.last_error = "" if ok else msg
        if ok:
            router.last_connected_at = timezone.now()
        router.save()
        if was_online and not ok:
            prefs = NotificationPreference.objects.filter(operator=router.owner).first()
            if prefs and prefs.router_offline_email:
                Notification.objects.create(
                    operator=router.owner,
                    channel=Notification.Channel.IN_APP,
                    title=f"Routeur hors ligne : {router.name}",
                    message=msg,
                )
            if prefs and prefs.router_offline_sms and router.owner.phone:
                from core.services.sms import send_sms

                send_sms(
                    router.owner.phone,
                    f"WiFiZone: routeur {router.name} hors ligne — {msg[:80]}",
                )
            fire_webhook(router.owner, "router.offline", {"router_id": router.pk, "name": router.name})


@shared_task
def check_subscription_expiring():
    from billing.models import Subscription
    from datetime import timedelta

    soon = timezone.now() + timedelta(days=7)
    subs = Subscription.objects.filter(
        expires_at__lte=soon,
        expires_at__gt=timezone.now(),
        status__in=["active", "trial"],
    ).select_related("user", "plan")
    for sub in subs:
        Notification.objects.create(
            operator=sub.user,
            channel=Notification.Channel.IN_APP,
            title="Abonnement expire bientôt",
            message=f"Forfait {sub.plan.name} expire le {sub.expires_at:%d/%m/%Y}",
        )
        fire_webhook(
            sub.user,
            "subscription.expiring",
            {"expires_at": sub.expires_at.isoformat(), "plan": sub.plan.slug},
        )


@shared_task
def deliver_sms_notification(operator_id, message):
    """Stub SMS — log console (configurer gateway en production)."""
    import logging
    logging.getLogger("wifizone.sms").info("SMS to operator %s: %s", operator_id, message)
