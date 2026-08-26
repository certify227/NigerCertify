from datetime import timedelta

from django.utils import timezone

from .models import Plan, Subscription


def get_default_plan():
    return Plan.objects.filter(is_active=True).order_by("sort_order").first()


def activate_trial(user, days=14):
    """Active un essai gratuit sur le forfait Starter."""
    plan = Plan.objects.filter(slug="starter").first() or get_default_plan()
    if not plan:
        return None

    expires = timezone.now() + timedelta(days=days)
    subscription, _ = Subscription.objects.update_or_create(
        user=user,
        defaults={
            "plan": plan,
            "status": Subscription.Status.TRIAL,
            "expires_at": expires,
            "month_reset_at": timezone.now(),
        },
    )
    return subscription


def activate_plan(user, plan_slug):
    """Active ou change le forfait (simulation paiement — intégrer Stripe plus tard)."""
    plan = Plan.objects.filter(slug=plan_slug, is_active=True).first()
    if not plan:
        return None

    expires = timezone.now() + timedelta(days=30)
    subscription, _ = Subscription.objects.update_or_create(
        user=user,
        defaults={
            "plan": plan,
            "status": Subscription.Status.ACTIVE,
            "expires_at": expires,
            "month_reset_at": timezone.now(),
        },
    )
    return subscription


def get_user_subscription(user):
    if not user.is_authenticated:
        return None
    try:
        sub = Subscription.objects.select_related("plan").get(user=user)
        sub.reset_monthly_usage_if_needed()
        return sub
    except Subscription.DoesNotExist:
        return None
