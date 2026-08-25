from billing.services import get_user_subscription


def subscription_context(request):
    sub = get_user_subscription(request.user) if request.user.is_authenticated else None
    plan = sub.plan if sub else None
    return {
        "current_subscription": sub,
        "current_plan": plan,
    }
