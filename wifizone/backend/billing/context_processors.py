from accounts.tenant import get_operator
from billing.services import get_user_subscription


def subscription_context(request):
    if not request.user.is_authenticated:
        return {"current_subscription": None, "current_plan": None, "operator": None}
    operator = get_operator(request.user)
    sub = get_user_subscription(operator)
    return {
        "current_subscription": sub,
        "current_plan": sub.plan if sub else None,
        "operator": operator,
    }
