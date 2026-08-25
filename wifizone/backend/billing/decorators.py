from functools import wraps

from django.contrib import messages
from django.shortcuts import redirect

from billing.services import get_user_subscription


def subscription_required(view_func):
    """Redirige si l'abonnement est expiré ou invalide."""

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        sub = get_user_subscription(request.user)
        if not sub or not sub.is_valid:
            messages.error(
                request,
                "Votre abonnement a expiré. Renouvelez pour continuer.",
            )
            return redirect("billing:pricing")
        return view_func(request, *args, **kwargs)

    return wrapper
