"""Résolution tenant opérateur (propriétaire vs employé)."""

from django.conf import settings

from billing.services import get_user_subscription


def get_operator(user):
    """Retourne le propriétaire de la zone WiFi (tenant)."""
    if not user.is_authenticated:
        return None
    membership = (
        user.team_memberships.filter(is_active=True).select_related("owner").first()
    )
    if membership:
        return membership.owner
    return user


def is_team_owner(user):
    return user.is_authenticated and get_operator(user) == user


def get_team_role(user):
    if not user.is_authenticated:
        return None
    if get_operator(user) == user:
        return "owner"
    membership = user.team_memberships.filter(is_active=True).first()
    return membership.role if membership else None


def can_manage_team(user):
    """Gestion équipe : propriétaire ou manager Enterprise."""
    if not is_team_owner(user):
        membership = user.team_memberships.filter(is_active=True).first()
        if not membership or membership.role != "manager":
            return False
    operator = get_operator(user)
    sub = get_user_subscription(operator)
    if not sub or not sub.is_valid:
        return False
    return sub.plan.slug == "enterprise" or (sub.plan.max_staff or 0) > 0


def can_generate_vouchers(user):
    role = get_team_role(user)
    return role in ("owner", "manager", "staff")


def can_manage_routers(user):
    role = get_team_role(user)
    return role in ("owner", "manager")


def operator_queryset_filter(user, queryset, owner_field="owner"):
    operator = get_operator(user)
    return queryset.filter(**{owner_field: operator})
