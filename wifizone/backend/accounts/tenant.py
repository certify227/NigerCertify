"""Résolution tenant opérateur (propriétaire vs employé)."""

from billing.services import get_user_subscription


def get_operator(user):
    if not user.is_authenticated:
        return None
    membership = user.team_memberships.filter(is_active=True).select_related("owner").first()
    if membership:
        return membership.owner
    return user


def get_membership(user):
    if not user.is_authenticated:
        return None
    if get_operator(user) == user:
        return None
    return user.team_memberships.filter(is_active=True).first()


def is_team_owner(user):
    return user.is_authenticated and get_operator(user) == user


def get_team_role(user):
    if not user.is_authenticated:
        return None
    if get_operator(user) == user:
        return "owner"
    membership = get_membership(user)
    return membership.role if membership else None


def can_manage_team(user):
    if is_team_owner(user):
        operator = user
    else:
        membership = get_membership(user)
        if not membership or not membership.can_manage_team:
            return False
        operator = membership.owner
    sub = get_user_subscription(operator)
    if not sub or not sub.is_valid:
        return False
    return sub.plan.slug == "enterprise" or (sub.plan.max_staff or 0) > 0


def can_generate_vouchers(user):
    if is_team_owner(user):
        return True
    membership = get_membership(user)
    return membership and membership.can_generate_vouchers


def can_manage_routers(user):
    if is_team_owner(user):
        return True
    membership = get_membership(user)
    return membership and membership.can_manage_routers


def can_view_reports(user):
    if is_team_owner(user):
        return True
    membership = get_membership(user)
    return membership and membership.can_view_reports


def operator_queryset_filter(user, queryset, owner_field="owner"):
    operator = get_operator(user)
    return queryset.filter(**{owner_field: operator})
