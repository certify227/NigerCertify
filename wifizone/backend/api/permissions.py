"""Permissions API REST."""

from rest_framework import permissions

from accounts.tenant import get_operator


class IsOperatorMember(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)


def get_operator_from_request(request):
    return get_operator(request.user)
