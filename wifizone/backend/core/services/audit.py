"""Journal d'audit."""

from core.models import AuditLog


def log_action(operator, actor, action, detail="", request=None):
    ip = None
    if request:
        ip = request.META.get("REMOTE_ADDR")
    AuditLog.objects.create(
        operator=operator,
        actor=actor,
        action=action,
        detail=detail[:500],
        ip_address=ip,
    )
