from django.conf import settings
from django.db import models


class SupportTicket(models.Model):
    class Status(models.TextChoices):
        OPEN = "open", "Ouvert"
        IN_PROGRESS = "in_progress", "En cours"
        RESOLVED = "resolved", "Résolu"
        CLOSED = "closed", "Fermé"

    class Priority(models.TextChoices):
        LOW = "low", "Faible"
        NORMAL = "normal", "Normal"
        HIGH = "high", "Urgent"

    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="support_tickets",
    )
    subject = models.CharField(max_length=200)
    message = models.TextField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    priority = models.CharField(max_length=20, choices=Priority.choices, default=Priority.NORMAL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]


class TicketReply(models.Model):
    ticket = models.ForeignKey(SupportTicket, on_delete=models.CASCADE, related_name="replies")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
