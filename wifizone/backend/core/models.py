import secrets

from django.conf import settings
from django.db import models


class OperatorBranding(models.Model):
    """White-label par opérateur."""

    operator = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="branding",
    )
    app_name = models.CharField(max_length=80, default="WiFiZone Pro")
    logo_url = models.URLField(blank=True)
    primary_color = models.CharField(max_length=20, default="#0d6efd")
    custom_domain = models.CharField(max_length=255, blank=True)
    support_email = models.EmailField(blank=True)
    support_phone = models.CharField(max_length=30, blank=True)
    public_map_enabled = models.BooleanField(default=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)

    class Meta:
        verbose_name = "branding opérateur"


class OnboardingProgress(models.Model):
    operator = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="onboarding",
    )
    router_added = models.BooleanField(default=False)
    profile_created = models.BooleanField(default=False)
    voucher_generated = models.BooleanField(default=False)
    template_customized = models.BooleanField(default=False)
    team_invited = models.BooleanField(default=False)
    completed = models.BooleanField(default=False)

    @property
    def percent(self):
        steps = [self.router_added, self.profile_created, self.voucher_generated,
                 self.template_customized, self.team_invited]
        return int(sum(steps) / len(steps) * 100)


class AuditLog(models.Model):
    class Action(models.TextChoices):
        LOGIN = "login", "Connexion"
        VOUCHER_GENERATE = "voucher_generate", "Génération vouchers"
        ROUTER_ADD = "router_add", "Routeur ajouté"
        ROUTER_TEST = "router_test", "Test routeur"
        TEAM_ADD = "team_add", "Employé ajouté"
        WALLET_TOPUP = "wallet_topup", "Crédit client"
        WEBHOOK_FIRE = "webhook_fire", "Webhook"
        SETTINGS = "settings", "Paramètres"
        OTHER = "other", "Autre"

    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="audit_logs",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="actions_performed",
    )
    action = models.CharField(max_length=40, choices=Action.choices)
    detail = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]


class WebhookEndpoint(models.Model):
    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="webhooks",
    )
    url = models.URLField()
    secret = models.CharField(max_length=64, default="")
    events = models.JSONField(
        default=list,
        help_text="voucher.created, router.offline, subscription.expiring",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.secret:
            self.secret = secrets.token_hex(32)
        super().save(*args, **kwargs)


class Notification(models.Model):
    class Channel(models.TextChoices):
        IN_APP = "in_app", "Application"
        EMAIL = "email", "Email"
        SMS = "sms", "SMS"

    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notifications",
    )
    channel = models.CharField(max_length=20, choices=Channel.choices, default=Channel.IN_APP)
    title = models.CharField(max_length=200)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]


class NotificationPreference(models.Model):
    operator = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notification_prefs",
    )
    router_offline_email = models.BooleanField(default=True)
    router_offline_sms = models.BooleanField(default=False)
    subscription_expiring_email = models.BooleanField(default=True)
    voucher_batch_email = models.BooleanField(default=False)
