from decimal import Decimal

from django.conf import settings
from django.db import models
from django.utils import timezone


class Plan(models.Model):
    """Forfait d'abonnement pour opérateurs WiFi."""

    name = models.CharField("nom", max_length=100)
    slug = models.SlugField(unique=True)
    description = models.TextField("description", blank=True)
    price_monthly = models.DecimalField(
        "prix mensuel (FCFA)",
        max_digits=12,
        decimal_places=0,
        default=Decimal("0"),
    )
    max_routers = models.PositiveIntegerField("routeurs max", default=1)
    max_vouchers_month = models.PositiveIntegerField("vouchers / mois", default=100)
    max_profiles = models.PositiveIntegerField("profils max", default=5)
    features = models.JSONField("fonctionnalités", default=list, blank=True)
    is_active = models.BooleanField("actif", default=True)
    is_highlighted = models.BooleanField("mis en avant", default=False)
    sort_order = models.PositiveIntegerField("ordre", default=0)

    class Meta:
        ordering = ["sort_order", "price_monthly"]
        verbose_name = "forfait"
        verbose_name_plural = "forfaits"

    def __str__(self):
        return self.name


class Subscription(models.Model):
    """Abonnement actif d'un opérateur."""

    class Status(models.TextChoices):
        TRIAL = "trial", "Essai"
        ACTIVE = "active", "Actif"
        PAST_DUE = "past_due", "Impayé"
        CANCELLED = "cancelled", "Annulé"
        EXPIRED = "expired", "Expiré"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="subscription",
    )
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT, related_name="subscriptions")
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.TRIAL,
    )
    started_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField("expire le")
    vouchers_used_this_month = models.PositiveIntegerField(default=0)
    month_reset_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "abonnement"
        verbose_name_plural = "abonnements"

    def __str__(self):
        return f"{self.user} — {self.plan.name}"

    @property
    def is_valid(self):
        if self.status in (self.Status.CANCELLED, self.Status.EXPIRED):
            return False
        return timezone.now() < self.expires_at

    def reset_monthly_usage_if_needed(self):
        now = timezone.now()
        if not self.month_reset_at or now.month != self.month_reset_at.month:
            self.vouchers_used_this_month = 0
            self.month_reset_at = now
            self.save(update_fields=["vouchers_used_this_month", "month_reset_at"])

    def can_create_vouchers(self, count=1):
        self.reset_monthly_usage_if_needed()
        if not self.is_valid:
            return False
        return self.vouchers_used_this_month + count <= self.plan.max_vouchers_month

    def record_voucher_usage(self, count=1):
        self.reset_monthly_usage_if_needed()
        self.vouchers_used_this_month += count
        self.save(update_fields=["vouchers_used_this_month"])
