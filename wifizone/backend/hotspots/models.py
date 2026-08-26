from decimal import Decimal

from django.conf import settings
from django.db import models


class HotspotLoginTemplate(models.Model):
    """Template HTML page de login hotspot MikroTik personnalisable."""

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="login_templates",
        null=True,
        blank=True,
        help_text="Null = template système partagé",
    )
    name = models.CharField("nom", max_length=120)
    slug = models.SlugField(max_length=120)
    description = models.TextField(blank=True)
    html_body = models.TextField("HTML")
    is_system = models.BooleanField("template système", default=False)
    is_active = models.BooleanField(default=True)
    primary_color = models.CharField(max_length=20, default="#0d6efd")
    background_color = models.CharField(max_length=20, default="#1a1d23")
    wifi_name = models.CharField(max_length=120, blank=True, default="WiFiZone")
    logo_url = models.URLField(blank=True)
    html_status = models.TextField("HTML status", blank=True)
    html_logout = models.TextField("HTML logout", blank=True)
    locale = models.CharField(max_length=10, default="fr", help_text="fr, en, ha")
    ad_video_url = models.URLField(blank=True, help_text="Vidéo/pub avant login")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "template login hotspot"
        verbose_name_plural = "templates login hotspot"
        unique_together = ("owner", "slug")

    def __str__(self):
        return self.name

    def render_html(self, operator=None, router=None):
        from hotspots.services.login_template import render_login_template

        return render_login_template(self, operator=operator, router=router)


class PointOfSale(models.Model):
    """Point de vente / kiosque."""

    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="points_of_sale",
    )
    name = models.CharField(max_length=120)
    location = models.CharField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "point de vente"
        verbose_name_plural = "points de vente"

    def __str__(self):
        return self.name


class CustomerWallet(models.Model):
    """Crédit client prépayé (recharge manuelle, sans passerelle paiement)."""

    operator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="customer_wallets",
    )
    phone = models.CharField(max_length=30)
    name = models.CharField(max_length=120, blank=True)
    balance = models.DecimalField(max_digits=12, decimal_places=0, default=Decimal("0"))
    loyalty_points = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("operator", "phone")

    def __str__(self):
        return f"{self.phone} ({self.balance} FCFA)"


class WalletTransaction(models.Model):
    class TxType(models.TextChoices):
        TOPUP = "topup", "Recharge manuelle"
        DEBIT = "debit", "Débit voucher"
        LOYALTY = "loyalty", "Points fidélité"

    wallet = models.ForeignKey(CustomerWallet, on_delete=models.CASCADE, related_name="transactions")
    amount = models.DecimalField(max_digits=12, decimal_places=0)
    tx_type = models.CharField(max_length=20, choices=TxType.choices)
    note = models.CharField(max_length=200, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)


class LoyaltyProgram(models.Model):
    operator = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="loyalty_program",
    )
    points_per_voucher = models.PositiveIntegerField(default=1)
    vouchers_per_reward = models.PositiveIntegerField(
        default=10,
        help_text="Nombre de vouchers pour 1 récompense",
    )
    reward_description = models.CharField(max_length=200, default="1 voucher gratuit")
    is_active = models.BooleanField(default=True)


class HotspotProfile(models.Model):
    """Profil utilisateur hotspot (durée, limite data, prix)."""

    router = models.ForeignKey(
        "routers.Router",
        on_delete=models.CASCADE,
        related_name="profiles",
    )
    name = models.CharField("nom affiché", max_length=100)
    mikrotik_profile = models.CharField(
        "profil MikroTik",
        max_length=100,
        help_text="Nom du profil sur le routeur (ex: 1hour, 1day)",
    )
    validity_seconds = models.PositiveIntegerField(
        "validité (secondes)",
        default=3600,
        help_text="Durée de validité en secondes (3600 = 1h)",
    )
    data_limit_bytes = models.BigIntegerField(
        "limite data (octets)",
        null=True,
        blank=True,
        help_text="0 ou vide = illimité",
    )
    shared_users = models.PositiveIntegerField("utilisateurs partagés", default=1)
    price = models.DecimalField(
        "prix vente (FCFA)",
        max_digits=12,
        decimal_places=0,
        default=Decimal("0"),
    )
    parent_queue = models.CharField(max_length=100, blank=True, help_text="Parent queue MikroTik")
    is_active = models.BooleanField("actif", default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "profil hotspot"
        verbose_name_plural = "profils hotspot"

    def __str__(self):
        return f"{self.name} ({self.router.name})"

    @property
    def validity_display(self):
        secs = self.validity_seconds
        if secs >= 86400:
            days = secs // 86400
            return f"{days} jour(s)"
        if secs >= 3600:
            hours = secs // 3600
            return f"{hours} h"
        minutes = secs // 60
        return f"{minutes} min"


class VoucherBatch(models.Model):
    """Lot de vouchers générés."""

    router = models.ForeignKey(
        "routers.Router",
        on_delete=models.CASCADE,
        related_name="voucher_batches",
    )
    profile = models.ForeignKey(
        HotspotProfile,
        on_delete=models.CASCADE,
        related_name="batches",
    )
    quantity = models.PositiveIntegerField()
    prefix = models.CharField(max_length=20, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="voucher_batches",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    total_price = models.DecimalField(max_digits=14, decimal_places=0, default=Decimal("0"))

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "lot de vouchers"
        verbose_name_plural = "lots de vouchers"

    def __str__(self):
        return f"Lot {self.pk} — {self.quantity} vouchers"


class Voucher(models.Model):
    """Voucher / code d'accès WiFi."""

    class Status(models.TextChoices):
        UNUSED = "unused", "Non utilisé"
        ACTIVE = "active", "Actif"
        EXPIRED = "expired", "Expiré"
        DISABLED = "disabled", "Désactivé"

    batch = models.ForeignKey(
        VoucherBatch,
        on_delete=models.CASCADE,
        related_name="vouchers",
        null=True,
        blank=True,
    )
    router = models.ForeignKey(
        "routers.Router",
        on_delete=models.CASCADE,
        related_name="vouchers",
    )
    profile = models.ForeignKey(
        HotspotProfile,
        on_delete=models.CASCADE,
        related_name="vouchers",
    )
    code = models.CharField("code voucher", max_length=50, unique=True)
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=50)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.UNUSED,
    )
    sold_price = models.DecimalField(
        max_digits=12,
        decimal_places=0,
        default=Decimal("0"),
    )
    sold_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="vouchers_sold",
    )
    point_of_sale = models.ForeignKey(
        PointOfSale,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="vouchers",
    )
    commission_amount = models.DecimalField(
        max_digits=12, decimal_places=0, default=Decimal("0")
    )
    synced_to_mikrotik = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    activated_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "voucher"
        verbose_name_plural = "vouchers"

    def __str__(self):
        return self.code
