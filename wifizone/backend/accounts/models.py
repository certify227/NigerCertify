from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Propriétaire de zone WiFi (opérateur hotspot)."""

    company_name = models.CharField("entreprise / zone WiFi", max_length=200, blank=True)
    phone = models.CharField("téléphone", max_length=30, blank=True)
    city = models.CharField("ville", max_length=100, blank=True)
    country = models.CharField("pays", max_length=100, default="Niger")
    is_reseller = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=32, blank=True)
    totp_enabled = models.BooleanField(default=False)
    gdpr_consent_at = models.DateTimeField(null=True, blank=True)
    reseller = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reseller_clients",
    )

    class Meta:
        verbose_name = "utilisateur"
        verbose_name_plural = "utilisateurs"

    def __str__(self):
        return self.get_full_name() or self.username

    @property
    def display_name(self):
        return self.company_name or self.get_full_name() or self.username


class TeamInvitation(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="team_invitations")
    email = models.EmailField()
    role = models.CharField(max_length=20, default="staff")
    token = models.CharField(max_length=64, unique=True)
    accepted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()


class TeamMembership(models.Model):
    """Employé rattaché à un opérateur WiFi (Enterprise)."""

    class Role(models.TextChoices):
        MANAGER = "manager", "Gérant"
        STAFF = "staff", "Employé (vente vouchers)"

    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="team_members",
    )
    member = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="team_memberships",
    )
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.STAFF)
    is_active = models.BooleanField(default=True)
    can_manage_routers = models.BooleanField(default=False)
    can_generate_vouchers = models.BooleanField(default=True)
    can_view_reports = models.BooleanField(default=True)
    can_manage_team = models.BooleanField(default=False)
    commission_percent = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    point_of_sale = models.ForeignKey(
        "hotspots.PointOfSale",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="staff",
    )
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("owner", "member")
        verbose_name = "membre d'équipe"
        verbose_name_plural = "membres d'équipe"

    def __str__(self):
        return f"{self.member.username} → {self.owner.display_name} ({self.role})"

    def apply_role_defaults(self):
        if self.role == self.Role.MANAGER:
            self.can_manage_routers = True
            self.can_generate_vouchers = True
            self.can_view_reports = True
            self.can_manage_team = True
        elif self.role == self.Role.STAFF:
            self.can_manage_routers = False
            self.can_generate_vouchers = True
            self.can_view_reports = True
            self.can_manage_team = False
