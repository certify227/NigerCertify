from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Propriétaire de zone WiFi (opérateur hotspot)."""

    company_name = models.CharField("entreprise / zone WiFi", max_length=200, blank=True)
    phone = models.CharField("téléphone", max_length=30, blank=True)
    city = models.CharField("ville", max_length=100, blank=True)
    country = models.CharField("pays", max_length=100, default="Niger")

    class Meta:
        verbose_name = "utilisateur"
        verbose_name_plural = "utilisateurs"

    def __str__(self):
        return self.get_full_name() or self.username

    @property
    def display_name(self):
        return self.company_name or self.get_full_name() or self.username


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
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("owner", "member")
        verbose_name = "membre d'équipe"
        verbose_name_plural = "membres d'équipe"

    def __str__(self):
        return f"{self.member.username} → {self.owner.display_name} ({self.role})"
