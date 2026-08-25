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
