import base64
import hashlib

from cryptography.fernet import Fernet
from django.conf import settings
from django.db import models


def _get_fernet():
    key = settings.FERNET_KEY
    if not key:
        derived = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        key = base64.urlsafe_b64encode(derived)
    return Fernet(key)


class Router(models.Model):
    """Routeur MikroTik connecté via API."""

    class ConnectionStatus(models.TextChoices):
        UNKNOWN = "unknown", "Non testé"
        ONLINE = "online", "En ligne"
        OFFLINE = "offline", "Hors ligne"
        ERROR = "error", "Erreur"

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="routers",
    )
    name = models.CharField("nom", max_length=100)
    host = models.CharField("adresse IP / hostname", max_length=255)
    port = models.PositiveIntegerField("port API", default=8728)
    username = models.CharField("utilisateur API", max_length=100)
    password_encrypted = models.TextField("mot de passe (chiffré)")
    hotspot_server = models.CharField(
        "serveur hotspot",
        max_length=100,
        blank=True,
        default="hotspot1",
    )
    login_template = models.ForeignKey(
        "hotspots.HotspotLoginTemplate",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="routers",
        verbose_name="template login",
    )
    is_active = models.BooleanField("actif", default=True)
    connection_status = models.CharField(
        max_length=20,
        choices=ConnectionStatus.choices,
        default=ConnectionStatus.UNKNOWN,
    )
    last_connected_at = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    snmp_enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "routeur"
        verbose_name_plural = "routeurs"

    def __str__(self):
        return f"{self.name} ({self.host})"

    def set_password(self, raw_password: str):
        f = _get_fernet()
        self.password_encrypted = f.encrypt(raw_password.encode()).decode()

    def get_password(self) -> str:
        f = _get_fernet()
        return f.decrypt(self.password_encrypted.encode()).decode()
