from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Utilisateur avec profil gamifié (XP, série, cœurs)."""

    avatar = models.ImageField(upload_to="avatars/", blank=True, null=True)
    xp = models.PositiveIntegerField(default=0)
    streak = models.PositiveIntegerField(default=0)
    hearts = models.PositiveSmallIntegerField(default=5)
    last_activity_date = models.DateField(null=True, blank=True)
    bio = models.CharField(max_length=280, blank=True)
    reminder_enabled = models.BooleanField(default=False)
    reminder_hour = models.PositiveSmallIntegerField(
        default=19,
        help_text="Heure du rappel quotidien (0-23)",
    )

    class Meta:
        ordering = ["-xp", "username"]

    def __str__(self) -> str:
        return self.username

    @property
    def level(self) -> int:
        """Niveau calculé à partir de l'XP (100 XP par niveau)."""
        return self.xp // 100 + 1
