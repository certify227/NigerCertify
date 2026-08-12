"""Modèles pour les utilisateurs de CodeLingo."""
from __future__ import annotations

from datetime import date, timedelta

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Utilisateur personnalisé avec les compteurs de gamification."""

    xp = models.PositiveIntegerField(default=0)
    hearts = models.PositiveSmallIntegerField(default=5)
    streak = models.PositiveIntegerField(default=0)
    last_activity_date = models.DateField(null=True, blank=True)
    avatar = models.URLField(blank=True, default="")

    class Meta:
        ordering = ["-xp", "username"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.username

    @property
    def level(self) -> int:
        """Palier de niveau simple : 1 niveau par tranche de 100 XP."""
        return 1 + self.xp // 100

    def register_activity(self, today: date | None = None) -> None:
        """Met à jour la série (streak) et la date de dernière activité."""
        today = today or date.today()
        if self.last_activity_date == today:
            return
        if self.last_activity_date == today - timedelta(days=1):
            self.streak += 1
        else:
            self.streak = 1
        self.last_activity_date = today
