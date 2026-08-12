from datetime import timedelta

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    """Custom user carrying Duolingo-style gamification state."""

    MAX_HEARTS = 5

    xp = models.PositiveIntegerField(default=0)
    gems = models.PositiveIntegerField(default=0)
    hearts = models.PositiveIntegerField(default=MAX_HEARTS)
    streak_count = models.PositiveIntegerField(default=0)
    last_activity_date = models.DateField(null=True, blank=True)
    daily_goal_xp = models.PositiveIntegerField(default=50)
    avatar = models.CharField(max_length=8, default="🦉")

    def register_activity(self, xp_gained: int) -> None:
        """Update XP and streak after a study session on the current day."""
        today = timezone.localdate()
        if self.last_activity_date == today:
            pass  # already counted today, keep streak
        elif self.last_activity_date == today - timedelta(days=1):
            self.streak_count += 1
        else:
            self.streak_count = 1
        self.last_activity_date = today
        self.xp += xp_gained
        self.gems += max(1, xp_gained // 10)
        self.save(
            update_fields=[
                "xp",
                "gems",
                "streak_count",
                "last_activity_date",
            ]
        )

    def __str__(self) -> str:
        return self.username
