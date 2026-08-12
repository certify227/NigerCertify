"""Services de gamification : XP, cœurs, séries."""

from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from progress.models import DailyActivity


def update_streak(user) -> None:
    """Met à jour la série de jours consécutifs."""
    today = timezone.localdate()
    if user.last_activity_date == today:
        return

    if user.last_activity_date == today - timedelta(days=1):
        user.streak += 1
    elif user.last_activity_date is None or user.last_activity_date < today - timedelta(days=1):
        user.streak = 1

    user.last_activity_date = today
    user.save(update_fields=["streak", "last_activity_date"])


def add_xp(user, amount: int) -> None:
    """Ajoute de l'XP et enregistre l'activité du jour."""
    user.xp += amount
    user.save(update_fields=["xp"])
    update_streak(user)

    activity, _ = DailyActivity.objects.get_or_create(
        user=user,
        date=timezone.localdate(),
        defaults={"xp_earned": 0, "lessons_done": 0},
    )
    activity.xp_earned += amount
    activity.save(update_fields=["xp_earned"])


def lose_heart(user) -> int:
    """Retire un cœur. Retourne les cœurs restants."""
    if user.hearts > 0:
        user.hearts -= 1
        user.save(update_fields=["hearts"])
    return user.hearts


def refill_hearts(user) -> None:
    """Recharge les cœurs au maximum."""
    user.hearts = settings.MAX_HEARTS
    user.save(update_fields=["hearts"])


def record_lesson_completion(user) -> None:
    """Enregistre une leçon terminée dans l'activité quotidienne."""
    update_streak(user)
    activity, _ = DailyActivity.objects.get_or_create(
        user=user,
        date=timezone.localdate(),
        defaults={"xp_earned": 0, "lessons_done": 0},
    )
    activity.lessons_done += 1
    activity.save(update_fields=["lessons_done"])
