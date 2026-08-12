from django.conf import settings
from django.db import models
from django.utils import timezone

from courses.models import Exercise, Lesson, Track


class UserLessonProgress(models.Model):
    """Progression d'un utilisateur sur une leçon."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="lesson_progress",
    )
    lesson = models.ForeignKey(Lesson, on_delete=models.CASCADE, related_name="user_progress")
    completed = models.BooleanField(default=False)
    score = models.PositiveSmallIntegerField(default=0)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = [("user", "lesson")]

    def __str__(self) -> str:
        status = "✓" if self.completed else "…"
        return f"{status} {self.user.username} — {self.lesson.title}"


class UserExerciseAttempt(models.Model):
    """Tentative sur un exercice."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="exercise_attempts",
    )
    exercise = models.ForeignKey(Exercise, on_delete=models.CASCADE, related_name="attempts")
    is_correct = models.BooleanField()
    answer = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]


class UserTrackProgress(models.Model):
    """Déverrouillage et avancement sur un parcours."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="track_progress",
    )
    track = models.ForeignKey(Track, on_delete=models.CASCADE, related_name="user_progress")
    is_unlocked = models.BooleanField(default=False)
    lessons_completed = models.PositiveSmallIntegerField(default=0)

    class Meta:
        unique_together = [("user", "track")]


class DailyActivity(models.Model):
    """Activité quotidienne pour calculer la série (streak)."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="daily_activities",
    )
    date = models.DateField(default=timezone.localdate)
    xp_earned = models.PositiveIntegerField(default=0)
    lessons_done = models.PositiveSmallIntegerField(default=0)

    class Meta:
        unique_together = [("user", "date")]
        ordering = ["-date"]
