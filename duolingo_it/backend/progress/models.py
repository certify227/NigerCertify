"""Modèles de suivi de progression."""
from django.conf import settings
from django.db import models


class LessonCompletion(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="lesson_completions",
        on_delete=models.CASCADE,
    )
    lesson = models.ForeignKey("courses.Lesson", on_delete=models.CASCADE)
    xp_earned = models.PositiveIntegerField(default=0)
    correct_count = models.PositiveIntegerField(default=0)
    total_count = models.PositiveIntegerField(default=0)
    completed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "lesson")
        ordering = ["-completed_at"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.user} → {self.lesson}"


class ExerciseAttempt(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="exercise_attempts",
        on_delete=models.CASCADE,
    )
    exercise = models.ForeignKey("courses.Exercise", on_delete=models.CASCADE)
    submitted_answer = models.CharField(max_length=255, blank=True, default="")
    is_correct = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
