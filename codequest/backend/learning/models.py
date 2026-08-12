"""Data models for the CodeQuest IT-learning platform.

The structure mirrors Duolingo's hierarchy:

    Course -> Unit -> Lesson -> Exercise

Each authenticated user owns a :class:`Profile` that tracks gamification
state (XP, streak, hearts) and a :class:`LessonProgress` row per completed
lesson.
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class Course(models.Model):
    """A top-level learning track, e.g. "Python", "Networking"."""

    title = models.CharField(max_length=120)
    slug = models.SlugField(unique=True)
    description = models.TextField(blank=True)
    # A short emoji or icon identifier rendered by the Flutter client.
    icon = models.CharField(max_length=16, default="💻")
    color = models.CharField(max_length=9, default="#58CC02")
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.title


class Unit(models.Model):
    """A themed section grouping several lessons within a course."""

    course = models.ForeignKey(
        Course, related_name="units", on_delete=models.CASCADE
    )
    title = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.course.title} · {self.title}"


class Lesson(models.Model):
    """A single lesson made up of a handful of exercises."""

    unit = models.ForeignKey(
        Unit, related_name="lessons", on_delete=models.CASCADE
    )
    title = models.CharField(max_length=120)
    order = models.PositiveIntegerField(default=0)
    xp_reward = models.PositiveIntegerField(default=10)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.unit.title} · {self.title}"


class Exercise(models.Model):
    """A question inside a lesson.

    ``choices`` stores the list of possible answers (for multiple-choice and
    true/false questions). ``answer`` stores the canonical correct answer as a
    string; comparison is case-insensitive and trimmed.
    """

    class Kind(models.TextChoices):
        MULTIPLE_CHOICE = "multiple_choice", "Multiple choice"
        TRUE_FALSE = "true_false", "True / False"
        FILL_BLANK = "fill_blank", "Fill in the blank"

    lesson = models.ForeignKey(
        Lesson, related_name="exercises", on_delete=models.CASCADE
    )
    kind = models.CharField(
        max_length=32, choices=Kind.choices, default=Kind.MULTIPLE_CHOICE
    )
    prompt = models.TextField()
    choices = models.JSONField(default=list, blank=True)
    answer = models.CharField(max_length=255)
    explanation = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.lesson.title} · Q{self.order}"

    def is_correct(self, submitted: str) -> bool:
        """Return whether ``submitted`` matches the canonical answer."""

        if submitted is None:
            return False
        return str(submitted).strip().casefold() == self.answer.strip().casefold()


class Profile(models.Model):
    """Gamification state attached to every user."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name="profile",
        on_delete=models.CASCADE,
    )
    xp = models.PositiveIntegerField(default=0)
    streak = models.PositiveIntegerField(default=0)
    hearts = models.PositiveIntegerField(default=5)
    last_active = models.DateField(null=True, blank=True)

    MAX_HEARTS = 5

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"Profile<{self.user.username}>"

    @property
    def level(self) -> int:
        """Derive a level from total XP (100 XP per level)."""

        return self.xp // 100 + 1

    def register_activity(self) -> None:
        """Update the daily streak based on the last active date."""

        today = timezone.localdate()
        if self.last_active == today:
            return
        if self.last_active == today - timedelta(days=1):
            self.streak += 1
        else:
            self.streak = 1
        self.last_active = today


class LessonProgress(models.Model):
    """Tracks completion and best score of a lesson for a user."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="lesson_progress",
        on_delete=models.CASCADE,
    )
    lesson = models.ForeignKey(
        Lesson, related_name="progress", on_delete=models.CASCADE
    )
    completed = models.BooleanField(default=False)
    best_score = models.PositiveIntegerField(default=0)
    total_questions = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "lesson")

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.user.username} · {self.lesson.title}"
