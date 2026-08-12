from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone


class Track(models.Model):
    slug = models.SlugField(unique=True)
    title = models.CharField(max_length=120)
    description = models.TextField()
    icon = models.CharField(max_length=40, default="terminal")
    color = models.CharField(max_length=20, default="#58cc02")
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "title"]

    def __str__(self) -> str:
        return self.title


class Unit(models.Model):
    track = models.ForeignKey(Track, related_name="units", on_delete=models.CASCADE)
    title = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["track__order", "order", "title"]
        unique_together = [("track", "order")]

    def __str__(self) -> str:
        return f"{self.track.title} - {self.title}"


class Lesson(models.Model):
    unit = models.ForeignKey(Unit, related_name="lessons", on_delete=models.CASCADE)
    title = models.CharField(max_length=120)
    summary = models.TextField()
    xp_reward = models.PositiveIntegerField(default=10)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["unit__track__order", "unit__order", "order", "title"]
        unique_together = [("unit", "order")]

    def __str__(self) -> str:
        return self.title


class Challenge(models.Model):
    class ChallengeType(models.TextChoices):
        MULTIPLE_CHOICE = "multiple_choice", "Choix multiple"
        FLASHCARD = "flashcard", "Carte mémoire"
        CODE_ORDER = "code_order", "Réordonner le code"

    lesson = models.ForeignKey(Lesson, related_name="challenges", on_delete=models.CASCADE)
    type = models.CharField(max_length=32, choices=ChallengeType.choices)
    prompt = models.TextField()
    choices = models.JSONField(default=list, blank=True)
    correct_answer = models.JSONField()
    explanation = models.TextField()
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["lesson__unit__track__order", "lesson__unit__order", "lesson__order", "order"]
        unique_together = [("lesson", "order")]

    def __str__(self) -> str:
        return f"{self.lesson.title} #{self.order}"


class LearnerProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, related_name="learner_profile", on_delete=models.CASCADE)
    total_xp = models.PositiveIntegerField(default=0)
    current_streak = models.PositiveIntegerField(default=0)
    last_practice_at = models.DateTimeField(null=True, blank=True)

    def record_practice(self, xp: int) -> None:
        now = timezone.now()
        if self.last_practice_at is None or self.last_practice_at.date() < now.date():
            yesterday = (now - timedelta(days=1)).date()
            self.current_streak = self.current_streak + 1 if self.last_practice_at and self.last_practice_at.date() == yesterday else 1
        self.total_xp += xp
        self.last_practice_at = now
        self.save(update_fields=["total_xp", "current_streak", "last_practice_at"])

    def __str__(self) -> str:
        return f"{self.user} - {self.total_xp} XP"


class LessonProgress(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="lesson_progress", on_delete=models.CASCADE)
    lesson = models.ForeignKey(Lesson, related_name="progress", on_delete=models.CASCADE)
    completed = models.BooleanField(default=False)
    earned_xp = models.PositiveIntegerField(default=0)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = [("user", "lesson")]

    def __str__(self) -> str:
        return f"{self.user} - {self.lesson}"


class Attempt(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="attempts", null=True, blank=True, on_delete=models.SET_NULL)
    challenge = models.ForeignKey(Challenge, related_name="attempts", on_delete=models.CASCADE)
    submitted_answer = models.JSONField()
    is_correct = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.challenge} - {'correct' if self.is_correct else 'incorrect'}"
