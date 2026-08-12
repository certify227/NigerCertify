from django.conf import settings
from django.db import models
from django.utils.text import slugify


class Course(models.Model):
    """A learning track, e.g. "Python", "Réseaux", "Linux"."""

    title = models.CharField(max_length=120)
    slug = models.SlugField(max_length=140, unique=True, blank=True)
    subtitle = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=8, default="💻")
    color = models.CharField(max_length=9, default="#58CC02")
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "id"]

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title)
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return self.title


class Unit(models.Model):
    """A group of lessons inside a course (a section of the learning path)."""

    course = models.ForeignKey(Course, related_name="units", on_delete=models.CASCADE)
    title = models.CharField(max_length=120)
    description = models.CharField(max_length=255, blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self) -> str:
        return f"{self.course.title} · {self.title}"


class Lesson(models.Model):
    """A single lesson made of a handful of exercises."""

    unit = models.ForeignKey(Unit, related_name="lessons", on_delete=models.CASCADE)
    title = models.CharField(max_length=120)
    order = models.PositiveIntegerField(default=0)
    xp_reward = models.PositiveIntegerField(default=10)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self) -> str:
        return f"{self.unit.title} · {self.title}"


class Exercise(models.Model):
    """One question inside a lesson."""

    class Type(models.TextChoices):
        MULTIPLE_CHOICE = "multiple_choice", "Choix multiple"
        TRUE_FALSE = "true_false", "Vrai / Faux"
        FILL_BLANK = "fill_blank", "Texte à compléter"
        TYPE_ANSWER = "type_answer", "Réponse libre"

    lesson = models.ForeignKey(
        Lesson, related_name="exercises", on_delete=models.CASCADE
    )
    exercise_type = models.CharField(
        max_length=32, choices=Type.choices, default=Type.MULTIPLE_CHOICE
    )
    question = models.TextField()
    # For choice-based exercises: list of possible answers.
    choices = models.JSONField(default=list, blank=True)
    # Canonical correct answer (string). For multiple choice this matches one choice.
    correct_answer = models.CharField(max_length=255)
    explanation = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "id"]

    def is_correct(self, answer) -> bool:
        given = (str(answer) if answer is not None else "").strip().lower()
        return given == self.correct_answer.strip().lower()

    def __str__(self) -> str:
        return f"[{self.get_exercise_type_display()}] {self.question[:50]}"


class LessonProgress(models.Model):
    """Tracks a user's completion state for a lesson."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="lesson_progress",
        on_delete=models.CASCADE,
    )
    lesson = models.ForeignKey(
        Lesson, related_name="progress", on_delete=models.CASCADE
    )
    completed = models.BooleanField(default=False)
    best_score = models.PositiveIntegerField(default=0)  # percentage 0-100
    times_completed = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "lesson")

    def __str__(self) -> str:
        return f"{self.user} · {self.lesson} ({self.best_score}%)"
