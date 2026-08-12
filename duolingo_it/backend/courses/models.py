"""Modèles pour le catalogue de contenus pédagogiques."""
from __future__ import annotations

from django.db import models


class Course(models.Model):
    """Un cours regroupe des modules autour d'une thématique informatique."""

    LANGUAGES = [
        ("python", "Python"),
        ("linux", "Linux / Shell"),
        ("network", "Réseau"),
        ("web", "Web (HTML/CSS)"),
        ("security", "Cybersécurité"),
        ("git", "Git"),
    ]

    title = models.CharField(max_length=120)
    slug = models.SlugField(unique=True)
    description = models.TextField(blank=True)
    language = models.CharField(max_length=20, choices=LANGUAGES, default="python")
    icon = models.CharField(max_length=8, default="📘", help_text="Emoji court")
    color = models.CharField(max_length=7, default="#58CC02", help_text="Couleur HEX")
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.title


class Module(models.Model):
    """Un module (unit) regroupe plusieurs leçons dans un cours."""

    course = models.ForeignKey(Course, related_name="modules", on_delete=models.CASCADE)
    title = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["course_id", "order", "id"]
        unique_together = ("course", "order")

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.course.title} · {self.title}"


class Lesson(models.Model):
    """Une leçon est un mini-parcours d'exercices."""

    module = models.ForeignKey(Module, related_name="lessons", on_delete=models.CASCADE)
    title = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)
    xp_reward = models.PositiveIntegerField(default=10)

    class Meta:
        ordering = ["module_id", "order", "id"]
        unique_together = ("module", "order")

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.module.title} · {self.title}"


class Exercise(models.Model):
    """Un exercice au sein d'une leçon."""

    class Kind(models.TextChoices):
        MCQ = "mcq", "Question à choix multiples"
        TRUE_FALSE = "true_false", "Vrai / Faux"
        FILL_BLANK = "fill_blank", "Compléter le texte"
        CODE_OUTPUT = "code_output", "Que renvoie ce code ?"

    lesson = models.ForeignKey(Lesson, related_name="exercises", on_delete=models.CASCADE)
    kind = models.CharField(max_length=20, choices=Kind.choices, default=Kind.MCQ)
    prompt = models.TextField(help_text="Consigne / énoncé")
    code_snippet = models.TextField(blank=True, default="")
    explanation = models.TextField(blank=True, default="")
    correct_answer = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Réponse attendue pour fill_blank ou true_false ('true'/'false').",
    )
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["lesson_id", "order", "id"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.lesson.title} · #{self.order} {self.get_kind_display()}"


class Choice(models.Model):
    """Choix pour un exercice de type QCM."""

    exercise = models.ForeignKey(Exercise, related_name="choices", on_delete=models.CASCADE)
    text = models.CharField(max_length=255)
    is_correct = models.BooleanField(default=False)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["exercise_id", "order", "id"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.text
