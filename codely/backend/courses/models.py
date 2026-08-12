from django.db import models


class Track(models.Model):
    """Parcours thématique (ex: Python, Réseaux, Cybersécurité)."""

    title = models.CharField(max_length=120)
    slug = models.SlugField(unique=True)
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=8, default="💻", help_text="Emoji ou icône")
    color = models.CharField(max_length=7, default="#58CC02")
    order = models.PositiveSmallIntegerField(default=0)
    is_published = models.BooleanField(default=True)

    class Meta:
        ordering = ["order", "title"]

    def __str__(self) -> str:
        return self.title


class Unit(models.Model):
    """Section d'un parcours (ex: Variables, Boucles)."""

    track = models.ForeignKey(Track, on_delete=models.CASCADE, related_name="units")
    title = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    order = models.PositiveSmallIntegerField(default=0)

    class Meta:
        ordering = ["order"]
        unique_together = [("track", "order")]

    def __str__(self) -> str:
        return f"{self.track.title} — {self.title}"


class Lesson(models.Model):
    """Leçon interactive avec exercices."""

    unit = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name="lessons")
    title = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    order = models.PositiveSmallIntegerField(default=0)
    xp_reward = models.PositiveSmallIntegerField(default=25)

    class Meta:
        ordering = ["order"]
        unique_together = [("unit", "order")]

    def __str__(self) -> str:
        return self.title


class ExerciseType(models.TextChoices):
    MULTIPLE_CHOICE = "multiple_choice", "Choix multiple"
    TRUE_FALSE = "true_false", "Vrai / Faux"
    FILL_BLANK = "fill_blank", "Texte à trous"
    CODE_ORDER = "code_order", "Ordre du code"
    CODE_CHALLENGE = "code_challenge", "Défi code Python"


class Exercise(models.Model):
    """Exercice d'une leçon."""

    lesson = models.ForeignKey(Lesson, on_delete=models.CASCADE, related_name="exercises")
    question = models.TextField()
    exercise_type = models.CharField(
        max_length=20,
        choices=ExerciseType.choices,
        default=ExerciseType.MULTIPLE_CHOICE,
    )
    hint = models.CharField(max_length=255, blank=True)
    explanation = models.TextField(blank=True, help_text="Explication après réponse")
    order = models.PositiveSmallIntegerField(default=0)
    # Pour fill_blank, code_order, code_challenge
    correct_answer = models.TextField(blank=True)
    starter_code = models.TextField(
        blank=True,
        help_text="Code de départ pour les exercices code_challenge",
    )

    class Meta:
        ordering = ["order"]

    def __str__(self) -> str:
        return f"{self.lesson.title} — Q{self.order + 1}"


class Choice(models.Model):
    """Option de réponse pour choix multiple / vrai-faux."""

    exercise = models.ForeignKey(Exercise, on_delete=models.CASCADE, related_name="choices")
    text = models.CharField(max_length=500)
    is_correct = models.BooleanField(default=False)
    order = models.PositiveSmallIntegerField(default=0)

    class Meta:
        ordering = ["order"]

    def __str__(self) -> str:
        return self.text[:50]
