from django.db import models


class TimestampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Track(TimestampedModel):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    LEVEL_CHOICES = [
        (BEGINNER, "Beginner"),
        (INTERMEDIATE, "Intermediate"),
        (ADVANCED, "Advanced"),
    ]

    title = models.CharField(max_length=120)
    slug = models.SlugField(unique=True)
    summary = models.TextField()
    level = models.CharField(max_length=20, choices=LEVEL_CHOICES, default=BEGINNER)
    estimated_minutes = models.PositiveIntegerField(default=15)
    color_theme = models.CharField(max_length=20, default="#58CC02")
    icon = models.CharField(max_length=40, default="terminal")
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "title"]

    def __str__(self) -> str:
        return self.title


class Module(TimestampedModel):
    track = models.ForeignKey(Track, related_name="modules", on_delete=models.CASCADE)
    title = models.CharField(max_length=120)
    slug = models.SlugField()
    description = models.TextField()
    xp_reward = models.PositiveIntegerField(default=15)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "title"]
        constraints = [
            models.UniqueConstraint(fields=["track", "slug"], name="unique_module_slug_per_track")
        ]

    def __str__(self) -> str:
        return f"{self.track.title} / {self.title}"


class Lesson(TimestampedModel):
    THEORY = "theory"
    CODE_QUIZ = "code_quiz"
    DEBUG = "debug"
    PROJECT = "project"
    LESSON_TYPE_CHOICES = [
        (THEORY, "Theory"),
        (CODE_QUIZ, "Code Quiz"),
        (DEBUG, "Debug Challenge"),
        (PROJECT, "Project Sprint"),
    ]

    module = models.ForeignKey(Module, related_name="lessons", on_delete=models.CASCADE)
    title = models.CharField(max_length=140)
    slug = models.SlugField()
    lesson_type = models.CharField(max_length=20, choices=LESSON_TYPE_CHOICES, default=THEORY)
    theory = models.TextField()
    instructions = models.TextField()
    starter_code = models.TextField(blank=True)
    solution_hint = models.TextField(blank=True)
    xp_reward = models.PositiveIntegerField(default=10)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "title"]
        constraints = [
            models.UniqueConstraint(fields=["module", "slug"], name="unique_lesson_slug_per_module")
        ]

    def __str__(self) -> str:
        return f"{self.module.title} / {self.title}"


class Challenge(TimestampedModel):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    DIFFICULTY_CHOICES = [
        (EASY, "Easy"),
        (MEDIUM, "Medium"),
        (HARD, "Hard"),
    ]

    track = models.ForeignKey(
        Track,
        related_name="challenges",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    title = models.CharField(max_length=120)
    prompt = models.TextField()
    answer_format = models.CharField(max_length=60, default="text")
    difficulty = models.CharField(max_length=10, choices=DIFFICULTY_CHOICES, default=EASY)
    estimated_minutes = models.PositiveIntegerField(default=5)
    is_daily_featured = models.BooleanField(default=False)
    reference_solution = models.TextField()

    class Meta:
        ordering = ["-is_daily_featured", "estimated_minutes", "title"]

    def __str__(self) -> str:
        return self.title
