from django.db import models


class Track(models.Model):
    beginner = "beginner"
    intermediate = "intermediate"
    advanced = "advanced"
    DIFFICULTY_CHOICES = [
        (beginner, "Debutant"),
        (intermediate, "Intermediaire"),
        (advanced, "Avance"),
    ]

    title = models.CharField(max_length=120)
    slug = models.SlugField(unique=True)
    description = models.TextField()
    icon = models.CharField(max_length=32, default="terminal")
    difficulty = models.CharField(
        max_length=20,
        choices=DIFFICULTY_CHOICES,
        default=beginner,
    )
    color_start = models.CharField(max_length=7, default="#1D4ED8")
    color_end = models.CharField(max_length=7, default="#7C3AED")
    sort_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["sort_order", "title"]

    def __str__(self):
        return self.title


class Lesson(models.Model):
    track = models.ForeignKey(
        Track,
        related_name="lessons",
        on_delete=models.CASCADE,
    )
    title = models.CharField(max_length=120)
    slug = models.SlugField(unique=True)
    summary = models.TextField()
    estimated_minutes = models.PositiveIntegerField(default=8)
    xp_reward = models.PositiveIntegerField(default=15)
    challenge_count = models.PositiveIntegerField(default=3)
    sort_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["sort_order", "title"]

    def __str__(self):
        return self.title


class Exercise(models.Model):
    multiple_choice = "multiple_choice"
    terminal = "terminal"
    code_order = "code_order"
    EXERCISE_TYPE_CHOICES = [
        (multiple_choice, "Choix multiple"),
        (terminal, "Terminal"),
        (code_order, "Ordre du code"),
    ]

    lesson = models.ForeignKey(
        Lesson,
        related_name="exercises",
        on_delete=models.CASCADE,
    )
    prompt = models.TextField()
    exercise_type = models.CharField(
        max_length=32,
        choices=EXERCISE_TYPE_CHOICES,
        default=multiple_choice,
    )
    options = models.JSONField(default=list, blank=True)
    correct_answer = models.CharField(max_length=255)
    explanation = models.TextField(blank=True)
    sort_order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["sort_order", "id"]

    def __str__(self):
        return f"{self.lesson.title} #{self.sort_order}"


class LearnerProfile(models.Model):
    display_name = models.CharField(max_length=120, default="Ada")
    target_role = models.CharField(max_length=120, default="Developpeuse full-stack")
    daily_goal_minutes = models.PositiveIntegerField(default=20)
    streak_days = models.PositiveIntegerField(default=5)
    total_xp = models.PositiveIntegerField(default=180)
    hearts = models.PositiveIntegerField(default=5)

    def __str__(self):
        return self.display_name


class LessonProgress(models.Model):
    locked = "locked"
    available = "available"
    completed = "completed"
    STATUS_CHOICES = [
        (locked, "Verrouille"),
        (available, "Disponible"),
        (completed, "Termine"),
    ]

    profile = models.ForeignKey(
        LearnerProfile,
        related_name="lesson_progress",
        on_delete=models.CASCADE,
    )
    lesson = models.ForeignKey(
        Lesson,
        related_name="progress_records",
        on_delete=models.CASCADE,
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=locked,
    )
    score = models.PositiveIntegerField(default=0)
    last_practiced_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ("profile", "lesson")
        ordering = ["lesson__sort_order", "lesson__title"]

    def __str__(self):
        return f"{self.profile.display_name} - {self.lesson.title}"
