from django.db import models


class Track(models.Model):
    title = models.CharField(max_length=120)
    slug = models.SlugField(unique=True)
    description = models.TextField()
    icon = models.CharField(max_length=24, default="code")
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "title"]

    def __str__(self) -> str:
        return self.title


class Lesson(models.Model):
    track = models.ForeignKey(Track, related_name="lessons", on_delete=models.CASCADE)
    title = models.CharField(max_length=120)
    summary = models.TextField()
    xp_reward = models.PositiveIntegerField(default=20)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["track__order", "order", "title"]
        unique_together = ["track", "order"]

    def __str__(self) -> str:
        return f"{self.track.title} - {self.title}"


class Question(models.Model):
    lesson = models.ForeignKey(Lesson, related_name="questions", on_delete=models.CASCADE)
    prompt = models.TextField()
    explanation = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self) -> str:
        return self.prompt[:80]


class AnswerOption(models.Model):
    question = models.ForeignKey(Question, related_name="options", on_delete=models.CASCADE)
    text = models.CharField(max_length=255)
    is_correct = models.BooleanField(default=False)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "id"]

    def __str__(self) -> str:
        return self.text


class UserProgress(models.Model):
    username = models.CharField(max_length=80, db_index=True)
    lesson = models.ForeignKey(Lesson, related_name="progress_entries", on_delete=models.CASCADE)
    score = models.PositiveIntegerField(default=0)
    max_score = models.PositiveIntegerField(default=0)
    xp = models.PositiveIntegerField(default=0)
    completed = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["username", "lesson__track__order", "lesson__order"]
        unique_together = ["username", "lesson"]

    def __str__(self) -> str:
        return f"{self.username}: {self.lesson.title} ({self.score}/{self.max_score})"
