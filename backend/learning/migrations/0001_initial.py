from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Track",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("slug", models.SlugField(unique=True)),
                ("title", models.CharField(max_length=120)),
                ("description", models.TextField()),
                ("icon", models.CharField(default="terminal", max_length=40)),
                ("color", models.CharField(default="#58cc02", max_length=20)),
                ("order", models.PositiveIntegerField(default=0)),
            ],
            options={"ordering": ["order", "title"]},
        ),
        migrations.CreateModel(
            name="LearnerProfile",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("total_xp", models.PositiveIntegerField(default=0)),
                ("current_streak", models.PositiveIntegerField(default=0)),
                ("last_practice_at", models.DateTimeField(blank=True, null=True)),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="learner_profile",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Unit",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=120)),
                ("description", models.TextField(blank=True)),
                ("order", models.PositiveIntegerField(default=0)),
                (
                    "track",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="units",
                        to="learning.track",
                    ),
                ),
            ],
            options={
                "ordering": ["track__order", "order", "title"],
                "unique_together": {("track", "order")},
            },
        ),
        migrations.CreateModel(
            name="Lesson",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=120)),
                ("summary", models.TextField()),
                ("xp_reward", models.PositiveIntegerField(default=10)),
                ("order", models.PositiveIntegerField(default=0)),
                (
                    "unit",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="lessons",
                        to="learning.unit",
                    ),
                ),
            ],
            options={
                "ordering": ["unit__track__order", "unit__order", "order", "title"],
                "unique_together": {("unit", "order")},
            },
        ),
        migrations.CreateModel(
            name="Challenge",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "type",
                    models.CharField(
                        choices=[
                            ("multiple_choice", "Choix multiple"),
                            ("flashcard", "Carte mémoire"),
                            ("code_order", "Réordonner le code"),
                        ],
                        max_length=32,
                    ),
                ),
                ("prompt", models.TextField()),
                ("choices", models.JSONField(blank=True, default=list)),
                ("correct_answer", models.JSONField()),
                ("explanation", models.TextField()),
                ("order", models.PositiveIntegerField(default=0)),
                (
                    "lesson",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="challenges",
                        to="learning.lesson",
                    ),
                ),
            ],
            options={
                "ordering": ["lesson__unit__track__order", "lesson__unit__order", "lesson__order", "order"],
                "unique_together": {("lesson", "order")},
            },
        ),
        migrations.CreateModel(
            name="LessonProgress",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("completed", models.BooleanField(default=False)),
                ("earned_xp", models.PositiveIntegerField(default=0)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "lesson",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="progress",
                        to="learning.lesson",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="lesson_progress",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"unique_together": {("user", "lesson")}},
        ),
        migrations.CreateModel(
            name="Attempt",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("submitted_answer", models.JSONField()),
                ("is_correct", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "challenge",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="attempts",
                        to="learning.challenge",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="attempts",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
