from django.contrib import admin

from .models import ExerciseAttempt, LessonCompletion


@admin.register(LessonCompletion)
class LessonCompletionAdmin(admin.ModelAdmin):
    list_display = ("user", "lesson", "xp_earned", "correct_count", "total_count", "completed_at")
    list_filter = ("lesson__module__course",)


@admin.register(ExerciseAttempt)
class ExerciseAttemptAdmin(admin.ModelAdmin):
    list_display = ("user", "exercise", "is_correct", "created_at")
    list_filter = ("is_correct",)
