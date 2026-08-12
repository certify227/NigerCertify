from django.contrib import admin

from progress.models import DailyActivity, UserExerciseAttempt, UserLessonProgress, UserTrackProgress


@admin.register(UserLessonProgress)
class UserLessonProgressAdmin(admin.ModelAdmin):
    list_display = ["user", "lesson", "completed", "score", "completed_at"]
    list_filter = ["completed"]


@admin.register(UserExerciseAttempt)
class UserExerciseAttemptAdmin(admin.ModelAdmin):
    list_display = ["user", "exercise", "is_correct", "created_at"]
    list_filter = ["is_correct"]


admin.site.register(UserTrackProgress)
admin.site.register(DailyActivity)
