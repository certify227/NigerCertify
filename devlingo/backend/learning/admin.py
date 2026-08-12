from django.contrib import admin

from .models import Exercise, LearnerProfile, Lesson, LessonProgress, Track


class ExerciseInline(admin.TabularInline):
    model = Exercise
    extra = 1


@admin.register(Track)
class TrackAdmin(admin.ModelAdmin):
    list_display = ("title", "difficulty", "sort_order")
    prepopulated_fields = {"slug": ("title",)}


@admin.register(Lesson)
class LessonAdmin(admin.ModelAdmin):
    list_display = ("title", "track", "xp_reward", "sort_order")
    list_filter = ("track",)
    prepopulated_fields = {"slug": ("title",)}
    inlines = [ExerciseInline]


@admin.register(LearnerProfile)
class LearnerProfileAdmin(admin.ModelAdmin):
    list_display = ("display_name", "target_role", "streak_days", "total_xp")


@admin.register(LessonProgress)
class LessonProgressAdmin(admin.ModelAdmin):
    list_display = ("profile", "lesson", "status", "score", "last_practiced_at")
    list_filter = ("status", "profile")
