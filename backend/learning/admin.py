from django.contrib import admin

from .models import Attempt, Challenge, LearnerProfile, Lesson, LessonProgress, Track, Unit


class UnitInline(admin.TabularInline):
    model = Unit
    extra = 0


class LessonInline(admin.TabularInline):
    model = Lesson
    extra = 0


class ChallengeInline(admin.TabularInline):
    model = Challenge
    extra = 0


@admin.register(Track)
class TrackAdmin(admin.ModelAdmin):
    list_display = ["title", "slug", "order"]
    prepopulated_fields = {"slug": ["title"]}
    inlines = [UnitInline]


@admin.register(Unit)
class UnitAdmin(admin.ModelAdmin):
    list_display = ["title", "track", "order"]
    list_filter = ["track"]
    inlines = [LessonInline]


@admin.register(Lesson)
class LessonAdmin(admin.ModelAdmin):
    list_display = ["title", "unit", "xp_reward", "order"]
    list_filter = ["unit__track", "unit"]
    inlines = [ChallengeInline]


@admin.register(Challenge)
class ChallengeAdmin(admin.ModelAdmin):
    list_display = ["prompt", "lesson", "type", "order"]
    list_filter = ["type", "lesson__unit__track"]


@admin.register(LearnerProfile)
class LearnerProfileAdmin(admin.ModelAdmin):
    list_display = ["user", "total_xp", "current_streak", "last_practice_at"]


@admin.register(LessonProgress)
class LessonProgressAdmin(admin.ModelAdmin):
    list_display = ["user", "lesson", "completed", "earned_xp", "completed_at"]
    list_filter = ["completed"]


@admin.register(Attempt)
class AttemptAdmin(admin.ModelAdmin):
    list_display = ["user", "challenge", "is_correct", "created_at"]
    list_filter = ["is_correct", "challenge__type"]
