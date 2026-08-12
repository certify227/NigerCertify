from django.contrib import admin

from .models import AnswerOption, Lesson, Question, Track, UserProgress


class AnswerOptionInline(admin.TabularInline):
    model = AnswerOption
    extra = 0


@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    list_display = ["prompt", "lesson", "order"]
    list_filter = ["lesson__track", "lesson"]
    inlines = [AnswerOptionInline]


@admin.register(Lesson)
class LessonAdmin(admin.ModelAdmin):
    list_display = ["title", "track", "order", "xp_reward"]
    list_filter = ["track"]


@admin.register(Track)
class TrackAdmin(admin.ModelAdmin):
    list_display = ["title", "slug", "order"]
    prepopulated_fields = {"slug": ("title",)}


@admin.register(UserProgress)
class UserProgressAdmin(admin.ModelAdmin):
    list_display = ["username", "lesson", "score", "max_score", "xp", "completed"]
    list_filter = ["completed", "lesson__track"]
    search_fields = ["username"]
