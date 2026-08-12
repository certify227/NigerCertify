from django.contrib import admin

from .models import Challenge, Lesson, Module, Track


@admin.register(Track)
class TrackAdmin(admin.ModelAdmin):
    list_display = ("title", "level", "estimated_minutes", "order")
    prepopulated_fields = {"slug": ("title",)}


@admin.register(Module)
class ModuleAdmin(admin.ModelAdmin):
    list_display = ("title", "track", "xp_reward", "order")
    list_filter = ("track",)
    prepopulated_fields = {"slug": ("title",)}


@admin.register(Lesson)
class LessonAdmin(admin.ModelAdmin):
    list_display = ("title", "module", "lesson_type", "xp_reward", "order")
    list_filter = ("lesson_type", "module__track")
    prepopulated_fields = {"slug": ("title",)}


@admin.register(Challenge)
class ChallengeAdmin(admin.ModelAdmin):
    list_display = ("title", "track", "difficulty", "estimated_minutes", "is_daily_featured")
    list_filter = ("difficulty", "is_daily_featured")

# Register your models here.
