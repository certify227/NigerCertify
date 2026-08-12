from django.contrib import admin

from .models import Course, Exercise, Lesson, LessonProgress, Profile, Unit


class UnitInline(admin.TabularInline):
    model = Unit
    extra = 0


class LessonInline(admin.TabularInline):
    model = Lesson
    extra = 0


class ExerciseInline(admin.StackedInline):
    model = Exercise
    extra = 0


@admin.register(Course)
class CourseAdmin(admin.ModelAdmin):
    list_display = ("title", "slug", "order")
    prepopulated_fields = {"slug": ("title",)}
    inlines = [UnitInline]


@admin.register(Unit)
class UnitAdmin(admin.ModelAdmin):
    list_display = ("title", "course", "order")
    inlines = [LessonInline]


@admin.register(Lesson)
class LessonAdmin(admin.ModelAdmin):
    list_display = ("title", "unit", "order", "xp_reward")
    inlines = [ExerciseInline]


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "xp", "level", "streak", "hearts")


@admin.register(LessonProgress)
class LessonProgressAdmin(admin.ModelAdmin):
    list_display = ("user", "lesson", "completed", "best_score")
