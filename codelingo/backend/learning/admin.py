from django.contrib import admin

from .models import Course, Exercise, Lesson, LessonProgress, Unit


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
    list_display = ("title", "slug", "order", "icon")
    prepopulated_fields = {"slug": ("title",)}
    inlines = [UnitInline]


@admin.register(Unit)
class UnitAdmin(admin.ModelAdmin):
    list_display = ("title", "course", "order")
    list_filter = ("course",)
    inlines = [LessonInline]


@admin.register(Lesson)
class LessonAdmin(admin.ModelAdmin):
    list_display = ("title", "unit", "order", "xp_reward")
    list_filter = ("unit__course",)
    inlines = [ExerciseInline]


@admin.register(Exercise)
class ExerciseAdmin(admin.ModelAdmin):
    list_display = ("question", "lesson", "exercise_type", "order")
    list_filter = ("exercise_type", "lesson__unit__course")


@admin.register(LessonProgress)
class LessonProgressAdmin(admin.ModelAdmin):
    list_display = ("user", "lesson", "completed", "best_score", "times_completed")
    list_filter = ("completed",)
