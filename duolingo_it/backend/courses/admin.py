from django.contrib import admin

from .models import Choice, Course, Exercise, Lesson, Module


class ChoiceInline(admin.TabularInline):
    model = Choice
    extra = 4


@admin.register(Exercise)
class ExerciseAdmin(admin.ModelAdmin):
    list_display = ("lesson", "order", "kind", "prompt")
    list_filter = ("kind", "lesson__module__course")
    inlines = [ChoiceInline]


class LessonInline(admin.TabularInline):
    model = Lesson
    extra = 1


@admin.register(Module)
class ModuleAdmin(admin.ModelAdmin):
    list_display = ("course", "order", "title")
    list_filter = ("course",)
    inlines = [LessonInline]


class ModuleInline(admin.TabularInline):
    model = Module
    extra = 1


@admin.register(Course)
class CourseAdmin(admin.ModelAdmin):
    list_display = ("title", "language", "order")
    prepopulated_fields = {"slug": ("title",)}
    inlines = [ModuleInline]


@admin.register(Lesson)
class LessonAdmin(admin.ModelAdmin):
    list_display = ("module", "order", "title", "xp_reward")
    list_filter = ("module__course",)
