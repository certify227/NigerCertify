from django.contrib import admin

from courses.models import Choice, Exercise, Lesson, Track, Unit


class ChoiceInline(admin.TabularInline):
    model = Choice
    extra = 2


class ExerciseInline(admin.StackedInline):
    model = Exercise
    extra = 1
    show_change_link = True


class LessonInline(admin.TabularInline):
    model = Lesson
    extra = 1
    show_change_link = True


class UnitInline(admin.TabularInline):
    model = Unit
    extra = 1
    show_change_link = True


@admin.register(Track)
class TrackAdmin(admin.ModelAdmin):
    list_display = ["title", "slug", "order", "is_published"]
    prepopulated_fields = {"slug": ("title",)}
    inlines = [UnitInline]


@admin.register(Unit)
class UnitAdmin(admin.ModelAdmin):
    list_display = ["title", "track", "order"]
    list_filter = ["track"]
    inlines = [LessonInline]


@admin.register(Lesson)
class LessonAdmin(admin.ModelAdmin):
    list_display = ["title", "unit", "order", "xp_reward"]
    list_filter = ["unit__track"]
    inlines = [ExerciseInline]


@admin.register(Exercise)
class ExerciseAdmin(admin.ModelAdmin):
    list_display = ["question", "lesson", "exercise_type", "order"]
    list_filter = ["exercise_type", "lesson__unit__track"]
    inlines = [ChoiceInline]
