from django.contrib import admin

from courses.models import Choice, Exercise, Lesson, Track, Unit


class ChoiceInline(admin.TabularInline):
    model = Choice
    extra = 2
    fields = ["text", "is_correct", "order"]


class ExerciseInline(admin.StackedInline):
    model = Exercise
    extra = 1
    show_change_link = True
    fields = [
        "question",
        "exercise_type",
        "hint",
        "starter_code",
        "correct_answer",
        "explanation",
        "order",
    ]


class LessonInline(admin.TabularInline):
    model = Lesson
    extra = 1
    show_change_link = True
    fields = ["title", "order", "xp_reward"]


class UnitInline(admin.TabularInline):
    model = Unit
    extra = 1
    show_change_link = True
    fields = ["title", "order"]


@admin.action(description="Publier les parcours sélectionnés")
def publish_tracks(modeladmin, request, queryset):
    queryset.update(is_published=True)


@admin.action(description="Dépublier les parcours sélectionnés")
def unpublish_tracks(modeladmin, request, queryset):
    queryset.update(is_published=False)


@admin.register(Track)
class TrackAdmin(admin.ModelAdmin):
    list_display = ["title", "slug", "order", "is_published", "unit_count", "lesson_count"]
    list_filter = ["is_published"]
    search_fields = ["title", "slug", "description"]
    prepopulated_fields = {"slug": ("title",)}
    inlines = [UnitInline]
    actions = [publish_tracks, unpublish_tracks]

    @admin.display(description="Unités")
    def unit_count(self, obj):
        return obj.units.count()

    @admin.display(description="Leçons")
    def lesson_count(self, obj):
        return Lesson.objects.filter(unit__track=obj).count()


@admin.register(Unit)
class UnitAdmin(admin.ModelAdmin):
    list_display = ["title", "track", "order", "lesson_count"]
    list_filter = ["track"]
    search_fields = ["title"]
    inlines = [LessonInline]

    @admin.display(description="Leçons")
    def lesson_count(self, obj):
        return obj.lessons.count()


@admin.register(Lesson)
class LessonAdmin(admin.ModelAdmin):
    list_display = ["title", "unit", "track_name", "order", "xp_reward", "exercise_count"]
    list_filter = ["unit__track"]
    search_fields = ["title", "description"]
    inlines = [ExerciseInline]

    @admin.display(description="Parcours")
    def track_name(self, obj):
        return obj.unit.track.title

    @admin.display(description="Exercices")
    def exercise_count(self, obj):
        return obj.exercises.count()


@admin.register(Exercise)
class ExerciseAdmin(admin.ModelAdmin):
    list_display = ["short_question", "lesson", "exercise_type", "order"]
    list_filter = ["exercise_type", "lesson__unit__track"]
    search_fields = ["question", "correct_answer"]
    inlines = [ChoiceInline]
    fieldsets = (
        (None, {"fields": ("lesson", "question", "exercise_type", "order")}),
        ("Contenu", {"fields": ("hint", "starter_code", "correct_answer", "explanation")}),
    )

    @admin.display(description="Question")
    def short_question(self, obj):
        return obj.question[:60] + ("…" if len(obj.question) > 60 else "")
