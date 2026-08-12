"""Sérialiseurs de l'app courses."""
from rest_framework import serializers

from .models import Choice, Course, Exercise, Lesson, Module


class ChoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Choice
        fields = ("id", "text", "order")


class ExerciseSerializer(serializers.ModelSerializer):
    """Sérialiseur public : NE PAS exposer is_correct ni correct_answer."""

    choices = ChoiceSerializer(many=True, read_only=True)

    class Meta:
        model = Exercise
        fields = (
            "id",
            "kind",
            "prompt",
            "code_snippet",
            "order",
            "choices",
        )


class LessonSummarySerializer(serializers.ModelSerializer):
    exercise_count = serializers.IntegerField(read_only=True)
    is_completed = serializers.SerializerMethodField()

    class Meta:
        model = Lesson
        fields = (
            "id",
            "title",
            "description",
            "order",
            "xp_reward",
            "exercise_count",
            "is_completed",
        )

    def get_is_completed(self, obj: Lesson) -> bool:
        completed_ids = self.context.get("completed_lesson_ids") or set()
        return obj.id in completed_ids


class LessonDetailSerializer(LessonSummarySerializer):
    exercises = ExerciseSerializer(many=True, read_only=True)

    class Meta(LessonSummarySerializer.Meta):
        fields = LessonSummarySerializer.Meta.fields + ("exercises",)


class ModuleSerializer(serializers.ModelSerializer):
    lessons = LessonSummarySerializer(many=True, read_only=True)

    class Meta:
        model = Module
        fields = ("id", "title", "description", "order", "lessons")


class CourseListSerializer(serializers.ModelSerializer):
    module_count = serializers.IntegerField(read_only=True)
    lesson_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Course
        fields = (
            "id",
            "title",
            "slug",
            "description",
            "language",
            "icon",
            "color",
            "order",
            "module_count",
            "lesson_count",
        )


class CourseDetailSerializer(CourseListSerializer):
    modules = ModuleSerializer(many=True, read_only=True)

    class Meta(CourseListSerializer.Meta):
        fields = CourseListSerializer.Meta.fields + ("modules",)
