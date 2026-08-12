from rest_framework import serializers

from .models import Challenge, Lesson, Module, Track


class LessonSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lesson
        fields = [
            "id",
            "title",
            "slug",
            "lesson_type",
            "theory",
            "instructions",
            "starter_code",
            "solution_hint",
            "xp_reward",
            "order",
        ]


class ModuleSerializer(serializers.ModelSerializer):
    lessons = LessonSerializer(many=True, read_only=True)

    class Meta:
        model = Module
        fields = [
            "id",
            "title",
            "slug",
            "description",
            "xp_reward",
            "order",
            "lessons",
        ]


class TrackListSerializer(serializers.ModelSerializer):
    module_count = serializers.IntegerField(read_only=True)
    lesson_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Track
        fields = [
            "id",
            "title",
            "slug",
            "summary",
            "level",
            "estimated_minutes",
            "color_theme",
            "icon",
            "order",
            "module_count",
            "lesson_count",
        ]


class TrackDetailSerializer(serializers.ModelSerializer):
    modules = ModuleSerializer(many=True, read_only=True)

    class Meta:
        model = Track
        fields = [
            "id",
            "title",
            "slug",
            "summary",
            "level",
            "estimated_minutes",
            "color_theme",
            "icon",
            "order",
            "modules",
        ]


class ChallengeSerializer(serializers.ModelSerializer):
    track = serializers.SlugRelatedField(slug_field="slug", read_only=True)

    class Meta:
        model = Challenge
        fields = [
            "id",
            "title",
            "prompt",
            "answer_format",
            "difficulty",
            "estimated_minutes",
            "is_daily_featured",
            "reference_solution",
            "track",
        ]
