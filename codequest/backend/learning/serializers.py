"""DRF serializers for the CodeQuest API."""

from __future__ import annotations

from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from .models import Course, Exercise, Lesson, Profile, Unit


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, validators=[validate_password]
    )

    class Meta:
        model = User
        fields = ["username", "email", "password"]

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data.get("email", ""),
            password=validated_data["password"],
        )
        return user


class ProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    level = serializers.IntegerField(read_only=True)

    class Meta:
        model = Profile
        fields = ["username", "xp", "streak", "hearts", "level", "last_active"]


class ExerciseSerializer(serializers.ModelSerializer):
    """Serializer used when *sending* an exercise to the client.

    The correct ``answer`` is intentionally omitted so it can't be scraped;
    grading happens server-side.
    """

    class Meta:
        model = Exercise
        fields = ["id", "kind", "prompt", "choices", "order"]


class LessonSerializer(serializers.ModelSerializer):
    exercises = ExerciseSerializer(many=True, read_only=True)
    completed = serializers.SerializerMethodField()

    class Meta:
        model = Lesson
        fields = ["id", "title", "order", "xp_reward", "exercises", "completed"]

    def get_completed(self, obj) -> bool:
        user = self.context.get("request").user if self.context.get("request") else None
        if not user or not user.is_authenticated:
            return False
        return any(
            p.completed for p in obj.progress.all() if p.user_id == user.id
        )


class LessonSummarySerializer(serializers.ModelSerializer):
    completed = serializers.SerializerMethodField()
    exercise_count = serializers.IntegerField(source="exercises.count", read_only=True)

    class Meta:
        model = Lesson
        fields = ["id", "title", "order", "xp_reward", "exercise_count", "completed"]

    def get_completed(self, obj) -> bool:
        user = self.context.get("request").user if self.context.get("request") else None
        if not user or not user.is_authenticated:
            return False
        return any(
            p.completed for p in obj.progress.all() if p.user_id == user.id
        )


class UnitSerializer(serializers.ModelSerializer):
    lessons = LessonSummarySerializer(many=True, read_only=True)

    class Meta:
        model = Unit
        fields = ["id", "title", "description", "order", "lessons"]


class CourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = ["id", "title", "slug", "description", "icon", "color", "order"]


class CourseDetailSerializer(serializers.ModelSerializer):
    units = UnitSerializer(many=True, read_only=True)

    class Meta:
        model = Course
        fields = [
            "id",
            "title",
            "slug",
            "description",
            "icon",
            "color",
            "order",
            "units",
        ]


class SubmissionSerializer(serializers.Serializer):
    """Payload sent by the client to grade a completed lesson."""

    answers = serializers.DictField(
        child=serializers.CharField(allow_blank=True),
        help_text="Mapping of exercise id (as string) to the submitted answer.",
    )


class LeaderboardEntrySerializer(serializers.Serializer):
    username = serializers.CharField()
    xp = serializers.IntegerField()
    level = serializers.IntegerField()
    streak = serializers.IntegerField()
