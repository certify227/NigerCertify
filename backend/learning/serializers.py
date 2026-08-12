from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import Attempt, Challenge, LearnerProfile, Lesson, LessonProgress, Track, Unit


class ChallengeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Challenge
        fields = ["id", "type", "prompt", "choices", "explanation", "order"]


class LessonListSerializer(serializers.ModelSerializer):
    challenge_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Lesson
        fields = ["id", "title", "summary", "xp_reward", "order", "challenge_count"]


class LessonDetailSerializer(serializers.ModelSerializer):
    challenges = ChallengeSerializer(many=True, read_only=True)

    class Meta:
        model = Lesson
        fields = ["id", "title", "summary", "xp_reward", "order", "challenges"]


class UnitSerializer(serializers.ModelSerializer):
    lessons = LessonListSerializer(many=True, read_only=True)

    class Meta:
        model = Unit
        fields = ["id", "title", "description", "order", "lessons"]


class TrackSerializer(serializers.ModelSerializer):
    units = UnitSerializer(many=True, read_only=True)

    class Meta:
        model = Track
        fields = ["id", "slug", "title", "description", "icon", "color", "order", "units"]


class SubmitAnswerSerializer(serializers.Serializer):
    answer = serializers.JSONField()


class AttemptResultSerializer(serializers.ModelSerializer):
    explanation = serializers.CharField(source="challenge.explanation")
    correct_answer = serializers.JSONField(source="challenge.correct_answer")
    earned_xp = serializers.IntegerField()
    lesson_completed = serializers.BooleanField()

    class Meta:
        model = Attempt
        fields = ["id", "is_correct", "explanation", "correct_answer", "earned_xp", "lesson_completed"]


class LearnerProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username")

    class Meta:
        model = LearnerProfile
        fields = ["username", "total_xp", "current_streak", "last_practice_at"]


class LessonProgressSerializer(serializers.ModelSerializer):
    lesson_title = serializers.CharField(source="lesson.title")

    class Meta:
        model = LessonProgress
        fields = ["lesson", "lesson_title", "completed", "earned_xp", "completed_at"]


class ProgressSerializer(serializers.Serializer):
    profile = LearnerProfileSerializer()
    lessons = LessonProgressSerializer(many=True)


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = get_user_model()
        fields = ["id", "username", "email", "password"]

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = get_user_model().objects.create_user(password=password, **validated_data)
        LearnerProfile.objects.create(user=user)
        return user
