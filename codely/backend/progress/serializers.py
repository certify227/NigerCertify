from rest_framework import serializers

from progress.models import UserLessonProgress


class UserLessonProgressSerializer(serializers.ModelSerializer):
    lesson_title = serializers.CharField(source="lesson.title", read_only=True)

    class Meta:
        model = UserLessonProgress
        fields = ["id", "lesson", "lesson_title", "completed", "score", "completed_at"]


class DashboardSerializer(serializers.Serializer):
    xp = serializers.IntegerField()
    level = serializers.IntegerField()
    streak = serializers.IntegerField()
    hearts = serializers.IntegerField()
    lessons_completed_today = serializers.IntegerField()
    xp_today = serializers.IntegerField()
    tracks_in_progress = serializers.IntegerField()
