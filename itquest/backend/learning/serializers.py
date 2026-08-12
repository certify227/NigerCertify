from rest_framework import serializers

from .models import AnswerOption, Lesson, Question, Track, UserProgress


class LessonSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Lesson
        fields = ["id", "title", "summary", "xp_reward", "order"]


class TrackSerializer(serializers.ModelSerializer):
    lessons = LessonSummarySerializer(many=True, read_only=True)

    class Meta:
        model = Track
        fields = ["id", "title", "slug", "description", "icon", "order", "lessons"]


class AnswerOptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnswerOption
        fields = ["id", "text", "order"]


class QuestionSerializer(serializers.ModelSerializer):
    options = AnswerOptionSerializer(many=True, read_only=True)

    class Meta:
        model = Question
        fields = ["id", "prompt", "explanation", "order", "options"]


class LessonDetailSerializer(serializers.ModelSerializer):
    track = serializers.CharField(source="track.title", read_only=True)
    questions = QuestionSerializer(many=True, read_only=True)

    class Meta:
        model = Lesson
        fields = ["id", "track", "title", "summary", "xp_reward", "order", "questions"]


class SubmittedAnswerSerializer(serializers.Serializer):
    question_id = serializers.IntegerField()
    option_id = serializers.IntegerField()


class LessonSubmissionSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=80, trim_whitespace=True)
    answers = SubmittedAnswerSerializer(many=True)

    def validate_username(self, value: str) -> str:
        if not value:
            raise serializers.ValidationError("Le nom d'utilisateur est obligatoire.")
        return value


class UserProgressSerializer(serializers.ModelSerializer):
    lesson_title = serializers.CharField(source="lesson.title", read_only=True)
    track_title = serializers.CharField(source="lesson.track.title", read_only=True)

    class Meta:
        model = UserProgress
        fields = [
            "lesson",
            "lesson_title",
            "track_title",
            "score",
            "max_score",
            "xp",
            "completed",
            "updated_at",
        ]
