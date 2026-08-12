from rest_framework import serializers

from courses.models import Choice, Exercise, Lesson, Track, Unit
from progress.models import UserLessonProgress


class ChoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Choice
        fields = ["id", "text", "order"]
        # is_correct masqué côté client jusqu'à la soumission


class ExerciseSerializer(serializers.ModelSerializer):
    choices = ChoiceSerializer(many=True, read_only=True)

    class Meta:
        model = Exercise
        fields = [
            "id",
            "question",
            "exercise_type",
            "hint",
            "order",
            "choices",
        ]


class LessonListSerializer(serializers.ModelSerializer):
    exercise_count = serializers.SerializerMethodField()
    completed = serializers.SerializerMethodField()

    class Meta:
        model = Lesson
        fields = ["id", "title", "description", "order", "xp_reward", "exercise_count", "completed"]

    def get_exercise_count(self, obj) -> int:
        return obj.exercises.count()

    def get_completed(self, obj) -> bool:
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return False
        progress = obj.user_progress.filter(user=request.user, completed=True).first()
        return progress is not None


class LessonDetailSerializer(serializers.ModelSerializer):
    exercises = ExerciseSerializer(many=True, read_only=True)

    class Meta:
        model = Lesson
        fields = ["id", "title", "description", "order", "xp_reward", "exercises"]


class UnitSerializer(serializers.ModelSerializer):
    lessons = LessonListSerializer(many=True, read_only=True)

    class Meta:
        model = Unit
        fields = ["id", "title", "description", "order", "lessons"]


class TrackListSerializer(serializers.ModelSerializer):
    unit_count = serializers.SerializerMethodField()
    progress_percent = serializers.SerializerMethodField()

    class Meta:
        model = Track
        fields = [
            "id",
            "title",
            "slug",
            "description",
            "icon",
            "color",
            "order",
            "unit_count",
            "progress_percent",
        ]

    def get_unit_count(self, obj) -> int:
        return obj.units.count()

    def get_progress_percent(self, obj) -> int:
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return 0
        total_lessons = Lesson.objects.filter(unit__track=obj).count()
        if total_lessons == 0:
            return 0
        done = UserLessonProgress.objects.filter(
            user=request.user,
            lesson__unit__track=obj,
            completed=True,
        ).count()
        return int(done / total_lessons * 100)


class TrackDetailSerializer(serializers.ModelSerializer):
    units = UnitSerializer(many=True, read_only=True)

    class Meta:
        model = Track
        fields = ["id", "title", "slug", "description", "icon", "color", "units"]


class SubmitAnswerSerializer(serializers.Serializer):
    answer = serializers.CharField(required=False, allow_blank=True)
    choice_id = serializers.IntegerField(required=False)

    def validate(self, data):
        if not data.get("answer") and not data.get("choice_id"):
            raise serializers.ValidationError("Fournissez answer ou choice_id.")
        return data
