from rest_framework import serializers

from .models import Course, Exercise, Lesson, LessonProgress, Unit


class ExerciseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Exercise
        # `correct_answer` and `explanation` are intentionally exposed so the
        # client can give instant feedback; for a competitive product these
        # would be validated server-side only.
        fields = (
            "id",
            "exercise_type",
            "question",
            "choices",
            "correct_answer",
            "explanation",
            "order",
        )


class LessonSerializer(serializers.ModelSerializer):
    exercise_count = serializers.IntegerField(source="exercises.count", read_only=True)
    completed = serializers.SerializerMethodField()
    best_score = serializers.SerializerMethodField()

    class Meta:
        model = Lesson
        fields = (
            "id",
            "title",
            "order",
            "xp_reward",
            "exercise_count",
            "completed",
            "best_score",
        )

    def _progress(self, obj):
        cache = self.context.get("progress_map")
        if cache is not None:
            return cache.get(obj.id)
        return None

    def get_completed(self, obj):
        progress = self._progress(obj)
        return bool(progress and progress.completed)

    def get_best_score(self, obj):
        progress = self._progress(obj)
        return progress.best_score if progress else 0


class LessonDetailSerializer(LessonSerializer):
    exercises = ExerciseSerializer(many=True, read_only=True)

    class Meta(LessonSerializer.Meta):
        fields = LessonSerializer.Meta.fields + ("exercises",)


class UnitSerializer(serializers.ModelSerializer):
    lessons = LessonSerializer(many=True, read_only=True)

    class Meta:
        model = Unit
        fields = ("id", "title", "description", "order", "lessons")


class CourseSerializer(serializers.ModelSerializer):
    unit_count = serializers.IntegerField(source="units.count", read_only=True)

    class Meta:
        model = Course
        fields = (
            "id",
            "title",
            "slug",
            "subtitle",
            "description",
            "icon",
            "color",
            "order",
            "unit_count",
        )


class CourseDetailSerializer(CourseSerializer):
    units = UnitSerializer(many=True, read_only=True)

    class Meta(CourseSerializer.Meta):
        fields = CourseSerializer.Meta.fields + ("units",)


class AnswerSerializer(serializers.Serializer):
    exercise_id = serializers.IntegerField()
    answer = serializers.CharField(allow_blank=True)


class LessonCompleteSerializer(serializers.Serializer):
    answers = AnswerSerializer(many=True)


class LessonProgressSerializer(serializers.ModelSerializer):
    lesson_title = serializers.CharField(source="lesson.title", read_only=True)

    class Meta:
        model = LessonProgress
        fields = (
            "lesson",
            "lesson_title",
            "completed",
            "best_score",
            "times_completed",
            "updated_at",
        )
