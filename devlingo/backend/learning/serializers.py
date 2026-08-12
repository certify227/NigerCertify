from rest_framework import serializers

from .models import Exercise, LearnerProfile, Lesson, LessonProgress, Track


class ExerciseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Exercise
        fields = [
            "id",
            "prompt",
            "exercise_type",
            "options",
            "correct_answer",
            "explanation",
            "sort_order",
        ]


class LessonPreviewSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()

    class Meta:
        model = Lesson
        fields = [
            "id",
            "title",
            "slug",
            "summary",
            "estimated_minutes",
            "xp_reward",
            "challenge_count",
            "status",
        ]

    def get_status(self, lesson):
        progress_map = self.context.get("progress_map", {})
        progress = progress_map.get(lesson.id)
        return progress.status if progress else LessonProgress.locked


class TrackSerializer(serializers.ModelSerializer):
    lessons = serializers.SerializerMethodField()
    completed_lessons = serializers.SerializerMethodField()
    total_lessons = serializers.SerializerMethodField()
    progress_percent = serializers.SerializerMethodField()

    class Meta:
        model = Track
        fields = [
            "id",
            "title",
            "slug",
            "description",
            "icon",
            "difficulty",
            "color_start",
            "color_end",
            "completed_lessons",
            "total_lessons",
            "progress_percent",
            "lessons",
        ]

    def get_lessons(self, track):
        progress_map = self.context.get("progress_map", {})
        serializer = LessonPreviewSerializer(
            track.lessons.all(),
            many=True,
            context={"progress_map": progress_map},
        )
        return serializer.data

    def get_completed_lessons(self, track):
        progress_map = self.context.get("progress_map", {})
        return sum(
            1
            for lesson in track.lessons.all()
            if progress_map.get(lesson.id)
            and progress_map[lesson.id].status == LessonProgress.completed
        )

    def get_total_lessons(self, track):
        return track.lessons.count()

    def get_progress_percent(self, track):
        total_lessons = track.lessons.count()
        if total_lessons == 0:
            return 0
        completed_lessons = self.get_completed_lessons(track)
        return int((completed_lessons / total_lessons) * 100)


class LearnerProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = LearnerProfile
        fields = [
            "id",
            "display_name",
            "target_role",
            "daily_goal_minutes",
            "streak_days",
            "total_xp",
            "hearts",
        ]


class LessonDetailSerializer(serializers.ModelSerializer):
    exercises = ExerciseSerializer(many=True)
    track_title = serializers.CharField(source="track.title")

    class Meta:
        model = Lesson
        fields = [
            "id",
            "title",
            "slug",
            "summary",
            "estimated_minutes",
            "xp_reward",
            "challenge_count",
            "track_title",
            "exercises",
        ]
