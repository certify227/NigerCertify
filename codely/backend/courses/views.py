from django.shortcuts import get_object_or_404
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from courses.models import Choice, Exercise, Lesson, Track
from courses.serializers import (
    LessonDetailSerializer,
    RunCodeSerializer,
    SubmitAnswerSerializer,
    TrackDetailSerializer,
    TrackListSerializer,
)
from courses.sandbox import SandboxError, check_code_output, run_python
from progress.models import UserExerciseAttempt, UserLessonProgress
from progress.services import add_xp, lose_heart, record_lesson_completion


class TrackListView(generics.ListAPIView):
    serializer_class = TrackListSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Track.objects.filter(is_published=True)


class TrackDetailView(generics.RetrieveAPIView):
    serializer_class = TrackDetailSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "slug"

    def get_queryset(self):
        return Track.objects.filter(is_published=True)


class LessonDetailView(generics.RetrieveAPIView):
    serializer_class = LessonDetailSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = Lesson.objects.all()


class RunCodeView(APIView):
    """Exécute du code Python sans le noter (mode essai)."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = RunCodeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            result = run_python(
                serializer.validated_data["code"],
                serializer.validated_data.get("stdin", ""),
            )
            return Response(result)
        except SandboxError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class SubmitAnswerView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, exercise_id):
        exercise = get_object_or_404(Exercise, pk=exercise_id)
        serializer = SubmitAnswerSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        if user.hearts <= 0:
            return Response(
                {"error": "Plus de cœurs. Rechargez pour continuer."},
                status=status.HTTP_403_FORBIDDEN,
            )

        is_correct = self._check_answer(exercise, serializer.validated_data)
        xp_gained = 0

        if is_correct:
            from django.conf import settings

            xp_gained = settings.XP_PER_CORRECT_ANSWER
            add_xp(user, xp_gained)
        else:
            hearts_left = lose_heart(user)
            UserExerciseAttempt.objects.create(
                user=user,
                exercise=exercise,
                is_correct=False,
                answer=str(serializer.validated_data),
            )
            return Response({
                "correct": False,
                "hearts_left": hearts_left,
                "explanation": exercise.explanation,
            })

        UserExerciseAttempt.objects.create(
            user=user,
            exercise=exercise,
            is_correct=True,
            answer=str(serializer.validated_data),
        )

        lesson = exercise.lesson
        total = lesson.exercises.count()
        correct_attempts = UserExerciseAttempt.objects.filter(
            user=user,
            exercise__lesson=lesson,
            is_correct=True,
        ).values("exercise").distinct().count()

        lesson_complete = correct_attempts >= total
        progress, _ = UserLessonProgress.objects.get_or_create(user=user, lesson=lesson)

        if lesson_complete and not progress.completed:
            from django.conf import settings
            from django.utils import timezone

            progress.completed = True
            progress.score = 100
            progress.completed_at = timezone.now()
            progress.save()
            add_xp(user, lesson.xp_reward)
            record_lesson_completion(user)
            xp_gained += lesson.xp_reward

        user.refresh_from_db()
        return Response({
            "correct": True,
            "xp_gained": xp_gained,
            "user_xp": user.xp,
            "user_level": user.level,
            "lesson_complete": lesson_complete,
            "explanation": exercise.explanation,
        })

    def _check_answer(self, exercise: Exercise, data: dict) -> bool:
        if exercise.exercise_type in ("multiple_choice", "true_false"):
            choice_id = data.get("choice_id")
            if not choice_id:
                return False
            choice = Choice.objects.filter(pk=choice_id, exercise=exercise).first()
            return choice is not None and choice.is_correct

        if exercise.exercise_type == "code_challenge":
            code = data.get("code") or data.get("answer") or ""
            try:
                result = check_code_output(code, exercise.correct_answer)
                return result["correct"]
            except SandboxError:
                return False

        answer = (data.get("answer") or "").strip().lower()
        correct = exercise.correct_answer.strip().lower()
        return answer == correct
