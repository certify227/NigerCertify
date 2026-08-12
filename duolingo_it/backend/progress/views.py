"""Vues API pour la soumission des exercices et la complétion des leçons."""
from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.serializers import UserSerializer
from courses.models import Exercise, Lesson

from .models import ExerciseAttempt, LessonCompletion


class AnswerSerializer(serializers.Serializer):
    exercise_id = serializers.IntegerField()
    answer = serializers.CharField(allow_blank=True, max_length=255)


class LessonSubmissionSerializer(serializers.Serializer):
    answers = AnswerSerializer(many=True)


def _grade_answer(exercise: Exercise, raw_answer: str) -> bool:
    """Détermine si `raw_answer` est correct pour l'exercice donné."""
    answer = (raw_answer or "").strip()
    if exercise.kind == Exercise.Kind.MCQ:
        try:
            choice_id = int(answer)
        except (TypeError, ValueError):
            return False
        return exercise.choices.filter(id=choice_id, is_correct=True).exists()
    if exercise.kind == Exercise.Kind.TRUE_FALSE:
        return answer.lower() == (exercise.correct_answer or "").strip().lower()
    if exercise.kind in (Exercise.Kind.FILL_BLANK, Exercise.Kind.CODE_OUTPUT):
        expected = (exercise.correct_answer or "").strip()
        # tolérance : casse ignorée, espaces internes conservés
        return answer.lower() == expected.lower()
    return False


class SubmitLessonView(APIView):
    """POST /lessons/<id>/submit/ — corrige les réponses et attribue de l'XP."""

    def post(self, request, pk: int):
        lesson = get_object_or_404(Lesson, pk=pk)
        serializer = LessonSubmissionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        answers = serializer.validated_data["answers"]

        exercises = {ex.id: ex for ex in lesson.exercises.prefetch_related("choices")}
        results = []
        correct_count = 0
        with transaction.atomic():
            for entry in answers:
                exercise = exercises.get(entry["exercise_id"])
                if exercise is None:
                    continue
                is_correct = _grade_answer(exercise, entry["answer"])
                if is_correct:
                    correct_count += 1
                ExerciseAttempt.objects.create(
                    user=request.user,
                    exercise=exercise,
                    submitted_answer=entry["answer"],
                    is_correct=is_correct,
                )
                results.append(
                    {
                        "exercise_id": exercise.id,
                        "is_correct": is_correct,
                        "explanation": exercise.explanation,
                    }
                )

            total = len(exercises)
            passed = total > 0 and correct_count >= max(1, total - 1)
            xp_earned = lesson.xp_reward if passed else 0

            user = request.user
            hearts_lost = 0
            if not passed and total > 0:
                hearts_lost = min(user.hearts, total - correct_count)
                user.hearts = max(0, user.hearts - hearts_lost)
            if passed:
                user.xp += xp_earned
                user.register_activity()
                LessonCompletion.objects.update_or_create(
                    user=user,
                    lesson=lesson,
                    defaults={
                        "xp_earned": xp_earned,
                        "correct_count": correct_count,
                        "total_count": total,
                    },
                )
            user.save()

        return Response(
            {
                "passed": passed,
                "correct_count": correct_count,
                "total_count": total,
                "xp_earned": xp_earned,
                "hearts_lost": hearts_lost,
                "results": results,
                "user": UserSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )
