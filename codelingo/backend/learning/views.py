from django.db.models import Prefetch
from django.shortcuts import get_object_or_404
from rest_framework import generics
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Course, Exercise, Lesson, LessonProgress
from .serializers import (
    CourseDetailSerializer,
    CourseSerializer,
    LessonCompleteSerializer,
    LessonDetailSerializer,
    LessonProgressSerializer,
)


class CourseListView(generics.ListAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseSerializer


class CourseDetailView(generics.RetrieveAPIView):
    serializer_class = CourseDetailSerializer
    lookup_field = "slug"

    def get_queryset(self):
        return Course.objects.prefetch_related("units__lessons")

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["progress_map"] = _progress_map_for_course(
            self.request.user, self.kwargs.get("slug")
        )
        return context


class LessonDetailView(generics.RetrieveAPIView):
    serializer_class = LessonDetailSerializer

    def get_queryset(self):
        return Lesson.objects.prefetch_related("exercises")

    def get_serializer_context(self):
        context = super().get_serializer_context()
        progress = LessonProgress.objects.filter(
            user=self.request.user, lesson_id=self.kwargs.get("pk")
        ).first()
        context["progress_map"] = {int(self.kwargs["pk"]): progress} if progress else {}
        return context


class LessonCompleteView(APIView):
    """Grade a lesson attempt, persist progress and award XP / streak."""

    def post(self, request, pk):
        lesson = get_object_or_404(Lesson.objects.prefetch_related("exercises"), pk=pk)
        serializer = LessonCompleteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        answers = {
            a["exercise_id"]: a["answer"] for a in serializer.validated_data["answers"]
        }
        exercises = list(lesson.exercises.all())
        total = len(exercises)
        correct = sum(
            1 for ex in exercises if ex.is_correct(answers.get(ex.id))
        )
        score = round((correct / total) * 100) if total else 0
        passed = score >= 60

        progress, _ = LessonProgress.objects.get_or_create(
            user=request.user, lesson=lesson
        )
        newly_completed = passed and not progress.completed
        progress.best_score = max(progress.best_score, score)
        if passed:
            progress.completed = True
            progress.times_completed += 1
        progress.save()

        xp_gained = lesson.xp_reward if passed else 0
        if xp_gained:
            request.user.register_activity(xp_gained)

        return Response(
            {
                "score": score,
                "correct": correct,
                "total": total,
                "passed": passed,
                "xp_gained": xp_gained,
                "newly_completed": newly_completed,
                "user": {
                    "xp": request.user.xp,
                    "gems": request.user.gems,
                    "streak_count": request.user.streak_count,
                    "hearts": request.user.hearts,
                },
            }
        )


class MyProgressView(generics.ListAPIView):
    serializer_class = LessonProgressSerializer

    def get_queryset(self):
        return LessonProgress.objects.filter(user=self.request.user).select_related(
            "lesson"
        )


def _progress_map_for_course(user, slug):
    if not user or not user.is_authenticated:
        return {}
    qs = LessonProgress.objects.filter(
        user=user, lesson__unit__course__slug=slug
    )
    return {p.lesson_id: p for p in qs}
