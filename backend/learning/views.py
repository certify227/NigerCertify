from django.db.models import Count, Prefetch
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import generics, status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Attempt, Challenge, LearnerProfile, Lesson, LessonProgress, Track
from .serializers import (
    AttemptResultSerializer,
    LessonDetailSerializer,
    ProgressSerializer,
    RegisterSerializer,
    SubmitAnswerSerializer,
    TrackSerializer,
)


@api_view(["GET"])
@permission_classes([AllowAny])
def health_check(request):
    return Response({"status": "ok", "service": "itlingo-backend"})


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]


class TrackViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = TrackSerializer
    permission_classes = [AllowAny]
    lookup_field = "slug"

    def get_queryset(self):
        return (
            Track.objects.prefetch_related(
                Prefetch("units__lessons", queryset=Lesson.objects.annotate(challenge_count=Count("challenges")))
            )
            .annotate(unit_count=Count("units"))
            .order_by("order", "title")
        )


class LessonDetailView(generics.RetrieveAPIView):
    queryset = Lesson.objects.prefetch_related("challenges").select_related("unit", "unit__track")
    serializer_class = LessonDetailSerializer
    permission_classes = [AllowAny]


class SubmitAnswerView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, pk):
        challenge = get_object_or_404(Challenge.objects.select_related("lesson"), pk=pk)
        serializer = SubmitAnswerSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        submitted_answer = serializer.validated_data["answer"]
        is_correct = submitted_answer == challenge.correct_answer
        user = request.user if request.user.is_authenticated else None
        attempt = Attempt.objects.create(
            user=user,
            challenge=challenge,
            submitted_answer=submitted_answer,
            is_correct=is_correct,
        )

        earned_xp = 1 if is_correct else 0
        lesson_completed = False
        if user and is_correct:
            earned_xp, lesson_completed = self._record_progress(user, challenge)

        attempt.earned_xp = earned_xp
        attempt.lesson_completed = lesson_completed
        response = AttemptResultSerializer(attempt).data
        return Response(response, status=status.HTTP_201_CREATED)

    def _record_progress(self, user, challenge):
        lesson = challenge.lesson
        progress, _ = LessonProgress.objects.get_or_create(user=user, lesson=lesson)
        correct_challenge_ids = set(
            Attempt.objects.filter(user=user, challenge__lesson=lesson, is_correct=True)
            .values_list("challenge_id", flat=True)
            .distinct()
        )
        lesson_completed = len(correct_challenge_ids) == lesson.challenges.count()
        newly_completed = lesson_completed and not progress.completed
        earned_xp = lesson.xp_reward if newly_completed else 1

        progress.earned_xp += earned_xp
        progress.completed = progress.completed or lesson_completed
        if newly_completed:
            progress.completed_at = timezone.now()
        progress.save(update_fields=["earned_xp", "completed", "completed_at"])

        profile, _ = LearnerProfile.objects.get_or_create(user=user)
        profile.record_practice(earned_xp)
        return earned_xp, progress.completed


class ProgressView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile, _ = LearnerProfile.objects.get_or_create(user=request.user)
        lessons = LessonProgress.objects.filter(user=request.user).select_related("lesson")
        serializer = ProgressSerializer({"profile": profile, "lessons": lessons})
        return Response(serializer.data)
