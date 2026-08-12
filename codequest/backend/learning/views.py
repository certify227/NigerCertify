"""API views for the CodeQuest platform."""

from __future__ import annotations

from django.contrib.auth.models import User
from django.db.models import Prefetch
from rest_framework import generics, status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Course, Exercise, Lesson, LessonProgress, Profile
from .serializers import (
    CourseDetailSerializer,
    CourseSerializer,
    LeaderboardEntrySerializer,
    LessonSerializer,
    ProfileSerializer,
    RegisterSerializer,
    SubmissionSerializer,
)


def _profile_for(user: User) -> Profile:
    profile, _ = Profile.objects.get_or_create(user=user)
    return profile


class RegisterView(generics.CreateAPIView):
    """Create an account and return an auth token."""

    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        Profile.objects.get_or_create(user=user)
        token, _ = Token.objects.get_or_create(user=user)
        return Response(
            {
                "token": token.key,
                "profile": ProfileSerializer(_profile_for(user)).data,
            },
            status=status.HTTP_201_CREATED,
        )


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    """Authenticate with username/password and return a token."""

    username = request.data.get("username")
    password = request.data.get("password")
    if not username or not password:
        return Response(
            {"detail": "username and password are required."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    from django.contrib.auth import authenticate

    user = authenticate(username=username, password=password)
    if user is None:
        return Response(
            {"detail": "Invalid credentials."},
            status=status.HTTP_401_UNAUTHORIZED,
        )
    token, _ = Token.objects.get_or_create(user=user)
    return Response(
        {
            "token": token.key,
            "profile": ProfileSerializer(_profile_for(user)).data,
        }
    )


class MeView(APIView):
    """Return the current user's gamification profile."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(ProfileSerializer(_profile_for(request.user)).data)


class CourseListView(generics.ListAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseSerializer
    permission_classes = [IsAuthenticated]


class CourseDetailView(generics.RetrieveAPIView):
    serializer_class = CourseDetailSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = "slug"

    def get_queryset(self):
        return Course.objects.prefetch_related(
            "units__lessons__progress",
            "units__lessons__exercises",
        )


class LessonDetailView(generics.RetrieveAPIView):
    serializer_class = LessonSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Lesson.objects.prefetch_related("exercises", "progress")


class SubmitLessonView(APIView):
    """Grade a lesson submission and update the user's progress."""

    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            lesson = Lesson.objects.prefetch_related("exercises").get(pk=pk)
        except Lesson.DoesNotExist:
            return Response(
                {"detail": "Lesson not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = SubmissionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        answers = serializer.validated_data["answers"]

        exercises = list(lesson.exercises.all())
        results = []
        correct_count = 0
        for exercise in exercises:
            submitted = answers.get(str(exercise.id))
            correct = exercise.is_correct(submitted)
            if correct:
                correct_count += 1
            results.append(
                {
                    "exercise_id": exercise.id,
                    "correct": correct,
                    "expected": exercise.answer,
                    "explanation": exercise.explanation,
                }
            )

        total = len(exercises)
        passed = total > 0 and correct_count == total

        profile = _profile_for(request.user)
        earned_xp = 0
        if passed:
            progress, created = LessonProgress.objects.get_or_create(
                user=request.user, lesson=lesson
            )
            first_completion = not progress.completed
            progress.completed = True
            progress.best_score = max(progress.best_score, correct_count)
            progress.total_questions = total
            progress.save()

            profile.register_activity()
            # Award XP only the first time the lesson is completed.
            if first_completion:
                earned_xp = lesson.xp_reward
                profile.xp += earned_xp
            profile.save()
        else:
            # Lose a heart on a failed attempt (floored at zero).
            if profile.hearts > 0:
                profile.hearts -= 1
                profile.save()

        return Response(
            {
                "passed": passed,
                "correct_count": correct_count,
                "total": total,
                "earned_xp": earned_xp,
                "results": results,
                "profile": ProfileSerializer(profile).data,
            }
        )


class LeaderboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profiles = (
            Profile.objects.select_related("user")
            .order_by("-xp", "-streak")[:50]
        )
        entries = [
            {
                "username": p.user.username,
                "xp": p.xp,
                "level": p.level,
                "streak": p.streak,
            }
            for p in profiles
        ]
        return Response(LeaderboardEntrySerializer(entries, many=True).data)
