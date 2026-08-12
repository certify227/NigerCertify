from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import LearnerProfile, Lesson, LessonProgress, Track
from .serializers import (
    LearnerProfileSerializer,
    LessonDetailSerializer,
    TrackSerializer,
)


def _ensure_demo_profile():
    profile, _ = LearnerProfile.objects.get_or_create(
        id=1,
        defaults={
            "display_name": "Aicha",
            "target_role": "Developpeuse mobile et cloud",
            "daily_goal_minutes": 25,
            "streak_days": 7,
            "total_xp": 320,
            "hearts": 5,
        },
    )
    return profile


@api_view(["GET"])
def health_check(_request):
    return Response({"status": "ok", "service": "devlingo-api"})


@api_view(["GET"])
def dashboard(_request):
    profile = _ensure_demo_profile()
    tracks = Track.objects.prefetch_related("lessons").all()
    progress_records = LessonProgress.objects.select_related("lesson").filter(
        profile=profile
    )
    progress_map = {record.lesson_id: record for record in progress_records}

    return Response(
        {
            "profile": LearnerProfileSerializer(profile).data,
            "tracks": TrackSerializer(
                tracks,
                many=True,
                context={"progress_map": progress_map},
            ).data,
            "daily_plan": {
                "goal_minutes": profile.daily_goal_minutes,
                "recommended_focus": "Python, Git et Linux",
                "cta": "Lancer la prochaine lecon",
            },
        }
    )


@api_view(["GET"])
def lesson_detail(_request, slug):
    lesson = get_object_or_404(
        Lesson.objects.select_related("track").prefetch_related("exercises"),
        slug=slug,
    )
    return Response(LessonDetailSerializer(lesson).data)
