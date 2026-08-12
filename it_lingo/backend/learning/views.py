from django.db.models import Count
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Challenge, Track
from .serializers import ChallengeSerializer, TrackDetailSerializer, TrackListSerializer


class HealthView(APIView):
    def get(self, request):
        return Response({"status": "ok", "service": "itlingo-backend"})


class DashboardView(APIView):
    def get(self, request):
        tracks = (
            Track.objects.annotate(
                module_count=Count("modules", distinct=True),
                lesson_count=Count("modules__lessons", distinct=True),
            )
            .prefetch_related("modules__lessons")
            .order_by("order", "title")
        )
        featured = Challenge.objects.filter(is_daily_featured=True).select_related("track").first()
        payload = {
            "streak_goal": 20,
            "daily_xp_target": 50,
            "tracks": TrackListSerializer(tracks, many=True).data,
            "daily_challenge": ChallengeSerializer(featured).data if featured else None,
        }
        return Response(payload)


class TrackListView(APIView):
    def get(self, request):
        tracks = Track.objects.annotate(
            module_count=Count("modules", distinct=True),
            lesson_count=Count("modules__lessons", distinct=True),
        ).order_by("order", "title")
        return Response(TrackListSerializer(tracks, many=True).data)


class TrackDetailView(APIView):
    def get(self, request, slug: str):
        track = get_object_or_404(
            Track.objects.prefetch_related("modules__lessons"),
            slug=slug,
        )
        return Response(TrackDetailSerializer(track).data)


class DailyChallengeView(APIView):
    def get(self, request):
        challenge = get_object_or_404(
            Challenge.objects.select_related("track").filter(is_daily_featured=True)
        )
        return Response(ChallengeSerializer(challenge).data)
