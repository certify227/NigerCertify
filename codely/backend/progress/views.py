from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from progress.models import DailyActivity, UserLessonProgress
from progress.serializers import DashboardSerializer, UserLessonProgressSerializer


class DashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        today = timezone.localdate()
        activity = DailyActivity.objects.filter(user=user, date=today).first()

        tracks_in_progress = UserLessonProgress.objects.filter(
            user=user,
            completed=False,
        ).values("lesson__unit__track").distinct().count()

        data = {
            "xp": user.xp,
            "level": user.level,
            "streak": user.streak,
            "hearts": user.hearts,
            "lessons_completed_today": activity.lessons_done if activity else 0,
            "xp_today": activity.xp_earned if activity else 0,
            "tracks_in_progress": tracks_in_progress,
        }
        return Response(DashboardSerializer(data).data)


class MyProgressView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        progress = UserLessonProgress.objects.filter(user=request.user).select_related("lesson")
        serializer = UserLessonProgressSerializer(progress, many=True)
        return Response(serializer.data)
