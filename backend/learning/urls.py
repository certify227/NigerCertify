from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import LessonDetailView, ProgressView, RegisterView, SubmitAnswerView, TrackViewSet, health_check


router = DefaultRouter()
router.register("tracks", TrackViewSet, basename="track")

urlpatterns = [
    path("health/", health_check, name="health"),
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("lessons/<int:pk>/", LessonDetailView.as_view(), name="lesson-detail"),
    path("challenges/<int:pk>/submit/", SubmitAnswerView.as_view(), name="challenge-submit"),
    path("me/progress/", ProgressView.as_view(), name="progress"),
    path("", include(router.urls)),
]
