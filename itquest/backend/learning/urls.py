from django.urls import path

from .views import (
    HealthCheckView,
    LessonDetailView,
    LessonSubmitView,
    TrackListView,
    UserProgressView,
)

urlpatterns = [
    path("health/", HealthCheckView.as_view(), name="health-check"),
    path("tracks/", TrackListView.as_view(), name="track-list"),
    path("lessons/<int:pk>/", LessonDetailView.as_view(), name="lesson-detail"),
    path("lessons/<int:pk>/submit/", LessonSubmitView.as_view(), name="lesson-submit"),
    path("progress/<str:username>/", UserProgressView.as_view(), name="user-progress"),
]
