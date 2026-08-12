from django.urls import path

from .views import DashboardView, DailyChallengeView, HealthView, TrackDetailView, TrackListView

urlpatterns = [
    path("health/", HealthView.as_view(), name="health"),
    path("dashboard/", DashboardView.as_view(), name="dashboard"),
    path("tracks/", TrackListView.as_view(), name="track-list"),
    path("tracks/<slug:slug>/", TrackDetailView.as_view(), name="track-detail"),
    path("daily-challenge/", DailyChallengeView.as_view(), name="daily-challenge"),
]
