"""Routes de l'app accounts."""
from django.urls import path

from .views import LeaderboardView, MeView, RegisterView

urlpatterns = [
    path("auth/register/", RegisterView.as_view(), name="auth-register"),
    path("me/", MeView.as_view(), name="me"),
    path("leaderboard/", LeaderboardView.as_view(), name="leaderboard"),
]
