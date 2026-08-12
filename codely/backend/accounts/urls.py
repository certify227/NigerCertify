from django.urls import path

from accounts.views import LeaderboardView, ProfileView, RefillHeartsView, RegisterView, ReminderSettingsView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("leaderboard/", LeaderboardView.as_view(), name="leaderboard"),
    path("hearts/refill/", RefillHeartsView.as_view(), name="refill-hearts"),
    path("reminders/", ReminderSettingsView.as_view(), name="reminder-settings"),
]
