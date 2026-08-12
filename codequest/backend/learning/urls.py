"""URL routing for the learning API."""

from django.urls import path

from . import views

urlpatterns = [
    path("auth/register/", views.RegisterView.as_view(), name="register"),
    path("auth/login/", views.login_view, name="login"),
    path("me/", views.MeView.as_view(), name="me"),
    path("courses/", views.CourseListView.as_view(), name="course-list"),
    path(
        "courses/<slug:slug>/",
        views.CourseDetailView.as_view(),
        name="course-detail",
    ),
    path("lessons/<int:pk>/", views.LessonDetailView.as_view(), name="lesson-detail"),
    path(
        "lessons/<int:pk>/submit/",
        views.SubmitLessonView.as_view(),
        name="lesson-submit",
    ),
    path("leaderboard/", views.LeaderboardView.as_view(), name="leaderboard"),
]
