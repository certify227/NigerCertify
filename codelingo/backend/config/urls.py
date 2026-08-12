from django.contrib import admin
from django.http import JsonResponse
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

from accounts.views import LeaderboardView, MeView, RegisterView
from learning.views import (
    CourseDetailView,
    CourseListView,
    LessonCompleteView,
    LessonDetailView,
    MyProgressView,
)


def api_root(_request):
    return JsonResponse(
        {
            "name": "CodeLingo API",
            "version": "1.0",
            "endpoints": [
                "/api/auth/register/",
                "/api/auth/login/",
                "/api/auth/refresh/",
                "/api/auth/me/",
                "/api/courses/",
                "/api/courses/<slug>/",
                "/api/lessons/<id>/",
                "/api/lessons/<id>/complete/",
                "/api/me/progress/",
                "/api/leaderboard/",
            ],
        }
    )


urlpatterns = [
    path("", api_root),
    path("admin/", admin.site.urls),
    # Auth
    path("api/auth/register/", RegisterView.as_view(), name="register"),
    path("api/auth/login/", TokenObtainPairView.as_view(), name="login"),
    path("api/auth/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/auth/me/", MeView.as_view(), name="me"),
    # Learning
    path("api/courses/", CourseListView.as_view(), name="course_list"),
    path("api/courses/<slug:slug>/", CourseDetailView.as_view(), name="course_detail"),
    path("api/lessons/<int:pk>/", LessonDetailView.as_view(), name="lesson_detail"),
    path(
        "api/lessons/<int:pk>/complete/",
        LessonCompleteView.as_view(),
        name="lesson_complete",
    ),
    path("api/me/progress/", MyProgressView.as_view(), name="my_progress"),
    path("api/leaderboard/", LeaderboardView.as_view(), name="leaderboard"),
]
