from django.urls import path

from .views import dashboard, health_check, lesson_detail

urlpatterns = [
    path("health/", health_check, name="health-check"),
    path("dashboard/", dashboard, name="dashboard"),
    path("lessons/<slug:slug>/", lesson_detail, name="lesson-detail"),
]
