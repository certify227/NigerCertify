"""Routes de l'app courses."""
from django.urls import path

from .views import CourseDetailView, CourseListView, LessonDetailView

urlpatterns = [
    path("courses/", CourseListView.as_view(), name="course-list"),
    path("courses/<slug:slug>/", CourseDetailView.as_view(), name="course-detail"),
    path("lessons/<int:pk>/", LessonDetailView.as_view(), name="lesson-detail"),
]
