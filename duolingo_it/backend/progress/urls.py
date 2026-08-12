from django.urls import path

from .views import SubmitLessonView

urlpatterns = [
    path("lessons/<int:pk>/submit/", SubmitLessonView.as_view(), name="lesson-submit"),
]
