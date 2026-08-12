from django.urls import path

from courses.views import LessonDetailView, SubmitAnswerView, TrackDetailView, TrackListView

urlpatterns = [
    path("tracks/", TrackListView.as_view(), name="track-list"),
    path("tracks/<slug:slug>/", TrackDetailView.as_view(), name="track-detail"),
    path("lessons/<int:pk>/", LessonDetailView.as_view(), name="lesson-detail"),
    path("exercises/<int:exercise_id>/submit/", SubmitAnswerView.as_view(), name="submit-answer"),
]
