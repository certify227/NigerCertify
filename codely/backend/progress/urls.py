from django.urls import path

from progress.views import DashboardView, MyProgressView

urlpatterns = [
    path("dashboard/", DashboardView.as_view(), name="dashboard"),
    path("me/", MyProgressView.as_view(), name="my-progress"),
]
