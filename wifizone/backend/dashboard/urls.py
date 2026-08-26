from django.urls import path

from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.landing, name="landing"),
    path("app/", views.home, name="home"),
    path("app/active-users/", views.active_users, name="active_users"),
]
