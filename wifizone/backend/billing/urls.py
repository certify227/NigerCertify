from django.urls import path

from . import views

app_name = "billing"

urlpatterns = [
    path("pricing/", views.pricing, name="pricing"),
    path("subscribe/<slug:slug>/", views.subscribe, name="subscribe"),
    path("success/<slug:slug>/", views.success, name="success"),
]
