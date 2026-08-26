from django.urls import path

from . import views

app_name = "routers"

urlpatterns = [
    path("", views.router_list, name="list"),
    path("add/", views.router_create, name="create"),
    path("<int:pk>/", views.router_detail, name="detail"),
    path("<int:pk>/edit/", views.router_edit, name="edit"),
    path("<int:pk>/delete/", views.router_delete, name="delete"),
    path("<int:pk>/test/", views.router_test, name="test"),
    path("<int:pk>/sync-profiles/", views.router_sync_profiles, name="sync_profiles"),
    path("radius/", views.radius_list, name="radius_list"),
    path("radius/<int:pk>/export/", views.radius_export, name="radius_export"),
]
