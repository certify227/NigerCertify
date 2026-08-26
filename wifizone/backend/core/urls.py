from django.urls import path

from . import views

app_name = "core"

urlpatterns = [
    path("settings/", views.settings_hub, name="settings"),
    path("settings/branding/", views.branding_edit, name="branding"),
    path("notifications/", views.notifications_list, name="notifications"),
    path("audit/", views.audit_log, name="audit"),
    path("webhooks/", views.webhooks_list, name="webhooks"),
    path("onboarding/", views.onboarding, name="onboarding"),
    path("wifi-map/", views.wifi_map, name="wifi_map"),
]
