from django.urls import path

from . import views

app_name = "hotspots"

urlpatterns = [
    path("profiles/", views.profile_list, name="profile_list"),
    path("profiles/add/", views.profile_create, name="profile_create"),
    path("profiles/<int:pk>/edit/", views.profile_edit, name="profile_edit"),
    path("vouchers/", views.voucher_list, name="voucher_list"),
    path("vouchers/export/", views.voucher_export_csv, name="voucher_export_csv"),
    path("vouchers/generate/", views.voucher_generate, name="voucher_generate"),
    path("batches/", views.batch_list, name="batch_list"),
    path("batches/<int:pk>/", views.batch_detail, name="batch_detail"),
    path("batches/<int:pk>/export/", views.batch_export_csv, name="batch_export_csv"),
    path("reports/", views.reports, name="reports"),
    path("login-templates/", views.login_template_list, name="login_template_list"),
    path("login-templates/add/", views.login_template_create, name="login_template_create"),
    path("login-templates/<int:pk>/edit/", views.login_template_edit, name="login_template_edit"),
    path("login-templates/<int:pk>/preview/", views.login_template_preview, name="login_template_preview"),
    path("login-templates/<int:pk>/download/", views.login_template_download, name="login_template_download"),
]
