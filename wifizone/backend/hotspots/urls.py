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
    path("login-templates/marketplace/", views.template_marketplace, name="template_marketplace"),
    path("login-templates/marketplace/<int:pk>/clone/", views.template_marketplace_clone, name="template_marketplace_clone"),
    path("pos/", views.pos_list, name="pos_list"),
    path("wallets/", views.wallet_list, name="wallet_list"),
    path("import-users/", views.import_users, name="import_users"),
    path("reports/advanced/", views.advanced_reports, name="advanced_reports"),
    path("reports/pdf/", views.reports_pdf, name="reports_pdf"),
    path("print/bluetooth/", views.bluetooth_print, name="bluetooth_print"),
    path("loyalty/", views.loyalty_settings, name="loyalty"),
]
