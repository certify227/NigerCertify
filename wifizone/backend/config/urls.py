import os

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

_admin_prefix = os.getenv("DJANGO_ADMIN_URL", "admin").strip("/")

urlpatterns = [
    path(f"{_admin_prefix}/", admin.site.urls),
    path("", include("dashboard.urls")),
    path("accounts/", include("accounts.urls")),
    path("billing/", include("billing.urls")),
    path("routers/", include("routers.urls")),
    path("hotspots/", include("hotspots.urls")),
    path("api/v1/", include("api.urls")),
    path("core/", include("core.urls")),
    path("support/", include("support.urls")),
]

_enable_api_docs = settings.DEBUG or os.getenv("ENABLE_API_DOCS", "false").lower() == "true"
if _enable_api_docs:
    from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

    urlpatterns += [
        path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
        path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    ]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
