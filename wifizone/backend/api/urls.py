from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import (
    ActiveUsersView,
    DashboardView,
    GenerateVoucherView,
    HotspotProfileViewSet,
    LoginTemplateViewSet,
    MeView,
    RouterViewSet,
    TeamMemberViewSet,
    VoucherBatchViewSet,
    VoucherViewSet,
)

router = DefaultRouter()
router.register("routers", RouterViewSet, basename="router")
router.register("profiles", HotspotProfileViewSet, basename="profile")
router.register("vouchers", VoucherViewSet, basename="voucher")
router.register("batches", VoucherBatchViewSet, basename="batch")
router.register("login-templates", LoginTemplateViewSet, basename="login-template")
router.register("team", TeamMemberViewSet, basename="team")

urlpatterns = [
    path("auth/token/", TokenObtainPairView.as_view(), name="token_obtain"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("me/", MeView.as_view(), name="me"),
    path("dashboard/", DashboardView.as_view(), name="dashboard"),
    path("active-users/", ActiveUsersView.as_view(), name="active-users"),
    path("vouchers/generate/", GenerateVoucherView.as_view(), name="generate-vouchers"),
    path("", include(router.urls)),
]
