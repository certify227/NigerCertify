from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import (
    ActiveUsersView,
    BrandingView,
    CustomerWalletViewSet,
    DashboardView,
    GenerateVoucherView,
    HotspotProfileViewSet,
    LiveDashboardView,
    LoginTemplateViewSet,
    MeView,
    NotificationViewSet,
    PointOfSaleViewSet,
    RouterViewSet,
    SupportTicketViewSet,
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
router.register("pos", PointOfSaleViewSet, basename="pos")
router.register("wallets", CustomerWalletViewSet, basename="wallet")
router.register("notifications", NotificationViewSet, basename="notification")
router.register("support-tickets", SupportTicketViewSet, basename="support-ticket")

urlpatterns = [
    path("auth/token/", TokenObtainPairView.as_view(), name="token_obtain"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("me/", MeView.as_view(), name="me"),
    path("dashboard/", DashboardView.as_view(), name="dashboard"),
    path("dashboard/live/", LiveDashboardView.as_view(), name="dashboard-live"),
    path("branding/", BrandingView.as_view(), name="branding"),
    path("active-users/", ActiveUsersView.as_view(), name="active-users"),
    path("vouchers/generate/", GenerateVoucherView.as_view(), name="generate-vouchers"),
    path("", include(router.urls)),
]
