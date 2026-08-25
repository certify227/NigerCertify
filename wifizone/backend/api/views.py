from django.db import models
from django.db.models import Sum
from django.http import HttpResponse
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import TeamMembership
from accounts.tenant import (
    can_generate_vouchers,
    can_manage_routers,
    can_manage_team,
    get_operator,
    get_team_role,
)
from billing.services import get_user_subscription
from dashboard.services.analytics import get_dashboard_chart_data, get_subscription_days_left
from hotspots.models import HotspotLoginTemplate, HotspotProfile, Voucher, VoucherBatch
from hotspots.services.export import batch_csv_content
from hotspots.services.login_template import build_mikrotik_login_html
from hotspots.services.qr import qr_code_base64, voucher_login_payload
from hotspots.services.voucher import generate_vouchers
from routers.models import Router
from routers.services.mikrotik import get_service_for_router, test_router_connection

from .permissions import IsOperatorMember, get_operator_from_request
from .serializers import (
    GenerateVoucherSerializer,
    HotspotProfileSerializer,
    LoginTemplateSerializer,
    RouterCreateSerializer,
    RouterSerializer,
    SubscriptionSerializer,
    TeamMemberSerializer,
    UserSerializer,
    VoucherBatchSerializer,
    VoucherSerializer,
)


class MeView(APIView):
    permission_classes = [IsOperatorMember]

    def get(self, request):
        operator = get_operator_from_request(request)
        sub = get_user_subscription(operator)
        return Response({
            "user": UserSerializer(request.user).data,
            "operator": UserSerializer(operator).data,
            "role": get_team_role(request.user),
            "subscription": SubscriptionSerializer(sub).data if sub else None,
        })


class DashboardView(APIView):
    permission_classes = [IsOperatorMember]

    def get(self, request):
        operator = get_operator_from_request(request)
        sub = get_user_subscription(operator)
        routers = Router.objects.filter(owner=operator)
        chart = get_dashboard_chart_data(operator)
        revenue = Voucher.objects.filter(router__owner=operator).aggregate(s=Sum("sold_price"))["s"] or 0
        return Response({
            "router_count": routers.count(),
            "online_count": routers.filter(connection_status=Router.ConnectionStatus.ONLINE).count(),
            "total_vouchers": Voucher.objects.filter(router__owner=operator).count(),
            "vouchers_month": sub.vouchers_used_this_month if sub else 0,
            "revenue": int(revenue),
            "subscription_days_left": get_subscription_days_left(sub),
            "chart": chart,
        })


class RouterViewSet(viewsets.ModelViewSet):
    permission_classes = [IsOperatorMember]

    def get_queryset(self):
        operator = get_operator_from_request(self.request)
        return Router.objects.filter(owner=operator)

    def get_serializer_class(self):
        if self.action in ("create", "update", "partial_update"):
            return RouterCreateSerializer
        return RouterSerializer

    def perform_create(self, serializer):
        if not can_manage_routers(self.request.user):
            raise PermissionDenied("Permission refusée pour gérer les routeurs.")
        operator = get_operator_from_request(self.request)
        sub = get_user_subscription(operator)
        if not sub or not sub.is_valid:
            raise ValidationError("Abonnement invalide.")
        if Router.objects.filter(owner=operator).count() >= sub.plan.max_routers:
            raise ValidationError("Limite de routeurs atteinte.")
        serializer.save(owner=operator)

    @action(detail=True, methods=["post"])
    def test_connection(self, request, pk=None):
        router = self.get_object()
        ok, message = test_router_connection(router)
        from django.utils import timezone
        router.connection_status = Router.ConnectionStatus.ONLINE if ok else Router.ConnectionStatus.ERROR
        router.last_error = "" if ok else message
        if ok:
            router.last_connected_at = timezone.now()
        router.save()
        return Response({"ok": ok, "message": message})

    @action(detail=True, methods=["get"])
    def active_users(self, request, pk=None):
        router = self.get_object()
        service = get_service_for_router(router)
        return Response(service.list_active_users())


class HotspotProfileViewSet(viewsets.ModelViewSet):
    permission_classes = [IsOperatorMember]
    serializer_class = HotspotProfileSerializer

    def get_queryset(self):
        operator = get_operator_from_request(self.request)
        return HotspotProfile.objects.filter(router__owner=operator).select_related("router")


class VoucherViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsOperatorMember]
    serializer_class = VoucherSerializer

    def get_queryset(self):
        operator = get_operator_from_request(self.request)
        qs = Voucher.objects.filter(router__owner=operator).select_related("router", "profile")
        status_filter = self.request.query_params.get("status")
        if status_filter:
            qs = qs.filter(status=status_filter)
        q = self.request.query_params.get("q")
        if q:
            qs = qs.filter(code__icontains=q)
        return qs[:500]


class VoucherBatchViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsOperatorMember]
    serializer_class = VoucherBatchSerializer

    def get_queryset(self):
        operator = get_operator_from_request(self.request)
        return VoucherBatch.objects.filter(router__owner=operator).select_related("router", "profile")

    @action(detail=True, methods=["get"])
    def vouchers(self, request, pk=None):
        batch = self.get_object()
        return Response(VoucherSerializer(batch.vouchers.all(), many=True).data)

    @action(detail=True, methods=["get"])
    def export_csv(self, request, pk=None):
        batch = self.get_object()
        content = batch_csv_content(batch)
        response = HttpResponse(content, content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="lot-{batch.pk}.csv"'
        return response

    @action(detail=True, methods=["get"])
    def qr_codes(self, request, pk=None):
        batch = self.get_object()
        items = []
        for v in batch.vouchers.all():
            payload = voucher_login_payload(v.username, v.password)
            items.append({
                "code": v.code,
                "username": v.username,
                "password": v.password,
                "qr_base64": qr_code_base64(payload),
            })
        return Response(items)


class GenerateVoucherView(APIView):
    permission_classes = [IsOperatorMember]

    def post(self, request):
        if not can_generate_vouchers(request.user):
            raise PermissionDenied("Permission refusée.")
        operator = get_operator_from_request(request)
        serializer = GenerateVoucherSerializer(operator, data=request.data)
        serializer.is_valid(raise_exception=True)
        batch, msg = generate_vouchers(
            router=serializer.validated_data["router"],
            profile=serializer.validated_data["profile"],
            quantity=serializer.validated_data["quantity"],
            user=request.user,
            prefix=serializer.validated_data.get("prefix", ""),
            sync_mikrotik=serializer.validated_data.get("sync_mikrotik", True),
        )
        if not batch:
            return Response({"error": msg}, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            "message": msg,
            "batch": VoucherBatchSerializer(batch).data,
        }, status=status.HTTP_201_CREATED)


class ActiveUsersView(APIView):
    permission_classes = [IsOperatorMember]

    def get(self, request):
        operator = get_operator_from_request(request)
        routers = Router.objects.filter(owner=operator, is_active=True)
        all_active = []
        for router in routers:
            try:
                service = get_service_for_router(router)
                for u in service.list_active_users():
                    all_active.append({
                        "router_id": router.id,
                        "router_name": router.name,
                        "user": u.get("user") or u.get("name"),
                        "address": u.get("address"),
                        "uptime": u.get("uptime"),
                    })
            except Exception as exc:
                all_active.append({"router_id": router.id, "error": str(exc)})
        return Response(all_active)


class LoginTemplateViewSet(viewsets.ModelViewSet):
    permission_classes = [IsOperatorMember]
    serializer_class = LoginTemplateSerializer

    def get_queryset(self):
        operator = get_operator_from_request(self.request)
        return HotspotLoginTemplate.objects.filter(
            models.Q(owner=operator) | models.Q(is_system=True)
        ).distinct()

    def perform_create(self, serializer):
        operator = get_operator_from_request(self.request)
        serializer.save(owner=operator, is_system=False)

    def perform_update(self, serializer):
        instance = self.get_object()
        if instance.is_system:
            raise PermissionDenied("Les templates système ne peuvent pas être modifiés.")
        serializer.save()

    def perform_destroy(self, instance):
        if instance.is_system:
            raise PermissionDenied("Les templates système ne peuvent pas être supprimés.")
        instance.delete()

    @action(detail=True, methods=["get"])
    def preview(self, request, pk=None):
        template = self.get_object()
        operator = get_operator_from_request(request)
        html = build_mikrotik_login_html(template, operator=operator)
        return Response({"html": html})

    @action(detail=True, methods=["get"])
    def download(self, request, pk=None):
        template = self.get_object()
        operator = get_operator_from_request(request)
        router_id = request.query_params.get("router")
        router = None
        if router_id:
            router = Router.objects.filter(pk=router_id, owner=operator).first()
        html = build_mikrotik_login_html(template, operator=operator, router=router)
        response = HttpResponse(html, content_type="text/html; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="login-{template.slug}.html"'
        return response


class TeamMemberViewSet(viewsets.ModelViewSet):
    permission_classes = [IsOperatorMember]
    serializer_class = TeamMemberSerializer

    def get_queryset(self):
        operator = get_operator_from_request(self.request)
        return TeamMembership.objects.filter(owner=operator).select_related("member")

    def perform_create(self, serializer):
        if not can_manage_team(self.request.user):
            raise PermissionDenied("Multi-utilisateurs disponible sur forfait Enterprise.")
        operator = get_operator_from_request(self.request)
        sub = get_user_subscription(operator)
        max_staff = sub.plan.max_staff if sub else 0
        current = TeamMembership.objects.filter(owner=operator, is_active=True).count()
        if current >= max_staff:
            raise ValidationError(f"Limite employés atteinte ({max_staff} max).")
        serializer.save(owner=operator)

    def perform_destroy(self, instance):
        if not can_manage_team(self.request.user):
            raise PermissionDenied("Permission refusée.")
        instance.delete()
