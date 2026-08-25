from rest_framework import serializers

from accounts.models import TeamMembership, User
from billing.models import Plan, Subscription
from billing.services import get_user_subscription
from hotspots.models import HotspotLoginTemplate, HotspotProfile, Voucher, VoucherBatch
from routers.models import Router


class UserSerializer(serializers.ModelSerializer):
    display_name = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = ("id", "username", "email", "company_name", "phone", "city", "display_name")


class PlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plan
        fields = (
            "slug", "name", "price_monthly", "max_routers",
            "max_vouchers_month", "max_profiles", "max_staff",
        )


class SubscriptionSerializer(serializers.ModelSerializer):
    plan = PlanSerializer(read_only=True)
    is_valid = serializers.BooleanField(read_only=True)

    class Meta:
        model = Subscription
        fields = (
            "status", "plan", "expires_at", "vouchers_used_this_month", "is_valid",
        )


class RouterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Router
        fields = (
            "id", "name", "host", "port", "username", "hotspot_server",
            "login_template", "is_active", "connection_status",
            "last_connected_at", "last_error", "created_at",
        )
        read_only_fields = ("connection_status", "last_connected_at", "last_error", "created_at")


class RouterCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = Router
        fields = (
            "name", "host", "port", "username", "password",
            "hotspot_server", "login_template", "is_active",
        )

    def create(self, validated_data):
        password = validated_data.pop("password")
        router = Router(**validated_data)
        router.set_password(password)
        router.save()
        return router


class HotspotProfileSerializer(serializers.ModelSerializer):
    validity_display = serializers.CharField(read_only=True)
    router_name = serializers.CharField(source="router.name", read_only=True)

    class Meta:
        model = HotspotProfile
        fields = (
            "id", "router", "router_name", "name", "mikrotik_profile",
            "validity_seconds", "validity_display", "data_limit_bytes",
            "shared_users", "price", "is_active",
        )


class VoucherSerializer(serializers.ModelSerializer):
    profile_name = serializers.CharField(source="profile.name", read_only=True)
    router_name = serializers.CharField(source="router.name", read_only=True)

    class Meta:
        model = Voucher
        fields = (
            "id", "code", "username", "password", "status",
            "sold_price", "synced_to_mikrotik", "router", "router_name",
            "profile", "profile_name", "created_at",
        )


class VoucherBatchSerializer(serializers.ModelSerializer):
    profile_name = serializers.CharField(source="profile.name", read_only=True)
    router_name = serializers.CharField(source="router.name", read_only=True)

    class Meta:
        model = VoucherBatch
        fields = (
            "id", "router", "router_name", "profile", "profile_name",
            "quantity", "prefix", "total_price", "created_at",
        )


class GenerateVoucherSerializer(serializers.Serializer):
    router = serializers.PrimaryKeyRelatedField(queryset=Router.objects.none())
    profile = serializers.PrimaryKeyRelatedField(queryset=HotspotProfile.objects.none())
    quantity = serializers.IntegerField(min_value=1, max_value=500, default=10)
    prefix = serializers.CharField(max_length=10, required=False, allow_blank=True)
    sync_mikrotik = serializers.BooleanField(default=True)

    def __init__(self, operator, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["router"].queryset = Router.objects.filter(owner=operator)
        self.fields["profile"].queryset = HotspotProfile.objects.filter(router__owner=operator)


class LoginTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = HotspotLoginTemplate
        fields = (
            "id", "name", "slug", "description", "html_body",
            "primary_color", "background_color", "wifi_name", "logo_url",
            "is_system", "is_active", "created_at", "updated_at",
        )
        read_only_fields = ("is_system", "created_at", "updated_at")


class TeamMemberSerializer(serializers.ModelSerializer):
    member = UserSerializer(read_only=True)
    username = serializers.CharField(write_only=True)
    email = serializers.EmailField(write_only=True, required=False)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = TeamMembership
        fields = ("id", "member", "role", "is_active", "joined_at", "username", "email", "password")
        read_only_fields = ("id", "member", "joined_at")

    def create(self, validated_data):
        owner = self.context["owner"]
        username = validated_data.pop("username")
        password = validated_data.pop("password")
        email = validated_data.pop("email", "")
        user = User.objects.create_user(username=username, password=password, email=email)
        return TeamMembership.objects.create(
            owner=owner,
            member=user,
            role=validated_data.get("role", TeamMembership.Role.STAFF),
            is_active=True,
        )
