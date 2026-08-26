"""Tests WiFiZone Pro."""

import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ["MIKROTIK_MOCK_MODE"] = "true"

from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from billing.models import Plan, Subscription
from billing.services import activate_trial
from hotspots.models import HotspotProfile, Voucher
from hotspots.services.profile_sync import parse_session_timeout, sync_profiles_from_router
from hotspots.services.qr import qr_code_base64, voucher_login_payload
from routers.models import Router

User = get_user_model()


class WiFiZoneTests(TestCase):
    def setUp(self):
        Plan.objects.get_or_create(
            slug="starter",
            defaults={
                "name": "Starter",
                "price_monthly": Decimal("15000"),
                "max_routers": 5,
                "max_vouchers_month": 500,
                "max_profiles": 20,
            },
        )
        self.client = Client()
        self.user = User.objects.create_user(
            username="testop",
            email="test@wifizone.local",
            password="TestPass123!",
        )
        activate_trial(self.user)

    def test_landing_page(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_register_and_dashboard(self):
        User.objects.create_user(username="newop", password="TestPass123!", email="a@b.com")
        self.client.login(username="newop", password="TestPass123!")
        response = self.client.get("/app/")
        self.assertEqual(response.status_code, 200)

    def test_full_voucher_flow(self):
        self.client.login(username="testop", password="TestPass123!")

        response = self.client.post(
            "/routers/add/",
            {
                "name": "MT1",
                "host": "192.168.88.1",
                "port": 8728,
                "username": "admin",
                "password": "secret",
                "hotspot_server": "hotspot1",
                "is_active": True,
            },
        )
        self.assertEqual(response.status_code, 302, f"Router create failed: {response.status_code}")
        router = Router.objects.get(owner=self.user)

        self.client.get(f"/routers/{router.pk}/test/")
        router.refresh_from_db()
        self.assertEqual(router.connection_status, Router.ConnectionStatus.ONLINE)

        self.client.post(
            "/hotspots/profiles/add/",
            {
                "router": router.pk,
                "name": "1 Heure",
                "mikrotik_profile": "1hour",
                "validity_seconds": 3600,
                "shared_users": 1,
                "price": 500,
                "is_active": True,
            },
        )
        profile = HotspotProfile.objects.get(router=router)

        response = self.client.post(
            "/hotspots/vouchers/generate/",
            {
                "router": router.pk,
                "profile": profile.pk,
                "quantity": 3,
                "prefix": "WZ",
                "sync_mikrotik": True,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Voucher.objects.filter(router=router).count(), 3)

    def test_profile_sync_mock(self):
        router = Router.objects.create(
            owner=self.user,
            name="MT",
            host="10.0.0.1",
            port=8728,
            username="admin",
        )
        router.set_password("pass")
        router.save()
        created, _, msgs = sync_profiles_from_router(router, self.user)
        self.assertGreater(created, 0)

    def test_qr_generation(self):
        payload = voucher_login_payload("user1", "pass1")
        b64 = qr_code_base64(payload)
        self.assertTrue(len(b64) > 50)

    def test_parse_session_timeout(self):
        self.assertEqual(parse_session_timeout("1h"), 3600)
        self.assertEqual(parse_session_timeout("1d"), 86400)
        self.assertEqual(parse_session_timeout("30m"), 1800)

    def test_csv_export(self):
        self.client.login(username="testop", password="TestPass123!")
        router = Router.objects.create(
            owner=self.user,
            name="MT",
            host="10.0.0.1",
            port=8728,
            username="admin",
        )
        router.set_password("pass")
        router.save()
        profile = HotspotProfile.objects.create(
            router=router,
            name="Test",
            mikrotik_profile="default",
            validity_seconds=3600,
            price=Decimal("500"),
        )
        self.client.post(
            "/hotspots/vouchers/generate/",
            {
                "router": router.pk,
                "profile": profile.pk,
                "quantity": 2,
                "sync_mikrotik": False,
            },
        )
        batch_pk = Voucher.objects.first().batch.pk
        response = self.client.get(f"/hotspots/batches/{batch_pk}/export/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response["Content-Type"])

    def test_api_jwt_dashboard(self):
        from rest_framework.test import APIClient

        api = APIClient()
        token_resp = api.post(
            "/api/v1/auth/token/",
            {"username": "testop", "password": "TestPass123!"},
            format="json",
        )
        self.assertEqual(token_resp.status_code, 200)
        token = token_resp.data["access"]
        api.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        dash = api.get("/api/v1/dashboard/")
        self.assertEqual(dash.status_code, 200)
        self.assertIn("router_count", dash.data)

    def test_login_templates_page(self):
        self.client.login(username="testop", password="TestPass123!")
        response = self.client.get("/hotspots/login-templates/")
        self.assertEqual(response.status_code, 200)

    def test_team_enterprise(self):
        from billing.models import Plan
        from billing.services import activate_plan

        activate_plan(self.user, "enterprise")
        self.client.login(username="testop", password="TestPass123!")
        response = self.client.get("/accounts/team/")
        self.assertEqual(response.status_code, 200)

    def test_core_settings_and_support(self):
        self.client.login(username="testop", password="TestPass123!")
        self.assertEqual(self.client.get("/core/settings/").status_code, 200)
        self.assertEqual(self.client.get("/core/onboarding/").status_code, 200)
        self.assertEqual(self.client.get("/support/").status_code, 200)
        response = self.client.post(
            "/support/new/",
            {"subject": "Test", "message": "Help", "priority": "normal"},
        )
        self.assertEqual(response.status_code, 302)

    def test_live_dashboard_api(self):
        from rest_framework.test import APIClient

        api = APIClient()
        token = api.post(
            "/api/v1/auth/token/",
            {"username": "testop", "password": "TestPass123!"},
            format="json",
        ).data["access"]
        api.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        live = api.get("/api/v1/dashboard/live/")
        self.assertEqual(live.status_code, 200)
        self.assertIn("timestamp", live.data)

    def test_reports_pdf(self):
        self.client.login(username="testop", password="TestPass123!")
        response = self.client.get("/hotspots/reports/pdf/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
