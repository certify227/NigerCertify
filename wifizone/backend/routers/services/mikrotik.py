"""Client API MikroTik RouterOS."""

import logging
from dataclasses import dataclass
from datetime import datetime

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


@dataclass
class MikroTikUser:
    name: str
    password: str
    profile: str
    comment: str = ""


class MikroTikService:
    """Connexion et opérations hotspot via API RouterOS."""

    def __init__(self, host: str, port: int, username: str, password: str):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self._pool = None

    def connect(self):
        if settings.MIKROTIK_MOCK_MODE:
            return True
        try:
            import routeros_api

            self._pool = routeros_api.RouterOsApiPool(
                self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                use_ssl=False,
                plaintext_login=True,
            )
            api = self._pool.get_api()
            api.get_resource("/system/identity").get()
            return True
        except Exception as exc:
            logger.warning("MikroTik connection failed: %s", exc)
            raise

    def disconnect(self):
        if self._pool:
            try:
                self._pool.disconnect()
            except Exception:
                pass
            self._pool = None

    def test_connection(self) -> tuple[bool, str]:
        if settings.MIKROTIK_MOCK_MODE:
            return True, "Mode démo — connexion simulée OK"
        try:
            self.connect()
            self.disconnect()
            return True, "Connexion réussie"
        except Exception as exc:
            return False, str(exc)

    def list_hotspot_users(self) -> list[dict]:
        if settings.MIKROTIK_MOCK_MODE:
            return [
                {"name": "demo-user1", "profile": "1hour", "uptime": "00:15:00"},
                {"name": "demo-user2", "profile": "1day", "uptime": "02:30:00"},
            ]
        self.connect()
        try:
            resource = self._pool.get_api().get_resource("/ip/hotspot/user")
            return resource.get()
        finally:
            self.disconnect()

    def list_active_users(self) -> list[dict]:
        if settings.MIKROTIK_MOCK_MODE:
            return [{"user": "demo-user1", "address": "192.168.88.100", "uptime": "00:15:00", "mac-address": "AA:BB:CC:DD:EE:01"}]
        self.connect()
        try:
            resource = self._pool.get_api().get_resource("/ip/hotspot/active")
            return resource.get()
        finally:
            self.disconnect()

    def list_profiles(self) -> list[dict]:
        if settings.MIKROTIK_MOCK_MODE:
            return [
                {"name": "default", "session-timeout": "1h"},
                {"name": "1day", "session-timeout": "1d"},
            ]
        self.connect()
        try:
            resource = self._pool.get_api().get_resource("/ip/hotspot/user/profile")
            return resource.get()
        finally:
            self.disconnect()

    def add_hotspot_user(self, user: MikroTikUser) -> bool:
        if settings.MIKROTIK_MOCK_MODE:
            return True
        self.connect()
        try:
            resource = self._pool.get_api().get_resource("/ip/hotspot/user")
            resource.add(
                name=user.name,
                password=user.password,
                profile=user.profile,
                comment=user.comment,
            )
            return True
        finally:
            self.disconnect()

    def remove_hotspot_user(self, name: str) -> bool:
        if settings.MIKROTIK_MOCK_MODE:
            return True
        self.connect()
        try:
            resource = self._pool.get_api().get_resource("/ip/hotspot/user")
            users = resource.get(name=name)
            for u in users:
                resource.remove(id=u["id"])
            return True
        finally:
            self.disconnect()

    def list_hotspot_cookies(self) -> list[dict]:
        if settings.MIKROTIK_MOCK_MODE:
            return [{"user": "demo-user1", "address": "192.168.88.100"}]
        self.connect()
        try:
            return self._pool.get_api().get_resource("/ip/hotspot/cookie").get()
        finally:
            self.disconnect()

    def disconnect_active_user(self, session_id: str) -> bool:
        if settings.MIKROTIK_MOCK_MODE:
            return True
        self.connect()
        try:
            resource = self._pool.get_api().get_resource("/ip/hotspot/active")
            resource.remove(id=session_id)
            return True
        finally:
            self.disconnect()

    def list_simple_queues(self) -> list[dict]:
        if settings.MIKROTIK_MOCK_MODE:
            return [{"name": "default", "target": "192.168.88.0/24"}]
        self.connect()
        try:
            return self._pool.get_api().get_resource("/queue/simple").get()
        finally:
            self.disconnect()

    def get_system_info(self) -> dict:
        if settings.MIKROTIK_MOCK_MODE:
            return {
                "identity": "MikroTik-Demo",
                "version": "7.12 (mock)",
                "uptime": "5d12h",
            }
        self.connect()
        try:
            api = self._pool.get_api()
            identity = api.get_resource("/system/identity").get()
            resource = api.get_resource("/system/resource")
            res = resource.get()
            info = res[0] if res else {}
            return {
                "identity": identity[0].get("name", "") if identity else "",
                "version": info.get("version", ""),
                "uptime": info.get("uptime", ""),
            }
        finally:
            self.disconnect()


def get_service_for_router(router) -> MikroTikService:
    return MikroTikService(
        host=router.host,
        port=router.port,
        username=router.username,
        password=router.get_password(),
    )


def test_router_connection(router) -> tuple[bool, str]:
    service = get_service_for_router(router)
    return service.test_connection()
