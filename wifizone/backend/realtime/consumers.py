import json

from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.db.models import Sum

from accounts.tenant import get_operator
from billing.services import get_user_subscription
from hotspots.models import Voucher
from routers.models import Router


class DashboardConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope["user"]
        if not user.is_authenticated:
            await self.close()
            return
        await self.accept()
        await self.send_stats()

    async def receive(self, text_data=None, bytes_data=None):
        if text_data in ("ping", '{"type":"ping"}'):
            await self.send_stats()

    async def send_stats(self):
        payload = await self._build_payload()
        await self.send(text_data=json.dumps({"type": "dashboard", "data": payload}))

    @sync_to_async
    def _build_payload(self):
        user = self.scope["user"]
        operator = get_operator(user)
        sub = get_user_subscription(operator)
        routers = Router.objects.filter(owner=operator)
        revenue = (
            Voucher.objects.filter(router__owner=operator).aggregate(s=Sum("sold_price"))["s"] or 0
        )
        return {
            "router_count": routers.count(),
            "online_count": routers.filter(connection_status=Router.ConnectionStatus.ONLINE).count(),
            "total_vouchers": Voucher.objects.filter(router__owner=operator).count(),
            "vouchers_month": sub.vouchers_used_this_month if sub else 0,
            "revenue": int(revenue),
        }
