"""Webhooks sortants."""

import hashlib
import hmac
import json
import logging

import requests

from core.models import WebhookEndpoint

logger = logging.getLogger(__name__)


def fire_webhook(operator, event: str, payload: dict):
    endpoints = WebhookEndpoint.objects.filter(operator=operator, is_active=True)
    body = json.dumps({"event": event, "data": payload}, default=str)
    for ep in endpoints:
        if ep.events and event not in ep.events:
            continue
        sig = hmac.new(ep.secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        try:
            requests.post(
                ep.url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-WiFiZone-Signature": sig,
                    "X-WiFiZone-Event": event,
                },
                timeout=10,
            )
        except Exception as exc:
            logger.warning("Webhook failed %s: %s", ep.url, exc)
