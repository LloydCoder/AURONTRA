"""Regression tests for the Aurontra security-first baseline."""
import hashlib
import hmac

import pytest
from fastapi import HTTPException

from core.config import settings
from billing.webhook_handler import verify_webhook_signature
from api.routes.automation import TriggerRequest, trigger_playbook
from api.routes.threats import BlockRequest, block_threat_endpoint


def test_webhook_rejects_missing_secret(monkeypatch):
    monkeypatch.setattr(settings, "LEMONSQUEEZY_WEBHOOK_SECRET", "")
    assert verify_webhook_signature(b'{"data":{}}', "a" * 64) is False


def test_webhook_rejects_missing_signature(monkeypatch):
    monkeypatch.setattr(settings, "LEMONSQUEEZY_WEBHOOK_SECRET", "unit-test-secret")
    assert verify_webhook_signature(b'{"data":{}}', "") is False


def test_webhook_accepts_correct_signature_and_rejects_tampering(monkeypatch):
    secret = "unit-test-secret"
    body = b'{"meta":{"event_name":"subscription_created"},"data":{"id":"test"}}'
    monkeypatch.setattr(settings, "LEMONSQUEEZY_WEBHOOK_SECRET", secret)
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    assert verify_webhook_signature(body, signature) is True
    assert verify_webhook_signature(body + b" ", signature) is False


@pytest.mark.asyncio
async def test_public_playbook_execution_is_disabled():
    with pytest.raises(HTTPException) as exc:
        await trigger_playbook(TriggerRequest(playbook_name="disk_full", device_id="test-device"))
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_public_threat_containment_is_disabled():
    with pytest.raises(HTTPException) as exc:
        await block_threat_endpoint(BlockRequest(src_ip="192.0.2.10", scenario="test", org_id="test-org"))
    assert exc.value.status_code == 503
