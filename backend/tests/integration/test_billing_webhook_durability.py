"""Billing webhook durability and fail-closed entitlement regression tests."""
import hashlib
import hmac
import json

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from core.config import settings
from core.database import AsyncSessionLocal
from models.webhook_event import WebhookEvent


def _signed(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.mark.asyncio
async def test_signed_billing_webhook_is_durable_and_exact_replay_is_idempotent(monkeypatch):
    secret = "test-webhook-secret-that-is-not-a-real-provider-secret"
    monkeypatch.setattr(settings, "LEMONSQUEEZY_WEBHOOK_SECRET", secret)
    body = json.dumps({
        "meta": {"event_name": "subscription_created"},
        "data": {"id": "provider-subscription-123", "attributes": {"status": "active"}},
    }, separators=(",", ":")).encode()
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/billing/webhook", content=body, headers={"X-Signature": _signed(body, secret)})
        replay = await client.post("/billing/webhook", content=body, headers={"X-Signature": _signed(body, secret)})

    assert first.status_code == 202
    assert first.json()["duplicate"] is False
    assert first.json()["entitlements_changed"] is False
    assert first.json()["reconciliation_required"] is True
    assert replay.status_code == 202
    assert replay.json()["duplicate"] is True
    assert replay.headers["Idempotent-Replay"] == "true"

    async with AsyncSessionLocal() as db:
        events = (await db.scalars(select(WebhookEvent).where(
            WebhookEvent.provider == "lemonsqueezy"
        ))).all()
    assert len(events) == 1
    assert events[0].status == "received"
    assert events[0].org_id is None
    assert events[0].payload_sha256 == hashlib.sha256(body).hexdigest()


@pytest.mark.asyncio
async def test_invalid_billing_signature_does_not_write_webhook_event(monkeypatch):
    monkeypatch.setattr(settings, "LEMONSQUEEZY_WEBHOOK_SECRET", "test-webhook-secret-that-is-not-a-real-provider-secret")
    body = b'{"meta":{"event_name":"subscription_created"},"data":{"id":"123"}}'
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/billing/webhook", content=body, headers={"X-Signature": "0" * 64})
    assert response.status_code == 401
    async with AsyncSessionLocal() as db:
        events = (await db.scalars(select(WebhookEvent).where(
            WebhookEvent.provider == "lemonsqueezy"
        ))).all()
    assert events == []


@pytest.mark.asyncio
async def test_unknown_signed_billing_event_is_recorded_but_never_executed(monkeypatch):
    secret = "test-webhook-secret-that-is-not-a-real-provider-secret"
    monkeypatch.setattr(settings, "LEMONSQUEEZY_WEBHOOK_SECRET", secret)
    body = b'{"meta":{"event_name":"arbitrary_command"},"data":{"id":"123"}}'
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/billing/webhook", content=body, headers={"X-Signature": _signed(body, secret)})
    assert response.status_code == 202
    assert response.json()["entitlements_changed"] is False
    assert response.json()["reconciliation_required"] is False
    async with AsyncSessionLocal() as db:
        event = await db.scalar(select(WebhookEvent).where(
            WebhookEvent.provider == "lemonsqueezy"
        ))
    assert event is not None
    assert event.status == "ignored_unknown_event"
    assert event.processed_at is not None
