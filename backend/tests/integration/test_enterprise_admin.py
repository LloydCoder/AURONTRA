"""Enterprise administration tests for tenant isolation and secret handling."""
import hashlib

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from core.database import AsyncSessionLocal
from models.api_key import APIKey
from models.audit_event import AuditEvent
from models.organization import Organization


@pytest.mark.asyncio
async def test_admin_api_key_is_shown_once_hashed_at_rest_and_audited():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post("/admin/api-keys", json={
            "scopes": ["read:devices", "read:tickets"], "expires_in_days": 30,
        })
        assert created.status_code == 201
        payload = created.json()
        raw_key = payload["api_key"]
        listed = await client.get("/admin/api-keys")
        audit = await client.get("/admin/audit")

    assert raw_key.startswith("aurontra_")
    assert payload["warning"].startswith("Copy this key now")
    assert listed.status_code == 200
    assert all("key_hash" not in item for item in listed.json()["api_keys"])
    assert audit.status_code == 200
    assert audit.json()["events"][0]["event_type"] == "admin.api_key.created"

    async with AsyncSessionLocal() as db:
        row = await db.get(APIKey, payload["id"])
        event = await db.scalar(select(AuditEvent).where(AuditEvent.resource_id == payload["id"]))
    assert row is not None
    assert row.key_hash == hashlib.sha256(raw_key.encode()).hexdigest()
    assert raw_key not in row.key_hash
    assert event is not None
    assert event.previous_hash == "0" * 64
    assert len(event.event_hash) == 64


@pytest.mark.asyncio
async def test_admin_api_key_revoke_is_idempotent_and_tenant_scoped():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post("/admin/api-keys", json={"scopes": ["read:devices"]})
        key_id = created.json()["id"]
        first = await client.post(f"/admin/api-keys/{key_id}/revoke")
        replay = await client.post(f"/admin/api-keys/{key_id}/revoke")
    assert created.status_code == 201
    assert first.status_code == 200
    assert first.json()["revoked"] is True
    assert first.json()["already_revoked"] is False
    assert replay.status_code == 200
    assert replay.json()["already_revoked"] is True

    async with AsyncSessionLocal() as db:
        row = await db.get(APIKey, key_id)
        events = (await db.scalars(select(AuditEvent).where(
            AuditEvent.resource_id == key_id
        ).order_by(AuditEvent.sequence))).all()
    assert row.revoked_at is not None
    assert [event.event_type for event in events] == ["admin.api_key.created", "admin.api_key.revoked"]
    assert events[1].previous_hash == events[0].event_hash


@pytest.mark.asyncio
async def test_admin_api_key_scopes_reject_unknown_or_duplicate_values():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        unknown = await client.post("/admin/api-keys", json={"scopes": ["admin:all"]})
        duplicate = await client.post("/admin/api-keys", json={"scopes": ["read:devices", "read:devices"]})
    assert unknown.status_code == 422
    assert duplicate.status_code == 422


@pytest.mark.asyncio
async def test_admin_api_key_listing_never_exposes_another_tenant_key():
    async with AsyncSessionLocal() as db:
        db.add(Organization(id="other-admin-tenant", name="Other Admin Tenant", status="active"))
        await db.flush()
        db.add(APIKey(
            id="other-tenant-key", org_id="other-admin-tenant", key_hash="f" * 64,
            key_prefix="aurontra_other", scopes=["read:devices"], created_by="other-admin",
        ))
        await db.commit()

    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/admin/api-keys")
    assert response.status_code == 200
    assert all(item["id"] != "other-tenant-key" for item in response.json()["api_keys"])
