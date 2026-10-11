"""Phase 07 lifecycle regression tests for tenant organization/device state."""
import pytest
from httpx import ASGITransport, AsyncClient

from core.database import AsyncSessionLocal
from models.device import Device
from models.organization import Organization


@pytest.mark.asyncio
async def test_device_provisioning_creates_inactive_unenrolled_record():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/devices/provision", json={
            "name": "ops-node-01",
            "device_type": "server",
            "os_type": "linux",
        })

    assert response.status_code == 201
    payload = response.json()
    assert payload["lifecycle_state"] == "provisioned_pending_agent_enrollment"
    device = payload["device"]
    assert device["is_active"] is False
    assert device["enrolled_at"] is None
    assert device["revoked_at"] is None
    async with AsyncSessionLocal() as db:
        stored = await db.get(Device, device["id"])
        assert stored is not None
        assert stored.org_id == "test-tenant"
        assert stored.is_active is False
        assert stored.enrolled_at is None


@pytest.mark.asyncio
async def test_device_revocation_is_idempotent_and_tenant_scoped():
    async with AsyncSessionLocal() as db:
        db.add(Device(id="revoke-me", org_id="test-tenant", name="revocation test", is_active=True))
        db.add(Organization(id="other-tenant", name="Other Tenant", status="active"))
        db.add(Device(id="other-device", org_id="other-tenant", name="other tenant device", is_active=True))
        await db.commit()

    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        revoked = await client.post("/devices/revoke-me/revoke")
        repeated = await client.post("/devices/revoke-me/revoke")
        cross_tenant = await client.post("/devices/other-device/revoke")

    assert revoked.status_code == 200
    assert revoked.json()["revoked"] is True
    assert repeated.status_code == 200
    assert repeated.json()["already_revoked"] is True
    assert cross_tenant.status_code == 404
    async with AsyncSessionLocal() as db:
        device = await db.get(Device, "revoke-me")
        assert device.is_active is False
        assert device.revoked_at is not None
        other = await db.get(Device, "other-device")
        assert other.is_active is True
        assert other.revoked_at is None


@pytest.mark.asyncio
async def test_offboarding_disables_org_and_all_owned_devices_without_deleting_them():
    async with AsyncSessionLocal() as db:
        db.add(Device(id="offboard-device", org_id="test-tenant", name="offboard device", is_active=True))
        await db.commit()

    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/organizations/offboard")
        repeated = await client.post("/organizations/offboard")
        provision = await client.post("/devices/provision", json={"name": "must-not-provision"})

    assert response.status_code == 200
    assert response.json()["status"] == "offboarded"
    assert repeated.status_code == 200
    assert repeated.json()["already_offboarded"] is True
    assert provision.status_code == 409
    async with AsyncSessionLocal() as db:
        org = await db.get(Organization, "test-tenant")
        device = await db.get(Device, "offboard-device")
        assert org.status == "offboarded"
        assert device is not None
        assert device.is_active is False
        assert device.revoked_at is not None


@pytest.mark.asyncio
async def test_offboarded_organization_cannot_read_active_tenant_context():
    async with AsyncSessionLocal() as db:
        org = await db.get(Organization, "test-tenant")
        org.status = "offboarded"
        await db.commit()

    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/organizations/me")

    assert response.status_code == 200
    assert response.json()["status"] == "offboarded"
