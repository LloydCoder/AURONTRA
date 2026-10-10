"""Regression tests for tenant-scoped route lookups and device ownership."""
import pytest
from httpx import ASGITransport, AsyncClient

from core.database import AsyncSessionLocal
from models.device import Device
from models.organization import Organization
from models.ticket import Ticket, TicketPriority, TicketSource, TicketStatus


@pytest.mark.asyncio
async def test_ticket_list_and_detail_never_disclose_another_tenant():
    async with AsyncSessionLocal() as session:
        session.add(Organization(id="other-tenant", name="Other Tenant", status="active"))
        session.add(Ticket(
            id="private-ticket",
            org_id="other-tenant",
            title="Private ticket",
            description="Must not be visible cross-tenant",
            reporter_email="private@example.invalid",
            source=TicketSource.MANUAL,
            priority=TicketPriority.HIGH,
            status=TicketStatus.OPEN,
        ))
        await session.commit()

    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        listed = await client.get("/tickets/")
        detail = await client.get("/tickets/private-ticket")

    assert listed.status_code == 200
    assert all(item["id"] != "private-ticket" for item in listed.json()["tickets"])
    assert detail.status_code == 404


@pytest.mark.asyncio
async def test_ticket_cannot_attach_device_owned_by_another_tenant():
    async with AsyncSessionLocal() as session:
        session.add(Organization(id="other-tenant", name="Other Tenant", status="active"))
        session.add(Device(id="private-device", org_id="other-tenant", name="Private device"))
        await session.commit()

    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/tickets/ingest", json={
            "title": "Cross tenant reference",
            "description": "Should be rejected",
            "reporter_email": "user@example.invalid",
            "device_id": "private-device",
        })

    assert response.status_code == 404
    assert response.json()["detail"] == "Device not found"


@pytest.mark.asyncio
async def test_telemetry_cannot_update_device_owned_by_another_tenant():
    async with AsyncSessionLocal() as session:
        session.add(Organization(id="other-tenant", name="Other Tenant", status="active"))
        session.add(Device(
            id="private-device",
            org_id="other-tenant",
            name="Private device",
            resilience_score=71,
        ))
        await session.commit()

    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/devices/telemetry", json={
            "device_id": "private-device",
            "cpu_percent": 99,
        })

    assert response.status_code == 404
    async with AsyncSessionLocal() as session:
        device = await session.get(Device, "private-device")
        assert device.resilience_score == 71
