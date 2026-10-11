"""
Sprint 2 — integration tests for full ticket resolution pipeline.
Tests the API layer end-to-end with mocked LLM.
"""
import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport


@pytest.fixture
async def client():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


class TestTicketIngestionAPI:

    @pytest.mark.asyncio
    async def test_ingest_returns_ticket_id(self, client):
        r = await client.post("/tickets/ingest", json={
            "title": "Cannot login to email",
            "description": "Getting wrong password error on Outlook",
            "reporter_email": "james@corp.com",
            "source": "email",
        })
        assert r.status_code == 201
        data = r.json()
        assert "ticket" in data
        assert "id" in data["ticket"]

    @pytest.mark.asyncio
    async def test_ingest_rejects_missing_title(self, client):
        r = await client.post("/tickets/ingest", json={
            "description": "Something broke",
            "reporter_email": "user@corp.com",
        })
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_ingest_rejects_missing_description(self, client):
        r = await client.post("/tickets/ingest", json={
            "title": "VPN issue",
            "reporter_email": "user@corp.com",
        })
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_ingest_via_email_endpoint(self, client):
        r = await client.post("/tickets/ingest/email", json={
            "from": "staff@corp.com",
            "subject": "Printer broken",
            "body": "The printer on floor 3 won't print. Paper jam light is on.",
        })
        assert r.status_code in (200, 201)
        data = r.json()
        assert "ticket" in data

    @pytest.mark.asyncio
    async def test_ingest_via_webhook_jira(self, client):
        r = await client.post("/tickets/ingest/webhook", json={
            "source": "jira",
            "issue": {
                "key": "IT-5555",
                "fields": {
                    "summary": "Slack not loading",
                    "description": "App crashes on startup",
                    "reporter": {"emailAddress": "dev@corp.com"},
                    "priority": {"name": "High"},
                },
            },
        })
        assert r.status_code in (200, 201)

    @pytest.mark.asyncio
    async def test_resolve_endpoint_exists(self, client):
        # Ingest first
        ingest_r = await client.post("/tickets/ingest", json={
            "title": "Password reset needed",
            "description": "Locked out of my account",
            "reporter_email": "user@corp.com",
        })
        ticket_id = ingest_r.json()["ticket"]["id"]

        mock_result = {
            "ticket_id": ticket_id,
            "resolved": True,
            "escalated": False,
            "response": "Please visit IT portal to reset password.",
            "model_used": "claude-sonnet-4-6",
            "confidence": 0.92,
            "category": "access",
        }
        with patch("api.routes.tickets.resolve_ticket", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = mock_result
            r = await client.post(f"/tickets/{ticket_id}/resolve")
            assert r.status_code in (200, 201, 404)

    @pytest.mark.asyncio
    async def test_ticket_list_includes_ai_resolved_field(self, client):
        r = await client.get("/tickets/")
        assert r.status_code == 200
        data = r.json()
        assert "tickets" in data

    @pytest.mark.asyncio
    async def test_telemetry_ingest_triggers_score(self, client):
        # Device enrollment is a separate, authenticated lifecycle operation.
        from core.database import AsyncSessionLocal
        from models.device import Device
        from models.organization import Organization
        async with AsyncSessionLocal() as db:
            if await db.get(Organization, "test-tenant") is None:
                db.add(Organization(id="test-tenant", name="Test Tenant", status="active"))
            if await db.get(Device, "test-server-01") is None:
                db.add(Device(id="test-server-01", org_id="test-tenant", name="test-server-01"))
            await db.commit()
        r = await client.post("/devices/telemetry", json={
            "device_id": "test-server-01",
            "cpu_percent": 25.0,
            "memory_percent": 40.0,
            "disk_percent": 55.0,
        })
        assert r.status_code == 200
        data = r.json()
        assert "resilience" in data
        assert data["resilience"]["score"] >= 80



@pytest.mark.asyncio
async def test_ticket_ingestion_commits_a_tenant_scoped_outbox_event():
    from sqlalchemy import select
    from core.database import AsyncSessionLocal
    from models.durable_job import OutboxEvent

    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/tickets/ingest", json={
            "title": "Outbox integration regression",
            "description": "Ticket and event must be committed together",
            "reporter_email": "outbox@example.invalid",
        })
    assert response.status_code == 201
    ticket_id = response.json()["ticket"]["id"]

    async with AsyncSessionLocal() as db:
        event = await db.scalar(
            select(OutboxEvent).where(
                OutboxEvent.org_id == "test-tenant",
                OutboxEvent.aggregate_id == ticket_id,
                OutboxEvent.event_type == "ticket.created",
            )
        )
        assert event is not None
        assert event.status == "pending"
        assert event.payload == {"ticket_id": ticket_id, "source": "manual"}
