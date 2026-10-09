"""
Integration tests for API routes.
RED → GREEN cycle.
"""
import pytest
from httpx import AsyncClient, ASGITransport


@pytest.fixture
async def client():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


class TestHealthRoutes:
    @pytest.mark.asyncio
    async def test_health_returns_200(self, client):
        r = await client.get("/health/")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_health_returns_status_ok(self, client):
        r = await client.get("/health/")
        data = r.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_health_includes_version(self, client):
        r = await client.get("/health/")
        data = r.json()
        assert "version" in data

    @pytest.mark.asyncio
    async def test_health_includes_bridges_status(self, client):
        r = await client.get("/health/")
        data = r.json()
        assert "bridges" in data

    @pytest.mark.asyncio
    async def test_readiness_endpoint_exists(self, client):
        r = await client.get("/health/ready")
        assert r.status_code in (200, 503)

    @pytest.mark.asyncio
    async def test_liveness_endpoint_exists(self, client):
        r = await client.get("/health/live")
        assert r.status_code == 200


class TestTicketRoutes:
    @pytest.mark.asyncio
    async def test_tickets_list_returns_200(self, client):
        r = await client.get("/tickets/")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_tickets_ingest_accepts_post(self, client):
        r = await client.post("/tickets/ingest", json={
            "title": "VPN not connecting",
            "description": "Cannot connect to VPN since 9am.",
            "reporter_email": "james@corp.com",
            "source": "email",
        })
        assert r.status_code in (200, 201, 422)

    @pytest.mark.asyncio
    async def test_devices_list_returns_200(self, client):
        r = await client.get("/devices/")
        assert r.status_code == 200
