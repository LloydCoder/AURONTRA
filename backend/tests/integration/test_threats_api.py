"""
Sprint 3 — Threat API integration tests.
RED phase.
"""
import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport


@pytest.fixture
async def client():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


class TestThreatsAPI:

    @pytest.mark.asyncio
    async def test_threats_list_returns_200(self, client):
        r = await client.get("/threats/")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_threats_analyse_endpoint_exists(self, client):
        r = await client.post("/threats/analyse", json={
            "src_ip": "185.220.101.47",
            "protocol": "QUIC",
            "entropy": 7.82,
            "z_score": 14.76,
        })
        assert r.status_code in (200, 201)

    @pytest.mark.asyncio
    async def test_threats_analyse_returns_threat_level(self, client):
        r = await client.post("/threats/analyse", json={
            "src_ip": "185.220.101.47",
            "protocol": "QUIC",
            "entropy": 7.82,
            "z_score": 14.76,
        })
        data = r.json()
        assert "threat_level" in data
        assert data["threat_level"] in ("info", "low", "medium", "high", "critical")

    @pytest.mark.asyncio
    async def test_threats_analyse_returns_mitre_ttp(self, client):
        r = await client.post("/threats/analyse", json={
            "src_ip": "10.0.2.15",
            "protocol": "HTTPS",
            "entropy": 6.9,
            "z_score": 7.01,
        })
        data = r.json()
        assert "mitre_ttp" in data

    @pytest.mark.asyncio
    async def test_threats_block_endpoint_exists(self, client):
        mock_result = {
            "event_id": "evt-test-001",
            "blocked": True,
            "threat_level": "high",
            "action_taken": "blocked",
            "mitre_ttp": "T1071.001",
            "src_ip": "185.220.101.47",
        }
        with patch("api.routes.threats.block_threat", new_callable=AsyncMock) as mock_block:
            mock_block.return_value = mock_result
            r = await client.post("/threats/block", json={
                "src_ip": "185.220.101.47",
                "scenario": "c2_beacon",
                "org_id": "org-001",
            })
        assert r.status_code in (200, 201)

    @pytest.mark.asyncio
    async def test_threats_events_endpoint_returns_list(self, client):
        with patch("api.routes.threats.get_events", new_callable=AsyncMock) as mock_events:
            mock_events.return_value = [
                {"event": "c2_detected", "ip": "1.2.3.4"},
                {"event": "ticket_resolved", "id": "tkt-001"},
            ]
            r = await client.get("/threats/events")
        assert r.status_code == 200
        data = r.json()
        assert "events" in data

    @pytest.mark.asyncio
    async def test_threats_siem_export_endpoint(self, client):
        r = await client.post("/threats/export/siem", json={
            "event_id": "evt-001",
            "src_ip": "185.220.101.47",
            "threat_level": "critical",
            "mitre_ttp": "T1071.001",
            "blocked": True,
            "timestamp": "2026-06-20T12:00:00Z",
            "format": "json",
        })
        assert r.status_code in (200, 201)
        data = r.json()
        assert "format" in data

    @pytest.mark.asyncio
    async def test_threats_siem_export_splunk(self, client):
        r = await client.post("/threats/export/siem", json={
            "event_id": "evt-002",
            "src_ip": "10.0.2.15",
            "threat_level": "high",
            "mitre_ttp": "T1059",
            "blocked": True,
            "timestamp": "2026-06-20T12:01:00Z",
            "format": "splunk_hec",
        })
        assert r.status_code in (200, 201)

    @pytest.mark.asyncio
    async def test_threats_siem_export_cef(self, client):
        r = await client.post("/threats/export/siem", json={
            "event_id": "evt-003",
            "src_ip": "5.5.5.5",
            "threat_level": "high",
            "mitre_ttp": "T1027",
            "blocked": False,
            "timestamp": "2026-06-20T12:02:00Z",
            "format": "cef",
        })
        assert r.status_code in (200, 201)
