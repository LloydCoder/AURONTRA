"""
Sprint 3 — Threat API integration tests.
RED phase.
"""
import pytest
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
    async def test_threats_block_endpoint_fails_closed_until_enforcement_exists(self, client):
        r = await client.post("/threats/block", json={
            "src_ip": "185.220.101.47",
            "scenario": "c2_beacon",
            "org_id": "org-001",
        })
        assert r.status_code == 503
        assert "containment is disabled" in r.json()["detail"]

    @pytest.mark.asyncio
    async def test_threats_events_endpoint_returns_tenant_scoped_durable_findings(self, client):
        created = await client.post("/threats/analyse", json={
            "event_id": "events-list-test",
            "src_ip": "192.0.2.10",
            "protocol": "QUIC",
            "entropy": 7.0,
        })
        assert created.status_code == 200
        r = await client.get("/threats/events")
        assert r.status_code == 200
        data = r.json()
        assert data["source"] == "aurontra_durable_evidence"
        assert any(item["event_id"] == "events-list-test" for item in data["events"])
        assert all(item["containment_verified"] is False for item in data["events"])

    @pytest.mark.asyncio
    async def test_threats_siem_export_endpoint(self, client):
        r = await client.post("/threats/export/siem", json={
            "event_id": "evt-001",
            "src_ip": "185.220.101.47",
            "threat_level": "critical",
            "mitre_ttp": "T1071.001",
            "blocked": True,
            "action_taken": "blocked",
            "timestamp": "2026-06-20T12:00:00Z",
            "format": "json",
        })
        assert r.status_code in (200, 201)
        data = r.json()
        assert "format" in data
        assert data["payload"]["blocked"] is False
        assert data["payload"]["containment_verified"] is False

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


    @pytest.mark.asyncio
    async def test_threat_containment_endpoint_is_closed_by_default(self, client, monkeypatch):
        from core.config import settings
        monkeypatch.setattr(settings, "THREAT_CONTAINMENT_ENABLED", False)
        r = await client.post("/threats/findings/not-a-real-finding/contain")
        assert r.status_code == 503
        assert r.json()["detail"] == "containment_disabled"
