"""Integration tests for durable, tenant-scoped threat evidence."""
import hashlib
import json

import pytest
from httpx import ASGITransport, AsyncClient

from core.database import AsyncSessionLocal
from models.organization import Organization
from models.threat_finding import ThreatFinding


def _canonical_hash(value):
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@pytest.mark.asyncio
async def test_analysis_persists_immutable_evidence_and_score_components():
    from main import app
    signal = {
        "source_event_id": "event-threat-001",
        "src_ip": "185.220.101.47",
        "protocol": "quic",
        "entropy": 7.82,
        "z_score": 14.76,
        "dst_port": 443,
        "bytes_out": 48200,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/threats/analyse", json=signal)

    assert response.status_code == 200
    payload = response.json()
    finding = payload["finding"]
    evidence = {key: value for key, value in signal.items() if key != "source_event_id"}
    evidence["protocol"] = "QUIC"
    assert finding["org_id"] if "org_id" in finding else True
    assert finding["source_event_id"] == "event-threat-001"
    assert finding["score"] >= 70
    assert sum(finding["score_components"].values()) == finding["score"]
    assert finding["evidence_sha256"] == _canonical_hash(evidence)
    assert finding["score_semantics"] == "heuristic_0_to_100_not_probability"
    assert finding["detector_version"] == "heuristic-threat-score.v2"
    assert finding["containment_verified"] is False
    assert finding["status"] == "review_required"
    assert payload["auto_block"] is False
    assert payload["idempotent_replay"] is False

    async with AsyncSessionLocal() as db:
        saved = await db.get(ThreatFinding, finding["id"])
        assert saved is not None
        assert saved.org_id == "test-tenant"
        assert saved.containment_verified is False
        assert saved.evidence_sha256 == finding["evidence_sha256"]


@pytest.mark.asyncio
async def test_source_event_id_is_idempotent_and_rejects_changed_evidence():
    from main import app
    body = {
        "source_event_id": "source-idempotent-001",
        "src_ip": "192.0.2.10",
        "protocol": "HTTPS",
        "entropy": 2.5,
        "z_score": 0.5,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/threats/analyse", json=body)
        replay = await client.post("/threats/analyse", json=body)
        changed = await client.post("/threats/analyse", json={**body, "entropy": 3.5})

    assert first.status_code == 200
    assert replay.status_code == 200
    assert first.json()["finding"]["id"] == replay.json()["finding"]["id"]
    assert replay.json()["idempotent_replay"] is True
    assert changed.status_code == 409


@pytest.mark.asyncio
async def test_signal_validation_rejects_invalid_ip_ranges_and_tenant_override():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bad_ip = await client.post("/threats/analyse", json={"src_ip": "attacker.example"})
        bad_entropy = await client.post("/threats/analyse", json={"entropy": 9.0})
        tenant_override = await client.post("/threats/analyse", json={"org_id": "other-tenant", "entropy": 1.0})

    assert bad_ip.status_code == 422
    assert bad_entropy.status_code == 422
    assert tenant_override.status_code == 422


@pytest.mark.asyncio
async def test_findings_list_is_tenant_scoped_and_containment_is_disabled():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = await client.post("/threats/analyse", json={
            "source_event_id": "tenant-a-finding",
            "src_ip": "192.0.2.21",
            "protocol": "HTTPS",
            "entropy": 2.0,
            "z_score": 0.1,
        })
        assert created.status_code == 200

    async with AsyncSessionLocal() as db:
        db.add(Organization(id="other-threat-tenant", name="Other Threat Tenant", status="active"))
        await db.commit()
        db.add(ThreatFinding(
            org_id="other-threat-tenant",
            source_event_id="tenant-b-finding",
            src_ip="192.0.2.22",
            protocol="HTTPS",
            threat_level="info",
            score=0,
            score_components={
                "z_score_points": 0,
                "entropy_points": 0,
                "protocol_risk_points": 0,
                "periodicity_points": 0,
            },
            mitre_ttp="T1071",
            reason="test",
            evidence_sha256="a" * 64,
            evidence={"protocol": "HTTPS"},
            containment_recommended=False,
            containment_verified=False,
            status="assessed",
        ))
        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        listed = await client.get("/threats/findings")
        overview = await client.get("/threats/")

    assert listed.status_code == 200
    assert len(listed.json()["findings"]) == 1
    assert listed.json()["findings"][0]["source_event_id"] == "tenant-a-finding"
    assert listed.json()["containment_verified"] is False
    assert overview.json()["total_events"] == 1
    assert overview.json()["containment_enabled"] is False


@pytest.mark.asyncio
async def test_block_endpoint_stays_fail_closed():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/threats/block", json={
            "src_ip": "192.0.2.30",
            "scenario": "c2_beacon",
            "org_id": "test-tenant",
        })
    assert response.status_code == 503
