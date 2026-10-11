"""Evidence-backed reporting, tenant scope, and immutable artifact tests."""
import hashlib
import json
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from core.database import AsyncSessionLocal
from models.report_artifact import ReportArtifact


@pytest.mark.asyncio
async def test_roi_report_uses_verified_tenant_and_persists_digest():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/reports/roi", json={"period_days": 30, "avg_hourly_rate_usd": 45})
    assert response.status_code == 200
    payload = response.json()
    assert payload["org_id"] == "test-tenant"
    assert payload["persisted"] is True
    assert len(payload["evidence_sha256"]) == 64
    assert payload["measured_savings"] is False
    assert payload["input_provenance"] == "tenant_scoped_database_aggregates_plus_disclosed_hourly_rate_assumption"

    async with AsyncSessionLocal() as db:
        artifact = await db.get(ReportArtifact, payload["evidence_artifact_id"])
    assert artifact is not None
    assert artifact.org_id == "test-tenant"
    assert artifact.report_type == "roi"
    assert artifact.payload_sha256 == payload["evidence_sha256"]
    canonical = json.dumps(artifact.report_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == artifact.payload_sha256
    assert artifact.input_provenance["query_scope"] == "verified_tenant_id"


@pytest.mark.asyncio
async def test_reporting_rejects_caller_supplied_org_and_metric_counts():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        roi = await client.post("/reports/roi", json={
            "org_id": "victim-tenant", "device_count": 100000,
            "tickets_resolved_ai": 100000, "tickets_total": 100000,
            "threats_blocked": 100000, "period_days": 30,
        })
        compliance = await client.post("/reports/compliance", json={
            "org_id": "victim-tenant", "device_count": 100000,
            "threats_blocked": 100000, "avg_resilience_score": 100,
            "tickets_resolved": 100000, "siem_active": True, "mfa_enabled": True,
        })
    assert roi.status_code == 422
    assert compliance.status_code == 422


@pytest.mark.asyncio
async def test_compliance_report_disclaims_certification_and_uses_verified_counts():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/reports/compliance", json={"framework": "DORA", "period_days": 7})
    assert response.status_code == 200
    payload = response.json()
    assert payload["org_id"] == "test-tenant"
    assert payload["certification_claim"] is False
    assert payload["score_semantics"] == "observed_control_evidence_score_not_legal_compliance_certification"
    assert payload["evidence_provenance"]["siem_provenance"] == "not_configured_or_not_tenant_verified"


@pytest.mark.asyncio
async def test_report_artifact_rejects_orm_mutation():
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/reports/summary")
    assert response.status_code == 200
    artifact_id = response.json()["evidence_artifact_id"]

    async with AsyncSessionLocal() as db:
        artifact = await db.get(ReportArtifact, artifact_id)
        assert artifact is not None
        artifact.report_payload = {"tampered": True}
        with pytest.raises(ValueError, match="append-only"):
            await db.commit()
        await db.rollback()
