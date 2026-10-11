"""Bounded retention tests for provenance-bearing telemetry evidence."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.telemetry_retention import TelemetryRetentionError, purge_expired_telemetry
from models.device import Device
from models.organization import Organization
from models.telemetry_record import TelemetryRecord


@pytest.mark.asyncio
async def test_retention_purge_deletes_only_expired_rows_for_bound_tenant():
    now = datetime.now(timezone.utc)
    device_id = "retention-device"
    async with AsyncSessionLocal() as db:
        if await db.get(Organization, "test-tenant") is None:
            db.add(Organization(id="test-tenant", name="Test Tenant", status="active"))
        db.add(Device(id=device_id, org_id="test-tenant", name=device_id))
        await db.flush()
        db.add_all([
            TelemetryRecord(
                id=str(uuid4()), org_id="test-tenant", device_id=device_id,
                event_id=str(uuid4()), schema_version="1", source="endpoint_agent",
                key_thumbprint="test-thumb", proof_jti=str(uuid4()), request_id="req-expired",
                request_hash="a" * 64, payload_hash="b" * 64,
                observed_at=now - timedelta(days=100), received_at=now - timedelta(days=100),
                metrics={"cpu_percent": 10}, missing_metrics=[], quality_flags=[],
                computed_score=90, score_components={"cpu": 90}, score_status="healthy",
                retention_expires_at=now - timedelta(seconds=1),
            ),
            TelemetryRecord(
                id=str(uuid4()), org_id="test-tenant", device_id=device_id,
                event_id=str(uuid4()), schema_version="1", source="endpoint_agent",
                key_thumbprint="test-thumb", proof_jti=str(uuid4()), request_id="req-live",
                request_hash="c" * 64, payload_hash="d" * 64,
                observed_at=now, received_at=now,
                metrics={"cpu_percent": 10}, missing_metrics=[], quality_flags=[],
                computed_score=90, score_components={"cpu": 90}, score_status="healthy",
                retention_expires_at=now + timedelta(days=30),
            ),
        ])
        await db.commit()

    async with AsyncSessionLocal() as db:
        db.info["tenant_id"] = "test-tenant"
        deleted = await purge_expired_telemetry(db, org_id="test-tenant", now=now, limit=10)
        await db.commit()
        remaining = list((await db.scalars(select(TelemetryRecord).where(
            TelemetryRecord.device_id == device_id
        ))).all())

    assert deleted == 1
    assert len(remaining) == 1
    assert remaining[0].request_id == "req-live"


@pytest.mark.asyncio
async def test_retention_purge_rejects_mismatched_tenant_session():
    async with AsyncSessionLocal() as db:
        db.info["tenant_id"] = "tenant-a"
        with pytest.raises(TelemetryRetentionError, match="tenant_session_mismatch"):
            await purge_expired_telemetry(db, org_id="tenant-b")


@pytest.mark.asyncio
async def test_retention_purge_bounds_batch_size_and_requires_aware_cutoff():
    async with AsyncSessionLocal() as db:
        db.info["tenant_id"] = "test-tenant"
        with pytest.raises(ValueError, match="between 1 and 1000"):
            await purge_expired_telemetry(db, org_id="test-tenant", limit=1001)
        with pytest.raises(ValueError, match="timezone-aware"):
            await purge_expired_telemetry(
                db, org_id="test-tenant", now=datetime(2026, 1, 1), limit=1
            )
