"""Platform-bound endpoint-agent enrollment and telemetry."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from core.agent_auth import AgentIdentity, get_agent_identity, get_agent_tenant_db
from core.config import settings
from models.agent_request_replay import AgentRequestReplay
from models.device import Device
from models.durable_job import OutboxEvent
from models.telemetry_record import TelemetryRecord
from core.job_queue import enqueue_outbox_event
from resilience.scorer import score_device

router = APIRouter()


class AgentEnrollmentPayload(BaseModel):
    agent_version: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")


class AgentTelemetryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    event_id: UUID
    schema_version: Literal["1"] = "1"
    observed_at: datetime = Field(alias="timestamp")
    cpu_percent: float | None = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    memory_percent: float | None = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    disk_percent: float | None = Field(default=None, ge=0, le=100, allow_inf_nan=False)
    boot_time: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    process_count: int | None = Field(default=None, ge=0, le=1_000_000)
    platform: Literal["Linux", "Windows", "Darwin", "FreeBSD", "OpenBSD", "NetBSD", "Unknown"] | None = None

    @field_validator("observed_at")
    @classmethod
    def observed_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)


def _record_lifecycle_event(db: AsyncSession, identity: AgentIdentity, event_type: str, agent_version: str) -> None:
    """Write non-secret lifecycle evidence to the transactional outbox."""
    db.add(OutboxEvent(
        id=uuid4().hex,
        org_id=identity.tenant_id,
        aggregate_type="device",
        aggregate_id=identity.device_id,
        event_type=event_type,
        schema_version="1",
        idempotency_key=f"{event_type}:{identity.device_id}:{identity.proof_jti}",
        payload={
            "device_id": identity.device_id,
            "agent_version": agent_version,
            "key_thumbprint": identity.key_thumbprint,
            "request_hash": identity.request_hash,
        },
    ))


async def _consume_proof(db: AsyncSession, identity: AgentIdentity) -> None:
    now = datetime.now(timezone.utc)
    if settings.AGENT_REPLAY_RETENTION_SECONDS < settings.AGENT_DPOP_MAX_AGE_SECONDS + settings.AGENT_CLOCK_SKEW_SECONDS:
        raise HTTPException(status_code=503, detail="Agent replay retention is too short.")
    await db.execute(delete(AgentRequestReplay).where(
        AgentRequestReplay.org_id == identity.tenant_id,
        AgentRequestReplay.expires_at < now,
    ))
    db.add(AgentRequestReplay(
        jti=identity.proof_jti,
        org_id=identity.tenant_id,
        device_id=identity.device_id,
        request_hash=identity.request_hash,
        expires_at=now + timedelta(seconds=settings.AGENT_REPLAY_RETENTION_SECONDS),
    ))
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=401, detail="DPoP proof has already been used.") from exc


@router.post("/enroll")
async def enroll_agent(
    payload: AgentEnrollmentPayload,
    request: Request,
    identity: AgentIdentity = Depends(get_agent_identity),
    db: AsyncSession = Depends(get_agent_tenant_db),
):
    if "aurontra:agent:enroll" not in identity.scopes:
        raise HTTPException(status_code=403, detail="Agent enrollment scope is required.")
    device = await db.scalar(select(Device).where(
        Device.id == identity.device_id,
        Device.org_id == identity.tenant_id,
        Device.revoked_at.is_(None),
    ).with_for_update())
    if device is None:
        raise HTTPException(status_code=404, detail="Provisioned device not found.")
    if device.enrolled_at is not None or device.agent_key_thumbprint is not None:
        raise HTTPException(status_code=409, detail="Device is already enrolled.")
    await _consume_proof(db, identity)
    now = datetime.now(timezone.utc)
    device.agent_key_thumbprint = identity.key_thumbprint
    device.agent_version = payload.agent_version
    device.enrolled_at = now
    device.is_active = True
    _record_lifecycle_event(db, identity, "agent.enrolled", device.agent_version)
    await db.flush()
    return {"device_id": device.id, "lifecycle_state": "enrolled", "is_active": True,
            "enrolled_at": now.isoformat(), "agent_version": device.agent_version}


@router.post("/rotate-key")
async def rotate_agent_key(
    payload: AgentEnrollmentPayload,
    identity: AgentIdentity = Depends(get_agent_identity),
    db: AsyncSession = Depends(get_agent_tenant_db),
):
    if "aurontra:agent:key:rotate" not in identity.scopes:
        raise HTTPException(status_code=403, detail="Agent key-rotation scope is required.")
    device = await db.scalar(select(Device).where(
        Device.id == identity.device_id,
        Device.org_id == identity.tenant_id,
        Device.is_active.is_(True),
        Device.enrolled_at.is_not(None),
        Device.revoked_at.is_(None),
    ).with_for_update())
    if device is None:
        raise HTTPException(status_code=404, detail="Enrolled device not found.")
    if device.agent_key_thumbprint == identity.key_thumbprint:
        raise HTTPException(status_code=409, detail="The presented key is already enrolled.")
    await _consume_proof(db, identity)
    now = datetime.now(timezone.utc)
    device.agent_key_thumbprint = identity.key_thumbprint
    device.agent_key_rotated_at = now
    device.agent_version = payload.agent_version
    _record_lifecycle_event(db, identity, "agent.key_rotated", device.agent_version)
    await db.flush()
    return {"device_id": device.id, "lifecycle_state": "key_rotated",
            "key_thumbprint": identity.key_thumbprint, "key_rotated_at": now.isoformat(),
            "agent_version": device.agent_version}


@router.post("/telemetry")
async def ingest_agent_telemetry(
    payload: AgentTelemetryPayload,
    request: Request,
    identity: AgentIdentity = Depends(get_agent_identity),
    db: AsyncSession = Depends(get_agent_tenant_db),
):
    """Persist validated telemetry as provenance-bearing, idempotent evidence."""
    if "aurontra:telemetry:write" not in identity.scopes:
        raise HTTPException(status_code=403, detail="Telemetry write scope is required.")
    metric_names = ("cpu_percent", "memory_percent", "disk_percent")
    metrics = {name: getattr(payload, name) for name in metric_names if getattr(payload, name) is not None}
    if not metrics:
        raise HTTPException(status_code=422, detail="At least one CPU, memory, or disk metric is required.")

    now = datetime.now(timezone.utc)
    if (
        settings.TELEMETRY_MAX_AGE_SECONDS < 1
        or settings.TELEMETRY_FUTURE_SKEW_SECONDS < 0
        or not 1 <= settings.TELEMETRY_RETENTION_DAYS <= 3650
    ):
        raise HTTPException(status_code=503, detail="Telemetry freshness or retention configuration is invalid.")
    if payload.observed_at > now + timedelta(seconds=settings.TELEMETRY_FUTURE_SKEW_SECONDS):
        raise HTTPException(status_code=422, detail="Telemetry timestamp is too far in the future.")
    if (now - payload.observed_at).total_seconds() > settings.TELEMETRY_MAX_AGE_SECONDS:
        raise HTTPException(status_code=422, detail="Telemetry is stale; it cannot update current device state.")

    device = await db.scalar(select(Device).where(
        Device.id == identity.device_id,
        Device.org_id == identity.tenant_id,
        Device.is_active.is_(True),
        Device.enrolled_at.is_not(None),
        Device.revoked_at.is_(None),
        Device.agent_key_thumbprint == identity.key_thumbprint,
    ).with_for_update())
    if device is None:
        raise HTTPException(status_code=404, detail="Enrolled device not found.")

    metadata = {
        "boot_time": payload.boot_time,
        "process_count": payload.process_count,
        "platform": payload.platform,
    }
    telemetry_values = {**metrics, **{key: value for key, value in metadata.items() if value is not None}}
    canonical = {
        "event_id": str(payload.event_id),
        "schema_version": payload.schema_version,
        "observed_at": payload.observed_at.isoformat(),
        "metrics": telemetry_values,
    }
    payload_hash = sha256(json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")).hexdigest()

    # Consume each DPoP proof even when the event ID conflicts. A JSON response
    # (rather than an exception) lets the request transaction commit the replay
    # record, so the same rejected proof cannot be retried indefinitely.
    await _consume_proof(db, identity)
    existing = await db.scalar(select(TelemetryRecord).where(
        TelemetryRecord.org_id == identity.tenant_id,
        TelemetryRecord.device_id == identity.device_id,
        TelemetryRecord.event_id == str(payload.event_id),
    ).with_for_update())
    if existing is not None:
        if existing.payload_hash != payload_hash:
            return JSONResponse(
                status_code=409,
                content={"detail": "Telemetry event ID already exists with different content."},
            )
        return {
            "device_id": device.id,
            "event_id": existing.event_id,
            "telemetry_id": existing.id,
            "stored": True,
            "duplicate": True,
            "current_state_updated": False,
            "persistence": "idempotent_duplicate",
            "observed_at": existing.observed_at.isoformat(),
            "received_at": existing.received_at.isoformat(),
            "quality_flags": existing.quality_flags,
        }

    if settings.TELEMETRY_MAX_EVENTS_PER_MINUTE < 1:
        raise HTTPException(status_code=503, detail="Telemetry rate-limit configuration is invalid.")
    recent_count = await db.scalar(select(func.count()).select_from(TelemetryRecord).where(
        TelemetryRecord.org_id == identity.tenant_id,
        TelemetryRecord.device_id == identity.device_id,
        TelemetryRecord.received_at >= now - timedelta(seconds=60),
    ))
    if int(recent_count or 0) >= settings.TELEMETRY_MAX_EVENTS_PER_MINUTE:
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": "60"},
            content={"detail": "Device telemetry rate limit exceeded.", "code": "TELEMETRY_RATE_LIMITED"},
        )

    latest = await db.scalar(select(TelemetryRecord).where(
        TelemetryRecord.org_id == identity.tenant_id,
        TelemetryRecord.device_id == identity.device_id,
    ).order_by(TelemetryRecord.observed_at.desc(), TelemetryRecord.received_at.desc()).limit(1))
    quality_flags = []
    missing_metrics = [name for name in metric_names if name not in metrics]
    if missing_metrics:
        quality_flags.append("partial_metrics")
    if payload.observed_at > now:
        quality_flags.append("agent_clock_ahead_within_skew")
    out_of_order = latest is not None and payload.observed_at < latest.observed_at
    if out_of_order:
        quality_flags.append("out_of_order")

    score_result = await score_device(device.id, metrics)
    # A partial sample may be useful evidence, but must not be converted into a
    # healthy-looking composite score or overwrite the device's current score.
    complete_metrics = not missing_metrics
    if not complete_metrics:
        score_result = {
            "device_id": device.id,
            "score": None,
            "status": "insufficient_data",
            "components": score_result.get("components", {}),
            "missing_metrics": missing_metrics,
        }
    request_id = request.headers.get("X-Request-ID", "")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", request_id):
        request_id = uuid4().hex
    record = TelemetryRecord(
        id=str(uuid4()),
        org_id=identity.tenant_id,
        device_id=identity.device_id,
        event_id=str(payload.event_id),
        schema_version=payload.schema_version,
        source="endpoint_agent",
        agent_version=device.agent_version,
        key_thumbprint=identity.key_thumbprint,
        proof_jti=identity.proof_jti,
        request_id=request_id,
        request_hash=identity.request_hash,
        payload_hash=payload_hash,
        observed_at=payload.observed_at,
        received_at=now,
        metrics=telemetry_values,
        missing_metrics=missing_metrics,
        quality_flags=quality_flags,
        computed_score=(
            int(max(0, min(100, score_result["score"])))
            if complete_metrics and score_result.get("score") is not None else None
        ),
        score_components=score_result.get("components", {}),
        score_status=score_result.get("status", "unknown"),
        retention_expires_at=now + timedelta(days=settings.TELEMETRY_RETENTION_DAYS),
    )
    db.add(record)
    device.last_seen_at = now
    current_state_updated = not out_of_order and complete_metrics
    if current_state_updated and record.computed_score is not None:
        device.resilience_score = record.computed_score
    await db.flush()
    await enqueue_outbox_event(
        db,
        org_id=identity.tenant_id,
        aggregate_type="device",
        aggregate_id=device.id,
        event_type="telemetry.accepted",
        idempotency_key=f"telemetry:{identity.tenant_id}:{device.id}:{payload.event_id}:accepted",
        payload={
            "telemetry_id": record.id,
            "event_id": record.event_id,
            "device_id": device.id,
            "schema_version": record.schema_version,
            "observed_at": record.observed_at.isoformat(),
            "received_at": record.received_at.isoformat(),
            "payload_hash": record.payload_hash,
            "quality_flags": quality_flags,
            "computed_score": record.computed_score,
            "current_state_updated": current_state_updated,
        },
    )
    return {
        "device_id": device.id,
        "event_id": record.event_id,
        "telemetry_id": record.id,
        "resilience": score_result,
        "stored": True,
        "duplicate": False,
        "current_state_updated": not out_of_order,
        "persistence": "telemetry_evidence_recorded",
        "observed_at": record.observed_at.isoformat(),
        "received_at": record.received_at.isoformat(),
        "quality_flags": quality_flags,
        "missing_metrics": missing_metrics,
        "retention_expires_at": record.retention_expires_at.isoformat(),
    }
