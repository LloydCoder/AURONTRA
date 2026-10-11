"""Platform-bound endpoint-agent enrollment and telemetry."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from core.agent_auth import AgentIdentity, get_agent_identity, get_agent_tenant_db
from core.config import settings
from models.agent_request_replay import AgentRequestReplay
from models.device import Device
from resilience.scorer import score_device

router = APIRouter()


class AgentEnrollmentPayload(BaseModel):
    agent_version: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")


class AgentTelemetryPayload(BaseModel):
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    memory_percent: float | None = Field(default=None, ge=0, le=100)
    disk_percent: float | None = Field(default=None, ge=0, le=100)
    boot_time: float | None = Field(default=None, ge=0)


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
    await db.flush()
    return {"device_id": device.id, "lifecycle_state": "enrolled", "is_active": True,
            "enrolled_at": now.isoformat(), "agent_version": device.agent_version}


@router.post("/telemetry")
async def ingest_agent_telemetry(
    payload: AgentTelemetryPayload,
    request: Request,
    identity: AgentIdentity = Depends(get_agent_identity),
    db: AsyncSession = Depends(get_tenant_db),
):
    if "aurontra:telemetry:write" not in identity.scopes:
        raise HTTPException(status_code=403, detail="Telemetry write scope is required.")
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
    await _consume_proof(db, identity)
    telemetry = payload.model_dump(exclude_none=True)
    score_result = await score_device(device.id, telemetry)
    now = datetime.now(timezone.utc)
    device.resilience_score = int(max(0, min(100, score_result["score"])))
    device.last_seen_at = now
    await db.flush()
    return {"device_id": device.id, "resilience": score_result, "stored": True,
            "persistence": "device_state_updated", "observed_at": now.isoformat()}
