"""Tenant-scoped device registry and telemetry ingestion."""
from datetime import datetime, timezone
from uuid import uuid4
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_tenant_db
from models.device import Device
from models.organization import Organization
from resilience.scorer import score_device

router = APIRouter()


class TelemetryPayload(BaseModel):
    device_id: str = Field(min_length=1, max_length=128)
    cpu_percent: Optional[float] = Field(default=None, ge=0, le=100)
    memory_percent: Optional[float] = Field(default=None, ge=0, le=100)
    disk_percent: Optional[float] = Field(default=None, ge=0, le=100)
    boot_time: Optional[float] = Field(default=None, ge=0)


def _serialize(device: Device) -> dict:
    return {
        "id": device.id,
        "org_id": device.org_id,
        "name": device.name,
        "ip_address": device.ip_address,
        "os_type": device.os_type,
        "device_type": device.device_type,
        "is_active": device.is_active,
        "resilience_score": device.resilience_score,
        "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
        "enrolled_at": device.enrolled_at.isoformat() if device.enrolled_at else None,
        "revoked_at": device.revoked_at.isoformat() if device.revoked_at else None,
        "agent_version": device.agent_version,
        "agent_key_rotated_at": device.agent_key_rotated_at.isoformat() if device.agent_key_rotated_at else None,
    }


@router.get("/")
async def list_devices(request: Request, db: AsyncSession = Depends(get_tenant_db)):
    result = await db.scalars(
        select(Device).where(Device.org_id == request.state.tenant_id).order_by(Device.name, Device.id)
    )
    devices = [_serialize(item) for item in result.all()]
    return {"devices": devices, "total": len(devices)}



class ProvisionDevicePayload(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    ip_address: Optional[str] = Field(default=None, max_length=64)
    os_type: Optional[str] = Field(default=None, max_length=80)
    device_type: str = Field(default="server", min_length=1, max_length=80)


@router.post("/provision", status_code=201)
async def provision_device(
    payload: ProvisionDevicePayload,
    request: Request,
    db: AsyncSession = Depends(get_tenant_db),
):
    """Create an inactive device record; never equate provisioning with agent enrollment."""
    org = await db.scalar(
        select(Organization).where(
            Organization.id == request.state.tenant_id,
            Organization.status == "active",
        )
    )
    if org is None:
        raise HTTPException(status_code=409, detail="Active organization required")
    device = Device(
        id=str(uuid4()),
        org_id=org.id,
        name=payload.name.strip(),
        ip_address=payload.ip_address,
        os_type=payload.os_type,
        device_type=payload.device_type,
        is_active=False,
        enrolled_at=None,
    )
    db.add(device)
    await db.flush()
    return {"device": _serialize(device), "lifecycle_state": "provisioned_pending_agent_enrollment"}


@router.post("/{device_id}/revoke")
async def revoke_device(
    device_id: str,
    request: Request,
    db: AsyncSession = Depends(get_tenant_db),
):
    """Revoke a device within the current tenant; repeated revocation is idempotent."""
    device = await db.scalar(
        select(Device)
        .where(Device.id == device_id, Device.org_id == request.state.tenant_id)
        .with_for_update()
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.revoked_at is not None:
        return {"device_id": device.id, "is_active": False, "already_revoked": True}
    now = datetime.now(timezone.utc)
    device.is_active = False
    device.revoked_at = now
    await db.flush()
    return {"device_id": device.id, "is_active": False, "revoked_at": now.isoformat(), "revoked": True}

@router.post("/telemetry")
async def ingest_telemetry(
    payload: TelemetryPayload,
    request: Request,
    db: AsyncSession = Depends(get_tenant_db),
):
    """Accept telemetry only for an enrolled device owned by the authenticated tenant."""
    device = await db.scalar(
        select(Device).where(
            Device.id == payload.device_id,
            Device.org_id == request.state.tenant_id,
            Device.is_active.is_(True),
            Device.enrolled_at.is_not(None),
        )
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Enrolled device not found")

    telemetry = payload.model_dump(exclude={"device_id"}, exclude_none=True)
    score_result = await score_device(payload.device_id, telemetry)
    device.resilience_score = int(max(0, min(100, score_result["score"])))
    device.last_seen_at = datetime.now(timezone.utc)
    await db.flush()
    await db.commit()

    return {
        "device_id": device.id,
        "resilience": score_result,
        "stored": True,
        "persistence": "device_state_updated",
    }


@router.get("/{device_id}")
async def get_device(device_id: str, request: Request, db: AsyncSession = Depends(get_tenant_db)):
    device = await db.scalar(
        select(Device).where(Device.id == device_id, Device.org_id == request.state.tenant_id)
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return _serialize(device)
