"""Tenant-scoped device registry and telemetry ingestion."""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_tenant_db
from models.device import Device
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
    }


@router.get("/")
async def list_devices(request: Request, db: AsyncSession = Depends(get_tenant_db)):
    result = await db.scalars(
        select(Device).where(Device.org_id == request.state.tenant_id).order_by(Device.name, Device.id)
    )
    devices = [_serialize(item) for item in result.all()]
    return {"devices": devices, "total": len(devices)}


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
