"""Devices router — device registry and telemetry ingestion."""
import uuid
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from resilience.scorer import score_device

router = APIRouter()

_devices: dict[str, dict] = {}


class TelemetryPayload(BaseModel):
    device_id: str
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    disk_percent: Optional[float] = None
    boot_time: Optional[float] = None


@router.get("/")
async def list_devices():
    """List all registered devices."""
    return {"devices": list(_devices.values()), "total": len(_devices)}


@router.post("/telemetry")
async def ingest_telemetry(payload: TelemetryPayload):
    """
    Receive telemetry from the lightweight device agent.
    Computes resilience score and upserts device record.
    """
    telemetry = payload.model_dump(exclude={"device_id"}, exclude_none=True)
    score_result = await score_device(payload.device_id, telemetry)

    device = _devices.get(payload.device_id, {
        "id": payload.device_id,
        "name": payload.device_id,
    })
    device.update({
        "resilience_score": score_result["score"],
        "resilience_status": score_result["status"],
        "last_telemetry": telemetry,
    })
    _devices[payload.device_id] = device

    return {
        "device_id": payload.device_id,
        "resilience": score_result,
        "stored": True,
    }


@router.get("/{device_id}")
async def get_device(device_id: str):
    """Get a single device's current state."""
    from fastapi import HTTPException
    if device_id not in _devices:
        raise HTTPException(status_code=404, detail="Device not found")
    return _devices[device_id]
