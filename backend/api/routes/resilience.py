"""
Resilience router — Sprint 4.
Score, predict, history endpoints.
Powered by Isolation Forest + TemporalCorrelator.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from resilience.scorer import score_device
from resilience.temporal import TemporalCorrelator

router = APIRouter()

# In-memory telemetry history store per device — replaced by DB in Sprint 5
_device_history: dict[str, list[dict]] = {}
_MAX_HISTORY = 200  # readings per device


class ScoreRequest(BaseModel):
    device_id: str
    telemetry: dict


class PredictRequest(BaseModel):
    device_id: str
    history: list[dict]


@router.get("/")
async def resilience_overview():
    return {
        "status": "ok",
        "devices_tracked": len(_device_history),
        "total_readings": sum(len(v) for v in _device_history.values()),
    }


@router.post("/score")
async def compute_score(payload: ScoreRequest):
    """Compute resilience score for a device from raw telemetry."""
    result = await score_device(payload.device_id, payload.telemetry)

    # Store reading in history
    history = _device_history.setdefault(payload.device_id, [])
    history.append(payload.telemetry)
    if len(history) > _MAX_HISTORY:
        history.pop(0)

    return result


@router.post("/predict")
async def predict_resilience(payload: PredictRequest):
    """
    Predict 72-hour resilience score from historical telemetry.
    Uses TemporalCorrelator for trend + projection.
    """
    if len(payload.history) < 2:
        raise HTTPException(
            status_code=422,
            detail="At least 2 historical readings required for prediction."
        )

    tc = TemporalCorrelator()
    try:
        result = tc.analyse(payload.history)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return {
        "device_id": payload.device_id,
        **result,
    }


@router.get("/history/{device_id}")
async def get_device_history(device_id: str, limit: int = 50):
    """Return stored telemetry history for a device."""
    history = _device_history.get(device_id, [])
    return {
        "device_id": device_id,
        "readings": history[-limit:],
        "total": len(history),
    }
