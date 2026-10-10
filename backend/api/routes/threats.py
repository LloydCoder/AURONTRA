"""
Threats router — analysis and export.

Analysis produces signals and decisions; it does not itself enforce a firewall,
quarantine an endpoint, or prove that traffic was stopped. Public containment
is disabled until enforcement and post-action verification exist.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from agents.threat_blocker import analyse_signal, export_siem
from bridges.threatfade import get_events

router = APIRouter()
_threat_events: list[dict] = []


class SignalAnalyseRequest(BaseModel):
    src_ip: Optional[str] = None
    protocol: Optional[str] = None
    entropy: Optional[float] = None
    z_score: Optional[float] = None
    beacon_interval: Optional[int] = None
    jitter: Optional[float] = None
    bytes_out: Optional[int] = None


class BlockRequest(BaseModel):
    src_ip: str
    scenario: str
    org_id: str = "default"


class SIEMExportRequest(BaseModel):
    event_id: str
    src_ip: str
    threat_level: str
    mitre_ttp: str
    blocked: bool
    timestamp: str
    format: str = "json"
    reason: Optional[str] = None
    action_taken: Optional[str] = "monitor"


@router.get("/")
async def threats_overview():
    contained = sum(1 for event in _threat_events if event.get("status") == "contained")
    return {
        "status": "ok",
        "total_events": len(_threat_events),
        "contained": contained,
        "containment_enabled": False,
        "note": "Detection and analysis do not establish successful containment.",
    }


@router.post("/analyse")
async def analyse_threat(payload: SignalAnalyseRequest):
    """Return risk analysis only; no enforcement action is taken."""
    return analyse_signal(payload.model_dump(exclude_none=True))


@router.post("/block", status_code=503)
async def block_threat_endpoint(payload: BlockRequest):
    """Fail closed until real enforcement and verification are implemented."""
    raise HTTPException(
        status_code=503,
        detail=(
            "Threat containment is disabled: no verified enforcement adapter and "
            "post-action verification are available. Use /analyse for analysis only."
        ),
    )


@router.get("/events")
async def threat_events_endpoint(limit: int = 50):
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200")
    try:
        return {"events": await get_events(limit=limit), "source": "threatfade", "containment_verified": False}
    except Exception:
        return {
            "events": _threat_events[-limit:],
            "source": "local",
            "bridge_available": False,
            "containment_verified": False,
        }


@router.post("/export/siem")
async def siem_export(payload: SIEMExportRequest):
    event = payload.model_dump(exclude={"format"})
    try:
        return export_siem(event, fmt=payload.format)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
