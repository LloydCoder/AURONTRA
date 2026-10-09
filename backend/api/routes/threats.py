"""
Threats router — Sprint 3.
Analyse, block, and export threat events via ThreatFade + local scoring.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import uuid

from agents.threat_blocker import analyse_signal, block_threat, export_siem
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
    blocked_count = sum(1 for e in _threat_events if e.get("blocked"))
    return {
        "status": "ok",
        "total_events": len(_threat_events),
        "blocked": blocked_count,
        "monitored": len(_threat_events) - blocked_count,
    }


@router.post("/analyse")
async def analyse_threat(payload: SignalAnalyseRequest):
    signal = payload.model_dump(exclude_none=True)
    result = analyse_signal(signal)
    return result


@router.post("/block", status_code=201)
async def block_threat_endpoint(payload: BlockRequest):
    event_id = f"evt-{uuid.uuid4().hex[:8]}"
    result = await block_threat(
        event_id=event_id,
        src_ip=payload.src_ip,
        scenario=payload.scenario,
        org_id=payload.org_id,
    )
    _threat_events.append(result)
    return result


@router.get("/events")
async def threat_events_endpoint(limit: int = 50):
    try:
        bridge_events = await get_events(limit=limit)
        return {"events": bridge_events, "source": "threatfade"}
    except Exception as e:
        return {
            "events": _threat_events[-limit:],
            "source": "local",
            "bridge_error": str(e),
        }


@router.post("/export/siem")
async def siem_export(payload: SIEMExportRequest):
    event = payload.model_dump(exclude={"format"})
    try:
        result = export_siem(event, fmt=payload.format)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return result
