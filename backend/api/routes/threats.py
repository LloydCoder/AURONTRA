"""Tenant-scoped threat assessment evidence API.

Detection is a risk assessment, not a containment action. Findings are durable,
idempotent per tenant/event, and never claim that an enforcement control acted.
"""
from datetime import datetime, timezone
from uuid import UUID
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from agents.threat_blocker import analyse_signal, export_siem
from core.database import get_tenant_db
from core.config import settings
from core.threat_evidence import DETECTOR_VERSION, sha256_json, validate_signal
from models.threat_finding import ThreatFinding
from models.device import Device
from core.governed_actions import TrustedPlatformContext
from core.threat_containment import ThreatContainmentError, ThreatContainmentService, serialize_attempt

router = APIRouter()


class SignalAnalyseRequest(BaseModel):
    event_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    device_id: str | None = Field(default=None, min_length=1, max_length=128)
    observed_at: datetime | None = None
    src_ip: str | None = None
    protocol: str | None = None
    entropy: float | None = None
    z_score: float | None = None
    beacon_interval: int | None = None
    jitter: float | None = None
    bytes_out: int | None = None


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
    reason: str | None = None
    action_taken: str | None = "monitor"


def _iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _serialize(finding: ThreatFinding) -> dict:
    return {
        "id": finding.id,
        "event_id": finding.event_id,
        "device_id": finding.device_id,
        "source": finding.source,
        "detector_version": finding.detector_version,
        "observed_at": _iso_utc(finding.observed_at),
        "received_at": _iso_utc(finding.received_at),
        "signal_sha256": finding.signal_sha256,
        "signal": finding.signal,
        "assessment": finding.assessment,
        "score": finding.score,
        "threat_level": finding.threat_level,
        "mitre_ttp": finding.mitre_ttp,
        "decision_status": finding.decision_status,
        "containment_verified": finding.containment_verified is True,
    }


@router.get("/")
async def threats_overview(request: Request, db: AsyncSession = Depends(get_tenant_db)):
    tenant_id = request.state.tenant_id
    total_events = await db.scalar(select(func.count()).select_from(ThreatFinding).where(
        ThreatFinding.org_id == tenant_id
    ))
    return {
        "status": "ok",
        "total_events": int(total_events or 0),
        "contained": 0,
        "containment_enabled": False,
        "note": "Detection and analysis do not establish successful containment.",
    }


@router.post("/analyse")
async def analyse_threat(
    payload: SignalAnalyseRequest,
    request: Request,
    db: AsyncSession = Depends(get_tenant_db),
):
    """Validate, assess and persist an evidence-bearing finding; never enforce."""
    raw = payload.model_dump(exclude_none=True, exclude={"event_id", "observed_at", "device_id"})
    try:
        signal = validate_signal(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    observed_at = payload.observed_at or datetime.now(timezone.utc)
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise HTTPException(status_code=422, detail="observed_at must include a timezone.")
    observed_at = observed_at.astimezone(timezone.utc)
    now = datetime.now(timezone.utc)
    if observed_at > now.replace(microsecond=0) and (observed_at - now).total_seconds() > 300:
        raise HTTPException(status_code=422, detail="observed_at cannot be more than five minutes in the future.")

    tenant_id = request.state.tenant_id
    if payload.device_id is not None:
        device = await db.scalar(select(Device).where(
            Device.id == payload.device_id,
            Device.org_id == tenant_id,
        ))
        if device is None:
            raise HTTPException(status_code=404, detail="Device not found.")
        if not device.is_active or device.revoked_at is not None or device.enrolled_at is None:
            raise HTTPException(status_code=409, detail="Device must be active and enrolled before telemetry can be attributed to it.")

    event_id = payload.event_id or str(uuid4())
    signal_hash = sha256_json(signal)
    existing = await db.scalar(select(ThreatFinding).where(
        ThreatFinding.org_id == tenant_id,
        ThreatFinding.event_id == event_id,
    ))
    if existing is not None:
        if existing.signal_sha256 != signal_hash or existing.device_id != payload.device_id:
            raise HTTPException(status_code=409, detail="event_id was already used with a different signal.")
        return {**existing.assessment, "finding": _serialize(existing), "idempotent_replay": True}

    assessment = analyse_signal(dict(signal))
    assessment.update({
        "detector_version": DETECTOR_VERSION,
        "signal_sha256": signal_hash,
        "score_semantics": "deterministic_heuristic_not_calibrated_probability",
        "mitre_mapping_semantics": "heuristic_hypothesis_not_confirmed_behavior",
        "containment_verified": False,
        "blocked": False,
    })
    finding = ThreatFinding(
        id=str(uuid4()),
        org_id=tenant_id,
        event_id=event_id,
        device_id=payload.device_id,
        source="network_signal",
        detector_version=DETECTOR_VERSION,
        observed_at=observed_at,
        signal_sha256=signal_hash,
        signal=signal,
        assessment=assessment,
        score=int(assessment["score"]),
        threat_level=assessment["threat_level"],
        mitre_ttp=assessment["mitre_ttp"],
        decision_status="assessed",
        containment_verified=False,
    )
    db.add(finding)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="event_id was concurrently recorded; retry with the same event_id.") from exc
    return {**assessment, "finding": _serialize(finding), "idempotent_replay": False}


@router.post("/block", status_code=503)
async def block_threat_endpoint(payload: BlockRequest):
    """Fail closed until a verified enforcement adapter and verifier are deployed."""
    raise HTTPException(
        status_code=503,
        detail="Threat containment is disabled: no verified enforcement adapter and post-action verification are available. Use /analyse for analysis only.",
    )


@router.get("/events")
async def threat_events_endpoint(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_tenant_db),
):
    """Return durable tenant-scoped assessments; upstream claims are not treated as evidence."""
    rows = (await db.scalars(
        select(ThreatFinding)
        .where(ThreatFinding.org_id == request.state.tenant_id)
        .order_by(ThreatFinding.received_at.desc(), ThreatFinding.id.desc())
        .limit(limit)
    )).all()
    return {
        "events": [_serialize(row) for row in rows],
        "source": "aurontra_durable_evidence",
        "containment_verified": False,
    }


@router.get("/findings/{finding_id}")
async def threat_finding_detail(
    finding_id: str,
    request: Request,
    db: AsyncSession = Depends(get_tenant_db),
):
    finding = await db.scalar(select(ThreatFinding).where(
        ThreatFinding.id == finding_id,
        ThreatFinding.org_id == request.state.tenant_id,
    ))
    if finding is None:
        raise HTTPException(status_code=404, detail="Threat finding not found.")
    return {"finding": _serialize(finding)}




def get_threat_containment_service() -> ThreatContainmentService:
    """Default has no verifier; production containment stays disabled until one is registered."""
    return ThreatContainmentService(verifier=None)


@router.post("/findings/{finding_id}/contain")
async def contain_threat_finding(
    finding_id: str,
    request: Request,
    db: AsyncSession = Depends(get_tenant_db),
    service: ThreatContainmentService = Depends(get_threat_containment_service),
):
    """Request endpoint isolation through the Agent Platform; never run local enforcement."""
    if request.state.role not in {"org:owner", "org:admin", "security:admin", "security:analyst"}:
        raise HTTPException(status_code=403, detail="Security-administrator role is required.")
    try:
        agent_id = UUID(settings.AGENT_PLATFORM_AGENT_ID)
        task_id = UUID(settings.AGENT_PLATFORM_TASK_ID)
        context = TrustedPlatformContext(
            tenant_id=request.state.tenant_id,
            subject_id=request.state.subject,
            agent_id=agent_id,
            task_id=task_id,
        )
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=503, detail="Trusted Platform agent/task context is not configured.") from None
    try:
        attempt, replay = await service.contain(
            db=db,
            tenant_id=request.state.tenant_id,
            finding_id=finding_id,
            platform_context=context,
        )
    except ThreatContainmentError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from None

    finding = await db.scalar(select(ThreatFinding).where(
        ThreatFinding.id == finding_id,
        ThreatFinding.org_id == request.state.tenant_id,
    ))
    body = {
        "attempt": serialize_attempt(attempt),
        "finding": _serialize(finding) if finding is not None else None,
        "idempotent_replay": replay,
    }
    if attempt.status == "contained" and attempt.verification_evidence_ids:
        return JSONResponse(status_code=200, content=body)
    if attempt.status in {"submitting", "approval_pending", "platform_pending", "unknown_outcome"}:
        return JSONResponse(status_code=202, content=body)
    return JSONResponse(status_code=409, content=body)


@router.post("/export/siem")
async def siem_export(payload: SIEMExportRequest):
    event = payload.model_dump(exclude={"format"})
    # Public request data is not trusted enforcement evidence.
    event["enforcement_verified"] = False
    try:
        return export_siem(event, fmt=payload.format)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
