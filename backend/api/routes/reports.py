"""Evidence-backed, tenant-scoped reports with immutable provenance artifacts."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_tenant_db
from models.device import Device
from models.resilience_score import ResilienceScore
from models.report_artifact import ReportArtifact
from models.threat_containment_attempt import ThreatContainmentAttempt
from models.ticket import Ticket, TicketStatus
from reporting.roi import generate_roi_report
from reporting.compliance import generate_compliance_report

router = APIRouter()


class ROIRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    period_days: int = Field(default=30, ge=1, le=365)
    avg_hourly_rate_usd: float = Field(default=45.0, ge=0, le=500)


class ComplianceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    framework: str = Field(default="NIS2", pattern="^(NIS2|DORA)$")
    period_days: int = Field(default=30, ge=1, le=365)


async def _collect_evidence(db: AsyncSession, tenant_id: str, period_days: int, claims: dict) -> tuple[dict, datetime, datetime]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=period_days)
    device_count = int(await db.scalar(
        select(func.count()).select_from(Device).where(
            Device.org_id == tenant_id, Device.is_active.is_(True), Device.revoked_at.is_(None)
        )
    ) or 0)
    tickets_total = int(await db.scalar(
        select(func.count()).select_from(Ticket).where(
            Ticket.org_id == tenant_id, Ticket.created_at >= start, Ticket.created_at <= end
        )
    ) or 0)
    tickets_resolved_ai = int(await db.scalar(
        select(func.count()).select_from(Ticket).where(
            Ticket.org_id == tenant_id, Ticket.created_at >= start, Ticket.created_at <= end,
            Ticket.ai_resolved.is_(True), Ticket.resolved_at.is_not(None),
            Ticket.resolved_at >= start, Ticket.resolved_at <= end
        )
    ) or 0)
    tickets_resolved = int(await db.scalar(
        select(func.count()).select_from(Ticket).where(
            Ticket.org_id == tenant_id, Ticket.created_at >= start, Ticket.created_at <= end,
            Ticket.status.in_([TicketStatus.RESOLVED, TicketStatus.CLOSED]),
            Ticket.resolved_at.is_not(None), Ticket.resolved_at >= start, Ticket.resolved_at <= end
        )
    ) or 0)
    threats_contained = int(await db.scalar(
        select(func.count()).select_from(ThreatContainmentAttempt).where(
            ThreatContainmentAttempt.org_id == tenant_id,
            ThreatContainmentAttempt.status == "contained",
            ThreatContainmentAttempt.completed_at.is_not(None),
            ThreatContainmentAttempt.completed_at >= start,
            ThreatContainmentAttempt.completed_at <= end,
        )
    ) or 0)
    average_score = await db.scalar(
        select(func.avg(ResilienceScore.score)).where(
            ResilienceScore.org_id == tenant_id,
            ResilienceScore.recorded_at >= start,
            ResilienceScore.recorded_at <= end,
        )
    )
    amr = claims.get("amr", []) if isinstance(claims, dict) else []
    if isinstance(amr, str):
        amr = [amr]
    mfa_enabled = bool(
        isinstance(claims, dict) and claims.get("mfa") is True
        or isinstance(amr, list) and any(str(item).lower() in {"mfa", "otp", "webauthn"} for item in amr)
    )
    evidence = {
        "period_start": start.isoformat(),
        "period_end": end.isoformat(),
        "period_days": period_days,
        "active_devices": device_count,
        "tickets_created": tickets_total,
        "ai_resolved_tickets": tickets_resolved_ai,
        "resolved_or_closed_tickets": tickets_resolved,
        "verified_containment_attempts": threats_contained,
        "average_resilience_score": round(float(average_score), 2) if average_score is not None else 0,
        "siem_active": False,
        "siem_provenance": "not_configured_or_not_tenant_verified",
        "mfa_enabled": mfa_enabled,
        "mfa_provenance": "verified_identity_claim" if mfa_enabled else "not_proven_by_verified_identity_claim",
        "query_scope": "verified_tenant_id",
        "source_queries": {
            "active_devices": "devices.org_id = verified tenant AND active AND not revoked",
            "tickets_created": "tickets.org_id = verified tenant AND created_at within report window",
            "ai_resolved_tickets": "tenant tickets created and resolved within window with ai_resolved=true",
            "resolved_or_closed_tickets": "tenant tickets created and resolved within window with resolved/closed status",
            "verified_containment_attempts": "tenant containment attempts with status=contained and completed_at within window",
            "average_resilience_score": "tenant resilience score snapshots recorded within window",
        },
    }
    return evidence, start, end


async def _persist_report(
    db: AsyncSession, *, tenant_id: str, actor: str, report_type: str,
    start: datetime, end: datetime, provenance: dict, report: dict,
) -> dict:
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    artifact_id = str(uuid4())
    db.add(ReportArtifact(
        id=artifact_id, org_id=tenant_id, report_type=report_type,
        period_start=start, period_end=end, created_by=actor,
        input_provenance=provenance, report_payload=report, payload_sha256=digest,
    ))
    await db.flush()
    return {**report, "evidence_artifact_id": artifact_id, "evidence_sha256": digest, "persisted": True}


def _tenant_actor(request: Request) -> tuple[str, str, dict]:
    tenant_id = getattr(request.state, "tenant_id", None)
    actor = getattr(request.state, "subject", None)
    claims = getattr(request.state, "claims", {})
    if not isinstance(tenant_id, str) or not tenant_id or not isinstance(actor, str) or not actor:
        raise HTTPException(status_code=401, detail="Verified tenant and actor context are required.")
    return tenant_id, actor, claims if isinstance(claims, dict) else {}


@router.post("/roi")
async def roi_report(
    payload: ROIRequest, request: Request,
    db: AsyncSession = Depends(get_tenant_db),
):
    """Generate a modelled ROI report from tenant-scoped records, not caller-supplied counts."""
    tenant_id, actor, claims = _tenant_actor(request)
    evidence, start, end = await _collect_evidence(db, tenant_id, payload.period_days, claims)
    report = generate_roi_report(
        org_id=tenant_id, device_count=evidence["active_devices"],
        tickets_resolved_ai=evidence["ai_resolved_tickets"], tickets_total=evidence["tickets_created"],
        threats_blocked=evidence["verified_containment_attempts"],
        avg_hourly_rate=payload.avg_hourly_rate_usd, period_days=payload.period_days,
    )
    report.update({
        "threats_verified_contained": evidence["verified_containment_attempts"],
        "threats_reported_blocked_unverified": 0,
        "measured_savings": False,
        "methodology_status": "illustrative_model_not_measured",
        "input_provenance": "tenant_scoped_database_aggregates_plus_disclosed_hourly_rate_assumption",
        "evidence_provenance": evidence,
        "disclaimer": "Illustrative model only; not measured savings, verified breach avoidance, or a financial guarantee.",
    })
    return await _persist_report(
        db, tenant_id=tenant_id, actor=actor, report_type="roi",
        start=start, end=end, provenance=evidence, report=report,
    )


@router.post("/compliance")
async def compliance_report(
    payload: ComplianceRequest, request: Request,
    db: AsyncSession = Depends(get_tenant_db),
):
    """Generate a tenant-scoped control evidence summary; never claim certification."""
    tenant_id, actor, claims = _tenant_actor(request)
    evidence, start, end = await _collect_evidence(db, tenant_id, payload.period_days, claims)
    try:
        report = generate_compliance_report(
            org_id=tenant_id, framework=payload.framework,
            device_count=evidence["active_devices"],
            threats_blocked=evidence["verified_containment_attempts"],
            avg_resilience_score=round(evidence["average_resilience_score"]),
            tickets_resolved=evidence["resolved_or_closed_tickets"],
            siem_active=False, mfa_enabled=evidence["mfa_enabled"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    report.update({
        "evidence_provenance": evidence,
        "certification_claim": False,
        "score_semantics": "observed_control_evidence_score_not_legal_compliance_certification",
        "disclaimer": "This is a control-evidence summary, not legal advice, independent assurance, or NIS2/DORA certification.",
    })
    return await _persist_report(
        db, tenant_id=tenant_id, actor=actor, report_type="compliance",
        start=start, end=end, provenance=evidence, report=report,
    )


@router.get("/summary")
async def summary_report(request: Request, db: AsyncSession = Depends(get_tenant_db)):
    """Return a tenant-scoped evidence summary without accepting an organization ID."""
    tenant_id, actor, claims = _tenant_actor(request)
    evidence, start, end = await _collect_evidence(db, tenant_id, 30, claims)
    report = {
        "org_id": tenant_id,
        "report_type": "executive_summary",
        "generated_at": end.isoformat(),
        "period_start": start.isoformat(),
        "period_end": end.isoformat(),
        "evidence_provenance": evidence,
        "sections": ["resilience", "tickets", "verified_containment", "compliance_evidence", "roi_model"],
        "note": "Only tenant-scoped database aggregates are included; absence of evidence is not proof of control effectiveness.",
        "certification_claim": False,
    }
    return await _persist_report(
        db, tenant_id=tenant_id, actor=actor, report_type="executive_summary",
        start=start, end=end, provenance=evidence, report=report,
    )
