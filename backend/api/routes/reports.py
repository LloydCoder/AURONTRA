"""
Reports router — Sprint 6.
ROI evidence + NIS2/DORA compliance reports.
Competitive gap: auto-generated compliance artefacts (no competitor does this).
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from reporting.roi import generate_roi_report
from reporting.compliance import generate_compliance_report

router = APIRouter()


class ROIRequest(BaseModel):
    org_id: str
    device_count: int
    tickets_resolved_ai: int
    tickets_total: int
    threats_blocked: int
    avg_hourly_rate: float = 45.0
    period_days: int = 30


class ComplianceRequest(BaseModel):
    org_id: str
    framework: str = "NIS2"
    device_count: int
    threats_blocked: int
    avg_resilience_score: int
    tickets_resolved: int
    siem_active: bool = True
    mfa_enabled: bool = False


@router.post("/roi")
async def roi_report(payload: ROIRequest):
    """Generate ROI evidence report — justifies subscription cost to finance teams."""
    return generate_roi_report(
        org_id=payload.org_id,
        device_count=payload.device_count,
        tickets_resolved_ai=payload.tickets_resolved_ai,
        tickets_total=payload.tickets_total,
        threats_blocked=payload.threats_blocked,
        avg_hourly_rate=payload.avg_hourly_rate,
        period_days=payload.period_days,
    )


@router.post("/compliance")
async def compliance_report(payload: ComplianceRequest):
    """
    Generate NIS2/DORA compliance evidence report.
    Replaces 8-20 hours of manual evidence collection.
    """
    from fastapi import HTTPException
    try:
        return generate_compliance_report(
            org_id=payload.org_id,
            framework=payload.framework,
            device_count=payload.device_count,
            threats_blocked=payload.threats_blocked,
            avg_resilience_score=payload.avg_resilience_score,
            tickets_resolved=payload.tickets_resolved,
            siem_active=payload.siem_active,
            mfa_enabled=payload.mfa_enabled,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("/summary/{org_id}")
async def summary_report(org_id: str):
    """High-level executive summary for a given org."""
    return {
        "org_id": org_id,
        "report_type": "executive_summary",
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "sections": ["resilience", "tickets", "threats", "compliance", "roi"],
        "note": "Full summary requires 30+ days of telemetry data.",
    }
