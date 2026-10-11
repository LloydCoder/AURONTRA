"""Threat analysis and evidence API.

Assessments are durable and tenant-scoped. This router never enforces a
firewall rule, quarantines an endpoint, or claims successful containment.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Literal

from agents.threat_blocker import analyse_signal, export_siem
from core.database import get_tenant_db
from models.threat_finding import ThreatFinding

router = APIRouter()
RULESET_VERSION = "threat-rules.v1"
DETECTOR_VERSION = "heuristic-threat-score.v2"


def _canonical_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _evidence_digest(signal: dict) -> str:
    return hashlib.sha256(_canonical_json(signal).encode("utf-8")).hexdigest()


def _response_from_finding(finding: ThreatFinding, *, idempotent_replay: bool) -> dict:
    evidence = finding.evidence or {}
    return {
        "threat_level": finding.threat_level,
        "score": finding.score,
        "score_components": finding.score_components,
        "detector_version": finding.detector_version,
        "score_semantics": finding.score_semantics,
        "periodic_pattern": (
            "beacon_interval" in evidence
            and "jitter" in evidence
            and float(evidence.get("jitter", 1.0)) < 0.2
        ),
        "mitre_ttp": finding.mitre_ttp,
        "auto_block": False,
        "containment_recommended": finding.containment_recommended,
        "reason": finding.reason,
        "finding": _serialize_finding(finding),
        "idempotent_replay": idempotent_replay,
    }


def _serialize_finding(finding: ThreatFinding) -> dict:
    return {
        "id": finding.id,
        "source_event_id": finding.source_event_id,
        "src_ip": finding.src_ip,
        "protocol": finding.protocol,
        "dst_port": finding.dst_port,
        "threat_level": finding.threat_level,
        "score": finding.score,
        "score_components": finding.score_components,
        "mitre_ttp": finding.mitre_ttp,
        "reason": finding.reason,
        "detector_version": finding.detector_version,
        "ruleset_version": finding.ruleset_version,
        "score_semantics": finding.score_semantics,
        "evidence_sha256": finding.evidence_sha256,
        "evidence": finding.evidence,
        "containment_recommended": finding.containment_recommended,
        "containment_verified": False,
        "status": finding.status,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
    }


class SignalAnalyseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_event_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]{1,128}$")
    src_ip: str | None = Field(default=None, max_length=45)
    protocol: str | None = Field(default=None, max_length=16, pattern=r"^[A-Za-z0-9._-]{1,16}$")
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    bytes_out: int | None = Field(default=None, ge=0, le=9223372036854775807)
    entropy: float | None = Field(default=None, ge=0.0, le=8.0, allow_inf_nan=False)
    z_score: float | None = Field(default=None, ge=-20.0, le=100.0, allow_inf_nan=False)
    beacon_interval: int | None = Field(default=None, ge=1, le=86400)
    jitter: float | None = Field(default=None, ge=0.0, le=1.0, allow_inf_nan=False)

    @field_validator("src_ip")
    @classmethod
    def canonicalize_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("src_ip must be a valid IPv4 or IPv6 address") from exc

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str | None) -> str | None:
        return value.strip().upper() if value is not None else None


class BlockRequest(BaseModel):
    src_ip: str
    scenario: str
    org_id: str = "default"


class SIEMExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    src_ip: str = Field(max_length=45)
    threat_level: Literal["info", "low", "medium", "high", "critical"]
    mitre_ttp: str = Field(max_length=32, pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")
    blocked: bool
    timestamp: str = Field(min_length=1, max_length=64)

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value: str) -> str:
        if any(ord(ch) < 32 for ch in value):
            raise ValueError("timestamp must not contain control characters")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be ISO 8601") from exc
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return parsed.isoformat()
    format: Literal["json", "splunk_hec", "cef"] = "json"
    reason: str | None = Field(default=None, max_length=512)
    action_taken: Literal["monitor", "assessed", "review_required", "containment_pending"] = "monitor"

    @field_validator("src_ip")
    @classmethod
    def validate_export_ip(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("src_ip must be a valid IPv4 or IPv6 address") from exc

    @field_validator("reason")
    @classmethod
    def reject_log_control_chars(cls, value: str | None) -> str | None:
        if value is not None and any(ord(ch) < 32 and ch not in "\t" for ch in value):
            raise ValueError("reason must not contain control characters")
        return value


@router.get("/")
async def threats_overview(request: Request, db: AsyncSession = Depends(get_tenant_db)):
    tenant_id = request.state.tenant_id
    total = await db.scalar(
        select(func.count()).select_from(ThreatFinding).where(ThreatFinding.org_id == tenant_id)
    )
    review_required = await db.scalar(
        select(func.count()).select_from(ThreatFinding).where(
            ThreatFinding.org_id == tenant_id, ThreatFinding.status == "review_required"
        )
    )
    return {
        "status": "ok",
        "total_events": int(total or 0),
        "review_required": int(review_required or 0),
        "contained": 0,
        "containment_enabled": False,
        "containment_verified": False,
        "note": "Threat scores are heuristic assessments; no finding proves successful containment.",
    }


@router.post("/analyse")
async def analyse_threat(
    payload: SignalAnalyseRequest,
    request: Request,
    db: AsyncSession = Depends(get_tenant_db),
):
    """Persist a tenant-scoped assessment and immutable evidence digest."""
    tenant_id = request.state.tenant_id
    signal = payload.model_dump(exclude_none=True, exclude={"source_event_id"})
    try:
        assessment = analyse_signal(signal)
    except (TypeError, ValueError, OverflowError) as exc:
        raise HTTPException(status_code=422, detail="Signal contains invalid or unsupported values.") from exc

    evidence_sha256 = _evidence_digest(signal)
    source_event_id = payload.source_event_id
    if source_event_id:
        existing = await db.scalar(
            select(ThreatFinding).where(
                ThreatFinding.org_id == tenant_id,
                ThreatFinding.source_event_id == source_event_id,
            )
        )
        if existing is not None:
            if existing.evidence_sha256 != evidence_sha256:
                raise HTTPException(status_code=409, detail="source_event_id was already used with different evidence.")
            return _response_from_finding(existing, idempotent_replay=True)

    status_value = "review_required" if assessment["containment_recommended"] else "assessed"
    finding = ThreatFinding(
        org_id=tenant_id,
        source_event_id=source_event_id,
        src_ip=signal.get("src_ip"),
        protocol=signal.get("protocol"),
        dst_port=signal.get("dst_port"),
        threat_level=assessment["threat_level"],
        score=assessment["score"],
        score_components=assessment["score_components"],
        mitre_ttp=assessment["mitre_ttp"],
        reason=assessment["reason"],
        detector_version=DETECTOR_VERSION,
        ruleset_version=RULESET_VERSION,
        score_semantics=assessment["score_semantics"],
        evidence_sha256=evidence_sha256,
        evidence=signal,
        containment_recommended=assessment["containment_recommended"],
        containment_verified=False,
        status=status_value,
    )
    db.add(finding)
    try:
        await db.flush()
        await db.refresh(finding)
    except IntegrityError as exc:
        await db.rollback()
        if db.get_bind().dialect.name == "postgresql":
            await db.execute(
                text("SELECT set_config('app.current_org_id', :tenant_id, true)"),
                {"tenant_id": tenant_id},
            )
        existing = None
        if source_event_id:
            existing = await db.scalar(
                select(ThreatFinding).where(
                    ThreatFinding.org_id == tenant_id,
                    ThreatFinding.source_event_id == source_event_id,
                )
            )
        if existing is not None and existing.evidence_sha256 == evidence_sha256:
            return _response_from_finding(existing, idempotent_replay=True)
        raise HTTPException(status_code=409, detail="Threat finding could not be persisted without a conflict.") from exc

    return {**assessment, "finding": _serialize_finding(finding), "idempotent_replay": False}


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


async def _list_findings(db: AsyncSession, tenant_id: str, limit: int) -> list[dict]:
    rows = (
        await db.scalars(
            select(ThreatFinding)
            .where(ThreatFinding.org_id == tenant_id)
            .order_by(ThreatFinding.created_at.desc(), ThreatFinding.id.desc())
            .limit(limit)
        )
    ).all()
    return [_serialize_finding(row) for row in rows]


@router.get("/events")
@router.get("/findings")
async def threat_events_endpoint(
    request: Request,
    limit: int = 50,
    db: AsyncSession = Depends(get_tenant_db),
):
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200")
    findings = await _list_findings(db, request.state.tenant_id, limit)
    return {
        "events": findings,
        "findings": findings,
        "source": "database",
        "containment_verified": False,
    }


@router.post("/export/siem")
async def siem_export(payload: SIEMExportRequest):
    event = payload.model_dump(exclude={"format"})
    event["enforcement_verified"] = False
    try:
        return export_siem(event, fmt=payload.format)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
