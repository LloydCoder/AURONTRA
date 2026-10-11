"""Authenticated, HMAC-signed independent containment-verification ingress."""
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from core.containment_webhook import ContainmentWebhookAuthError, configured_source, verify_signature
from core.database import get_tenant_db
from core.threat_containment import (
    ThreatContainmentError,
    ThreatContainmentService,
    serialize_attempt,
)
from models.containment_verification_evidence import ContainmentVerificationEvidence
from models.device import Device
from models.threat_containment_attempt import ThreatContainmentAttempt
from models.threat_finding import ThreatFinding
from api.routes.threats import get_threat_containment_service, _serialize

router = APIRouter()


class ContainmentVerificationWebhook(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    key_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    tenant_id: str = Field(min_length=1, max_length=64)
    attempt_id: UUID
    finding_id: UUID
    device_id: str = Field(min_length=1, max_length=128)
    action_id: UUID
    execution_id: UUID
    source_type: Literal["network_control_plane", "cloud_control_plane"]
    evidence_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    isolation_active: StrictBool
    reason_code: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_]{0,79}$")
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def observed_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value.astimezone(timezone.utc)


@router.post("/containment-verification")
async def ingest_containment_verification(
    request: Request,
    db: AsyncSession = Depends(get_tenant_db),
    service: ThreatContainmentService = Depends(get_threat_containment_service),
):
    """Accept signed control-plane evidence; signature validity alone is not containment proof."""
    if request.state.role not in {"org:owner", "org:admin"}:
        raise HTTPException(status_code=403, detail="Organization administrator role is required.")
    raw_body = await request.body()
    if not raw_body or len(raw_body) > 16_384:
        raise HTTPException(status_code=413, detail="Containment verification payload size is invalid.")
    try:
        payload = ContainmentVerificationWebhook.model_validate_json(raw_body)
    except Exception:
        raise HTTPException(status_code=422, detail="Containment verification payload is invalid.") from None

    try:
        source = configured_source(payload.source_id)
        if payload.key_id != source["key_id"] or payload.source_type != source["source_type"]:
            raise ContainmentWebhookAuthError("verifier_key_or_source_mismatch")
        nonce, payload_hash = verify_signature(
            raw_body=raw_body,
            timestamp_header=request.headers.get("X-Aurontra-Timestamp"),
            nonce=request.headers.get("X-Aurontra-Nonce"),
            signature_header=request.headers.get("X-Aurontra-Signature"),
            source=source,
            request_tenant_id=request.state.tenant_id,
        )
    except ContainmentWebhookAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from None

    if payload.tenant_id != request.state.tenant_id or payload.tenant_id != source["tenant_id"]:
        raise HTTPException(status_code=403, detail="Verifier tenant identity does not match authenticated tenant.")

    attempt = await db.scalar(select(ThreatContainmentAttempt).where(
        ThreatContainmentAttempt.org_id == request.state.tenant_id,
        ThreatContainmentAttempt.id == str(payload.attempt_id),
    ).with_for_update())
    if attempt is None:
        raise HTTPException(status_code=404, detail="Containment attempt not found.")
    if (
        attempt.finding_id != str(payload.finding_id)
        or attempt.device_id != payload.device_id
        or attempt.platform_action_id != str(payload.action_id)
        or attempt.platform_execution_id != str(payload.execution_id)
        or attempt.platform_state not in {"completed", "succeeded"}
        or attempt.status not in {"submitting", "platform_pending", "awaiting_verification"}
    ):
        raise HTTPException(status_code=409, detail="Verifier evidence does not match a completed Platform action.")

    finding = await db.scalar(select(ThreatFinding).where(
        ThreatFinding.org_id == request.state.tenant_id,
        ThreatFinding.id == attempt.finding_id,
        ThreatFinding.device_id == attempt.device_id,
    ))
    device = await db.scalar(select(Device).where(
        Device.org_id == request.state.tenant_id,
        Device.id == attempt.device_id,
    ))
    if finding is None or device is None:
        raise HTTPException(status_code=409, detail="Containment target binding is inconsistent.")

    evidence = ContainmentVerificationEvidence(
        id=str(uuid4()),
        org_id=request.state.tenant_id,
        attempt_id=attempt.id,
        finding_id=finding.id,
        device_id=device.id,
        action_id=str(payload.action_id),
        execution_id=str(payload.execution_id),
        source_id=payload.source_id,
        key_id=payload.key_id,
        source_type=payload.source_type,
        nonce=nonce,
        evidence_id=payload.evidence_id,
        payload_sha256=payload_hash,
        signature_valid=True,
        isolation_active=payload.isolation_active,
        reason_code=payload.reason_code,
        observed_at=payload.observed_at,
    )
    db.add(evidence)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Verifier nonce or evidence ID was already used.") from None

    try:
        updated_attempt, replay = await service.verify_attempt(
            db=db,
            tenant_id=request.state.tenant_id,
            attempt_id=attempt.id,
        )
    except ThreatContainmentError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.code) from None

    refreshed_finding = await db.scalar(select(ThreatFinding).where(
        ThreatFinding.org_id == request.state.tenant_id,
        ThreatFinding.id == finding.id,
    ))
    body = {
        "attempt": serialize_attempt(updated_attempt),
        "finding": _serialize(refreshed_finding) if refreshed_finding is not None else None,
        "verification_evidence_id": evidence.id,
        "idempotent_replay": replay,
    }
    if updated_attempt.status == "contained":
        return JSONResponse(status_code=200, content=body)
    if updated_attempt.status == "awaiting_verification":
        return JSONResponse(status_code=202, content=body)
    return JSONResponse(status_code=409, content=body)
