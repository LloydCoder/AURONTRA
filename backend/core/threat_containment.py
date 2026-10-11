"""Fail-closed, Platform-governed threat containment with independent verification.

No local firewall, shell, endpoint, or network side effect exists in this module.
A finding becomes contained only after the Platform reports a completed execution
and an independent verifier confirms the target's isolation state.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.governed_actions import (
    GovernedActionDefinition,
    GovernedActionError,
    GovernedActionRegistry,
    GovernedActionResult,
    PlatformGovernedActionExecutor,
    TrustedPlatformContext,
)
from models.device import Device
from models.threat_containment_attempt import ThreatContainmentAttempt
from models.threat_finding import ThreatFinding
from models.telemetry_record import TelemetryRecord

logger = logging.getLogger(__name__)
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_SAFE_EVIDENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ALLOWED_PENDING_STATES = frozenset({"waiting_approval", "approval_required", "pending_approval", "approval_pending"})


class ThreatContainmentError(RuntimeError):
    """Sanitized, machine-readable containment failure."""

    def __init__(self, code: str, status_code: int = 409) -> None:
        safe = code if isinstance(code, str) and _SAFE_CODE.fullmatch(code) else "containment_request_rejected"
        super().__init__(safe)
        self.code = safe
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class ContainmentVerification:
    """Independent, tenant-scoped observation of the target's current isolation state."""

    verified: bool
    isolation_active: bool
    tenant_id: str
    device_id: str
    finding_id: str
    execution_id: str
    observed_at: datetime
    evidence_source: str
    evidence_ids: tuple[str, ...]
    reason_code: str

    def __post_init__(self) -> None:
        if type(self.verified) is not bool or type(self.isolation_active) is not bool:
            raise ValueError("containment verification booleans are invalid")
        for name in ("tenant_id", "device_id", "finding_id", "execution_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or len(value) > 128:
                raise ValueError("containment verification identity is invalid")
        if self.evidence_source not in {"endpoint_agent", "network_control_plane", "cloud_control_plane"}:
            raise ValueError("containment verification source is not independent or supported")
        if not isinstance(self.evidence_ids, tuple) or len(self.evidence_ids) > 32:
            raise ValueError("containment verification evidence is invalid")
        if any(not isinstance(item, str) or not _SAFE_EVIDENCE.fullmatch(item) for item in self.evidence_ids):
            raise ValueError("containment verification evidence reference is invalid")
        if not isinstance(self.reason_code, str) or not _SAFE_CODE.fullmatch(self.reason_code):
            raise ValueError("containment verification reason code is invalid")
        if not isinstance(self.observed_at, datetime) or self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("containment verification timestamp must be timezone-aware")


class ThreatContainmentVerifier(Protocol):
    async def verify(
        self,
        *,
        tenant_id: str,
        device: Device,
        finding: ThreatFinding,
        execution: GovernedActionResult,
    ) -> ContainmentVerification:
        """Read independent endpoint/control-plane state; do not trust tool output alone."""
        ...


THREAT_CONTAINMENT_ACTION = GovernedActionDefinition(
    key="threat.containment.isolate_endpoint",
    capability_id="aurontra.threat.containment",
    capability_version="1",
    tool_name="isolate_endpoint",
    tool_version="1",
    action="isolate",
    allowed_arguments=frozenset({
        "finding_id", "device_id", "source_evidence_id", "reason_code", "indicator_ip",
    }),
    required_arguments=frozenset({
        "finding_id", "device_id", "source_evidence_id", "reason_code",
    }),
    risk="critical",
    reversibility="reversible",
    data_class="confidential",
    blast_radius="single",
    sandbox_required=True,
    evidence_required=True,
    requested_timeout_seconds=30,
    requested_tool_calls=1,
)
THREAT_CONTAINMENT_REGISTRY = GovernedActionRegistry((THREAT_CONTAINMENT_ACTION,))


async def _commit_with_tenant_context(db: AsyncSession, tenant_id: str) -> None:
    await db.commit()
    # RLS settings use transaction-local scope and are cleared by COMMIT.
    # Re-establish context for any subsequent query in this request.
    if db.get_bind().dialect.name == "postgresql":
        await db.execute(
            text("SELECT set_config('app.current_org_id', :tenant_id, true)"),
            {"tenant_id": tenant_id},
        )


def _iso_utc(value: datetime | None) -> str | None:    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def serialize_attempt(attempt: ThreatContainmentAttempt) -> dict:
    return {
        "id": attempt.id,
        "finding_id": attempt.finding_id,
        "device_id": attempt.device_id,
        "status": attempt.status,
        "version": attempt.version,
        "platform_state": attempt.platform_state,
        "platform_action_id": attempt.platform_action_id,
        "platform_run_id": attempt.platform_run_id,
        "platform_execution_id": attempt.platform_execution_id,
        "platform_evidence_ids": list(attempt.platform_evidence_ids or []),
        "audit_event_ids": list(attempt.audit_event_ids or []),
        "verification_evidence_ids": list(attempt.verification_evidence_ids or []),
        "reason_code": attempt.reason_code,
        "last_error_code": attempt.last_error_code,
        "created_at": _iso_utc(attempt.created_at),
        "updated_at": _iso_utc(attempt.updated_at),
        "completed_at": _iso_utc(attempt.completed_at),
        "containment_verified": attempt.status == "contained" and bool(attempt.verification_evidence_ids),
    }


class ThreatContainmentService:
    """Create/replay one durable attempt per finding; never infer containment from a decision."""

    def __init__(
        self,
        *,
        executor: PlatformGovernedActionExecutor | None = None,
        verifier: ThreatContainmentVerifier | None = None,
    ) -> None:
        self._executor = executor or PlatformGovernedActionExecutor(THREAT_CONTAINMENT_REGISTRY)
        self._verifier = verifier

    async def contain(
        self,
        *,
        db: AsyncSession,
        tenant_id: str,
        finding_id: str,
        platform_context: TrustedPlatformContext,
    ) -> tuple[ThreatContainmentAttempt, bool]:
        if not settings.THREAT_CONTAINMENT_ENABLED:
            raise ThreatContainmentError("containment_disabled", 503)
        if not settings.AGENT_PLATFORM_ENABLED:
            raise ThreatContainmentError("platform_integration_disabled", 503)
        if self._verifier is None or not callable(getattr(self._verifier, "verify", None)):
            raise ThreatContainmentError("independent_verifier_not_configured", 503)
        if db.info.get("tenant_id") != tenant_id:
            raise ThreatContainmentError("tenant_session_mismatch", 403)
        if platform_context.tenant_id != tenant_id:
            raise ThreatContainmentError("platform_tenant_mismatch", 403)

        finding = await db.scalar(select(ThreatFinding).where(
            ThreatFinding.id == finding_id,
            ThreatFinding.org_id == tenant_id,
        ))
        if finding is None:
            raise ThreatContainmentError("finding_not_found", 404)
        if finding.device_id is None:
            raise ThreatContainmentError("finding_not_bound_to_device", 409)
        # A user-submitted analysis request is not trusted evidence for an endpoint
        # isolation action. Require a server-verified endpoint-agent telemetry record.
        if finding.source != "endpoint_agent" or finding.telemetry_record_id is None:
            raise ThreatContainmentError("finding_not_backed_by_trusted_telemetry", 409)
        telemetry = await db.scalar(select(TelemetryRecord).where(
            TelemetryRecord.id == finding.telemetry_record_id,
            TelemetryRecord.org_id == tenant_id,
            TelemetryRecord.device_id == finding.device_id,
            TelemetryRecord.source == "endpoint_agent",
            TelemetryRecord.score_status == "ok",
        ))
        if telemetry is None:
            raise ThreatContainmentError("trusted_telemetry_not_found", 409)
        telemetry_observed_at = telemetry.observed_at
        if telemetry_observed_at.tzinfo is None or telemetry_observed_at.utcoffset() is None:
            telemetry_observed_at = telemetry_observed_at.replace(tzinfo=timezone.utc)
        telemetry_age = (datetime.now(timezone.utc) - telemetry_observed_at.astimezone(timezone.utc)).total_seconds()
        retention_expiry = telemetry.retention_expires_at
        if retention_expiry.tzinfo is None or retention_expiry.utcoffset() is None:
            retention_expiry = retention_expiry.replace(tzinfo=timezone.utc)
        if telemetry_age < -settings.TELEMETRY_FUTURE_SKEW_SECONDS or telemetry_age > settings.TELEMETRY_MAX_AGE_SECONDS:
            raise ThreatContainmentError("trusted_telemetry_stale", 409)
        if retention_expiry.astimezone(timezone.utc) <= datetime.now(timezone.utc):
            raise ThreatContainmentError("trusted_telemetry_expired", 409)
        if finding.threat_level not in {"high", "critical"} or finding.score < 70:
            raise ThreatContainmentError("finding_below_containment_threshold", 409)
        if not isinstance(finding.assessment, dict) or finding.assessment.get("containment_recommended") is not True:
            raise ThreatContainmentError("containment_not_recommended", 409)
        if finding.containment_verified is True:
            attempt = await db.scalar(select(ThreatContainmentAttempt).where(
                ThreatContainmentAttempt.org_id == tenant_id,
                ThreatContainmentAttempt.finding_id == finding.id,
            ))
            if attempt is None:
                raise ThreatContainmentError("containment_evidence_inconsistent", 500)
            return attempt, True

        device = await db.scalar(select(Device).where(
            Device.id == finding.device_id,
            Device.org_id == tenant_id,
        ))
        if device is None:
            raise ThreatContainmentError("target_device_not_found", 404)
        if not device.is_active or device.revoked_at is not None or device.enrolled_at is None:
            raise ThreatContainmentError("target_device_not_enrolled_or_active", 409)
        if device.last_seen_at is None:
            raise ThreatContainmentError("target_device_telemetry_missing", 409)
        last_seen = device.last_seen_at
        if last_seen.tzinfo is None or last_seen.utcoffset() is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        age_seconds = (datetime.now(timezone.utc) - last_seen.astimezone(timezone.utc)).total_seconds()
        if age_seconds < -settings.TELEMETRY_FUTURE_SKEW_SECONDS or age_seconds > settings.TELEMETRY_MAX_AGE_SECONDS:
            raise ThreatContainmentError("target_device_telemetry_stale", 409)

        attempt = await db.scalar(select(ThreatContainmentAttempt).where(
            ThreatContainmentAttempt.org_id == tenant_id,
            ThreatContainmentAttempt.finding_id == finding.id,
        ))
        if attempt is not None:
            if attempt.status not in {"unknown_outcome", "submitting"}:
                return attempt, True
            # Retry only an ambiguous outcome, with the same action ID and Platform
            # request/idempotency key. Never mint a second action.
            action_id = UUID(attempt.platform_action_id)
            attempt.status = "submitting"
            attempt.version += 1
            await _commit_with_tenant_context(db, tenant_id)
        else:
            action_id = uuid5(NAMESPACE_URL, f"aurontra:threat-containment:v1:{tenant_id}:{finding.id}")
            idempotency_key = f"threat-containment:{tenant_id}:{finding.id}:v1"
            attempt = ThreatContainmentAttempt(
                id=str(action_id),
                org_id=tenant_id,
                finding_id=finding.id,
                device_id=device.id,
                idempotency_key=idempotency_key,
                status="submitting",
                version=0,
                platform_action_id=str(action_id),
                platform_evidence_ids=[],
                audit_event_ids=[],
                verification_evidence_ids=[],
                reason_code="high_confidence_threat",
            )
            db.add(attempt)
            try:
                await db.flush()
                await _commit_with_tenant_context(db, tenant_id)  # Persist before crossing the external side-effect boundary.
            except Exception:
                await db.rollback()
                raise ThreatContainmentError("containment_attempt_persistence_failed", 503) from None

        arguments = {
            "finding_id": finding.id,
            "device_id": device.id,
            "source_evidence_id": finding.id,
            "reason_code": "high_confidence_threat",
        }
        indicator = (finding.signal or {}).get("src_ip")
        if isinstance(indicator, str) and indicator:
            arguments["indicator_ip"] = indicator
        try:
            result = await self._executor.submit(
                action_id=action_id,
                context=platform_context,
                action_key=THREAT_CONTAINMENT_ACTION.key,
                resource=f"device:{device.id}",
                intent=f"Aurontra requests governed isolation for threat finding {finding.id}",
                arguments=arguments,
            )
        except GovernedActionError as exc:
            attempt.status = "unknown_outcome" if exc.retryable else "failed"
            attempt.last_error_code = exc.code if _SAFE_CODE.fullmatch(exc.code) else "platform_submission_failed"
            attempt.reason_code = attempt.last_error_code
            attempt.version += 1
            await _commit_with_tenant_context(db, tenant_id)
            return attempt, False
        except Exception:
            logger.warning("Threat containment submission failed finding_id=%s", finding.id)
            attempt.status = "unknown_outcome"
            attempt.last_error_code = "platform_submission_unknown"
            attempt.reason_code = "platform_submission_unknown"
            attempt.version += 1
            await _commit_with_tenant_context(db, tenant_id)
            return attempt, False

        if not isinstance(result, GovernedActionResult):
            attempt.status = "unknown_outcome"
            attempt.last_error_code = "platform_result_invalid"
            attempt.reason_code = "platform_result_invalid"
            attempt.version += 1
            await _commit_with_tenant_context(db, tenant_id)
            return attempt, False

        platform_state = result.platform_state if isinstance(result.platform_state, str) and _SAFE_CODE.fullmatch(result.platform_state) else "unknown"
        attempt.platform_state = platform_state
        attempt.platform_run_id = str(result.run_id)
        attempt.platform_execution_id = str(result.execution_id) if result.execution_id else None
        attempt.platform_evidence_ids = [str(item) for item in result.evidence_ids]
        attempt.audit_event_ids = [str(item) for item in result.audit_event_ids]
        attempt.version += 1
        if result.execution_id is None or platform_state not in {"completed", "succeeded"}:
            attempt.status = "approval_pending" if platform_state in _ALLOWED_PENDING_STATES else "platform_pending"
            attempt.reason_code = attempt.status
            await _commit_with_tenant_context(db, tenant_id)
            return attempt, False

        try:
            verification = await self._verifier.verify(
                tenant_id=tenant_id, device=device, finding=finding, execution=result,
            )
            if not isinstance(verification, ContainmentVerification):
                raise TypeError("invalid verification result")
        except Exception as exc:
            logger.warning("Threat containment verifier failed finding_id=%s error_type=%s", finding.id, type(exc).__name__)
            attempt.status = "verification_failed"
            attempt.reason_code = "independent_verification_failed"
            attempt.last_error_code = "independent_verification_failed"
            attempt.completed_at = datetime.now(timezone.utc)
            await _commit_with_tenant_context(db, tenant_id)
            return attempt, False

        observed_at = verification.observed_at.astimezone(timezone.utc)
        age = (datetime.now(timezone.utc) - observed_at).total_seconds()
        identity_matches = (
            verification.tenant_id == tenant_id
            and verification.device_id == device.id
            and verification.finding_id == finding.id
            and verification.execution_id == str(result.execution_id)
        )
        fresh = -settings.TELEMETRY_FUTURE_SKEW_SECONDS <= age <= settings.TELEMETRY_MAX_AGE_SECONDS
        verified = (
            verification.verified is True
            and verification.isolation_active is True
            and bool(verification.evidence_ids)
            and bool(result.evidence_ids)
            and bool(result.audit_event_ids)
            and identity_matches
            and fresh
        )
        attempt.verification_evidence_ids = list(verification.evidence_ids) if identity_matches else []
        attempt.reason_code = verification.reason_code if _SAFE_CODE.fullmatch(verification.reason_code) else "verification_invalid"
        if verified:
            attempt.status = "contained"
            attempt.last_error_code = None
            attempt.completed_at = datetime.now(timezone.utc)
            finding.containment_verified = True
            finding.assessment = {
                **finding.assessment,
                "blocked": True,
                "containment_verified": True,
                "containment_attempt_id": attempt.id,
                "containment_evidence_ids": list(verification.evidence_ids),
                "containment_evidence_source": verification.evidence_source,
                "containment_observed_at": _iso_utc(verification.observed_at),
            }
        else:
            attempt.status = "verification_failed"
            attempt.last_error_code = "containment_postcondition_not_verified"
            attempt.completed_at = datetime.now(timezone.utc)
        await _commit_with_tenant_context(db, tenant_id)
        return attempt, False
