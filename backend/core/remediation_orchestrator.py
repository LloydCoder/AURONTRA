"""Durable, tenant-scoped remediation intent lifecycle.

This module persists intent before external calls, uses the existing durable job
queue and transactional outbox, and records unknown outcomes rather than assuming
a timed-out Platform call did not execute. It contains no local side effects.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.config import settings
from core.job_queue import IdempotencyConflict, enqueue_job, enqueue_outbox_event
from models.device import Device
from models.organization import Organization
from models.remediation_intent import RemediationIntent
from resilience.playbooks.planner import RemediationPlan, plan_as_dict

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,99}$")
_TERMINAL = frozenset({"verified", "failed", "verification_failed", "cancelled"})
_RECOVERABLE = frozenset({"approval_pending", "platform_pending", "awaiting_verification", "unknown_outcome"})
_ALLOWED_TRANSITIONS = {
    "proposed": {"queued", "cancelled", "failed"},
    "queued": {"submitting", "cancelled", "failed"},
    "submitting": {"approval_pending", "platform_pending", "awaiting_verification", "unknown_outcome", "verified", "failed", "verification_failed", "cancelled"},
    "approval_pending": {"submitting", "platform_pending", "awaiting_verification", "unknown_outcome", "verified", "failed", "verification_failed", "cancelled"},
    "platform_pending": {"submitting", "awaiting_verification", "unknown_outcome", "verified", "failed", "verification_failed", "cancelled"},
    "awaiting_verification": {"submitting", "unknown_outcome", "verified", "failed", "verification_failed", "cancelled"},
    "unknown_outcome": {"submitting", "approval_pending", "platform_pending", "awaiting_verification", "verified", "failed", "verification_failed", "cancelled"},
    "verified": set(),
    "failed": set(),
    "verification_failed": set(),
    "cancelled": set(),
}


class RemediationOrchestrationError(RuntimeError):
    """Sanitized orchestration error; never carries provider response text."""

    def __init__(self, code: str) -> None:
        if not isinstance(code, str) or not _SAFE_CODE.fullmatch(code):
            code = "remediation_orchestration_error"
        super().__init__(code)
        self.code = code


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    if len(encoded.encode("utf-8")) > 65536:
        raise ValueError("remediation intent payload exceeds 64 KiB")
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _safe_ids(values: Any, field: str) -> list[str]:
    if not isinstance(values, (list, tuple)) or len(values) > 100:
        raise ValueError(f"{field}_invalid")
    result = []
    for value in values:
        text_value = str(value)
        if not _SAFE_ID.fullmatch(text_value):
            raise ValueError(f"{field}_invalid")
        result.append(text_value)
    return result


def _set_tenant_context(session: AsyncSession, org_id: str) -> None:
    # The caller must use a tenant-scoped session; the worker sets the DB RLS
    # context from the trusted org_id on the claimed DurableJob, not its payload.
    session.info["tenant_id"] = org_id


async def _set_database_rls(session: AsyncSession, org_id: str) -> None:
    _set_tenant_context(session, org_id)
    if session.get_bind().dialect.name == "postgresql":
        await session.execute(
            text("SELECT set_config('app.current_org_id', :org_id, true)"),
            {"org_id": org_id},
        )


async def enqueue_remediation_intent(
    session: AsyncSession,
    plan: RemediationPlan,
) -> tuple[RemediationIntent, bool]:
    """Persist intent, initial outbox event and optional submit job atomically."""
    if not isinstance(plan, RemediationPlan) or plan.status != "proposed":
        raise RemediationOrchestrationError("remediation_plan_not_proposed")
    if not _SAFE_ID.fullmatch(plan.tenant_id) or not _SAFE_ID.fullmatch(plan.device_id):
        raise RemediationOrchestrationError("remediation_target_invalid")
    if session.info.get("tenant_id") != plan.tenant_id:
        raise RemediationOrchestrationError("tenant_session_mismatch")
    payload = plan_as_dict(plan)
    if payload.get("execution_enabled") is not False or payload.get("business_outcome_verified") is not False:
        raise RemediationOrchestrationError("remediation_plan_semantics_invalid")
    _canonical_hash(payload)

    organization = await session.scalar(
        select(Organization).where(Organization.id == plan.tenant_id)
    )
    if organization is None or organization.status != "active":
        raise RemediationOrchestrationError("organization_not_active")
    device = await session.scalar(
        select(Device).where(Device.org_id == plan.tenant_id, Device.id == plan.device_id)
    )
    if device is None or not device.is_active or device.enrolled_at is None or device.revoked_at is not None:
        raise RemediationOrchestrationError("target_device_not_enrolled")

    idempotency_key = f"remediation:{plan.plan_id}"
    existing = await session.scalar(
        select(RemediationIntent).where(
            RemediationIntent.org_id == plan.tenant_id,
            RemediationIntent.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.plan_id != plan.plan_id or _canonical_hash(existing.plan_payload) != _canonical_hash(payload):
            raise IdempotencyConflict("Remediation idempotency key reused with different plan content.")
        created = False
        intent = existing
    else:
        initial_status = "queued" if settings.REMEDIATION_SUBMISSION_ENABLED else "proposed"
        intent = RemediationIntent(
            id=plan.plan_id,
            org_id=plan.tenant_id,
            device_id=plan.device_id,
            plan_id=plan.plan_id,
            idempotency_key=idempotency_key,
            playbook=plan.playbook,
            source_evidence_id=plan.source_evidence_id,
            plan_payload=payload,
            status=initial_status,
            version=0,
            platform_evidence_ids=[],
            audit_event_ids=[],
            postcondition_evidence_ids=[],
            result_metadata={},
        )
        try:
            async with session.begin_nested():
                session.add(intent)
                await session.flush()
        except IntegrityError:
            existing = await session.scalar(
                select(RemediationIntent).where(
                    RemediationIntent.org_id == plan.tenant_id,
                    RemediationIntent.idempotency_key == idempotency_key,
                )
            )
            if existing is None or _canonical_hash(existing.plan_payload) != _canonical_hash(payload):
                raise IdempotencyConflict("Remediation idempotency key already exists with different content.")
            intent, created = existing, False
        else:
            created = True

    # Reconcile missing queue/outbox rows idempotently if a retry observes an
    # existing intent. All three writes are inside the caller's transaction.
    if settings.REMEDIATION_SUBMISSION_ENABLED:
        await enqueue_job(
            session,
            org_id=plan.tenant_id,
            job_type="remediation.submit",
            idempotency_key=f"remediation:{plan.plan_id}:submit",
            payload={"org_id": plan.tenant_id, "intent_id": plan.plan_id, "operation": "submit"},
            max_attempts=5,
        )
    await enqueue_outbox_event(
        session,
        org_id=plan.tenant_id,
        aggregate_type="remediation_intent",
        aggregate_id=plan.plan_id,
        event_type="remediation.intent.created",
        idempotency_key=f"remediation:{plan.plan_id}:created",
        payload={
            "intent_id": plan.plan_id,
            "plan_id": plan.plan_id,
            "device_id": plan.device_id,
            "playbook": plan.playbook,
            "status": intent.status,
            "version": intent.version,
        },
    )
    return intent, created


async def get_remediation_intent(
    session: AsyncSession, *, org_id: str, intent_id: str
) -> RemediationIntent | None:
    if session.info.get("tenant_id") != org_id:
        raise RemediationOrchestrationError("tenant_session_mismatch")
    return await session.scalar(
        select(RemediationIntent).where(
            RemediationIntent.org_id == org_id,
            RemediationIntent.id == intent_id,
        )
    )


async def transition_remediation_intent(
    session: AsyncSession,
    *,
    org_id: str,
    intent_id: str,
    to_status: str,
    reason_code: str | None = None,
    platform_state: str | None = None,
    platform_run_id: str | None = None,
    platform_execution_id: str | None = None,
    platform_evidence_ids: Any = (),
    audit_event_ids: Any = (),
    postcondition_evidence_ids: Any = (),
    result_metadata: dict[str, Any] | None = None,
) -> RemediationIntent:
    """Apply a locked, validated state transition and append an outbox event."""
    if session.info.get("tenant_id") != org_id:
        raise RemediationOrchestrationError("tenant_session_mismatch")
    if to_status not in _ALLOWED_TRANSITIONS:
        raise RemediationOrchestrationError("remediation_status_invalid")
    intent = await session.scalar(
        select(RemediationIntent).where(
            RemediationIntent.org_id == org_id,
            RemediationIntent.id == intent_id,
        ).with_for_update()
    )
    if intent is None:
        raise LookupError("Remediation intent not found.")
    if intent.status == to_status:
        return intent
    if to_status not in _ALLOWED_TRANSITIONS.get(intent.status, set()):
        raise RemediationOrchestrationError("remediation_transition_not_allowed")

    metadata = result_metadata or {}
    if not isinstance(metadata, dict):
        raise RemediationOrchestrationError("remediation_result_metadata_invalid")
    _canonical_hash(metadata)
    if reason_code is not None and not _SAFE_CODE.fullmatch(reason_code):
        reason_code = "remediation_error"
    for field_name, value in (("platform_state", platform_state), ("platform_run_id", platform_run_id), ("platform_execution_id", platform_execution_id)):
        if value is not None and (not isinstance(value, str) or not _SAFE_ID.fullmatch(value)):
            raise RemediationOrchestrationError(f"{field_name}_invalid")

    intent.status = to_status
    intent.version += 1
    intent.updated_at = datetime.now(timezone.utc)
    intent.last_error_code = reason_code
    if platform_state is not None:
        intent.platform_state = platform_state
    if platform_run_id is not None:
        intent.platform_run_id = platform_run_id
    if platform_execution_id is not None:
        intent.platform_execution_id = platform_execution_id
    intent.platform_evidence_ids = _safe_ids(platform_evidence_ids, "platform_evidence_ids")
    intent.audit_event_ids = _safe_ids(audit_event_ids, "audit_event_ids")
    intent.postcondition_evidence_ids = _safe_ids(postcondition_evidence_ids, "postcondition_evidence_ids")
    intent.result_metadata = metadata
    if to_status in _TERMINAL:
        intent.completed_at = datetime.now(timezone.utc)
    await session.flush()

    await enqueue_outbox_event(
        session,
        org_id=org_id,
        aggregate_type="remediation_intent",
        aggregate_id=intent.id,
        event_type="remediation.intent.state_changed",
        idempotency_key=f"remediation:{intent.id}:state:{intent.version}",
        payload={
            "intent_id": intent.id,
            "status": intent.status,
            "version": intent.version,
            "reason_code": intent.last_error_code,
        },
    )
    return intent


async def enqueue_stale_reconciliation_jobs(
    session: AsyncSession,
    *,
    org_id: str,
    older_than_seconds: int = 60,
    limit: int = 100,
) -> int:
    """Idempotently schedule reconciliation for stale nonterminal external states."""
    if not settings.REMEDIATION_SUBMISSION_ENABLED or not settings.AGENT_PLATFORM_ENABLED:
        return 0
    if session.info.get("tenant_id") != org_id:
        raise RemediationOrchestrationError("tenant_session_mismatch")
    if not 5 <= older_than_seconds <= 86400 or not 1 <= limit <= 500:
        raise ValueError("reconciliation bounds are invalid")
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=older_than_seconds)
    intents = list((await session.scalars(
        select(RemediationIntent).where(
            RemediationIntent.org_id == org_id,
            RemediationIntent.status.in_(list(_RECOVERABLE)),
            RemediationIntent.updated_at <= cutoff,
        ).order_by(RemediationIntent.updated_at, RemediationIntent.id).limit(limit).with_for_update(skip_locked=True)
    )).all())
    for intent in intents:
        await enqueue_job(
            session,
            org_id=org_id,
            job_type="remediation.reconcile",
            idempotency_key=f"remediation:{intent.id}:reconcile:{intent.version}",
            payload={
                "org_id": org_id,
                "intent_id": intent.id,
                "operation": "reconcile",
                "expected_version": intent.version,
            },
            max_attempts=5,
        )
    return len(intents)


class RemediationProcessor(Protocol):
    async def process(
        self,
        *,
        org_id: str,
        intent_id: str,
        plan_payload: dict[str, Any],
        operation: str,
        idempotency_key: str,
    ) -> Any:
        """Re-load trusted target/evidence and call the gated Platform service."""
        ...


def make_remediation_job_handler(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    processor: RemediationProcessor,
):
    """Return a tenant-aware worker handler; register it only for remediation job types."""
    async def handle(payload: dict[str, Any], idempotency_key: str, trusted_org_id: str) -> dict[str, Any]:
        if not settings.REMEDIATION_SUBMISSION_ENABLED or not settings.AGENT_PLATFORM_ENABLED:
            raise RemediationOrchestrationError("remediation_submission_disabled")
        if not isinstance(payload, dict) or payload.get("org_id") != trusted_org_id:
            raise RemediationOrchestrationError("job_tenant_context_mismatch")
        intent_id = payload.get("intent_id")
        operation = payload.get("operation")
        if not isinstance(intent_id, str) or not _SAFE_ID.fullmatch(intent_id):
            raise RemediationOrchestrationError("intent_id_invalid")
        if operation not in {"submit", "reconcile"}:
            raise RemediationOrchestrationError("operation_invalid")
        if operation == "submit":
            expected_key = f"remediation:{intent_id}:submit"
        else:
            version = payload.get("expected_version")
            if isinstance(version, bool) or not isinstance(version, int) or version < 0:
                raise RemediationOrchestrationError("reconciliation_version_invalid")
            expected_key = f"remediation:{intent_id}:reconcile:{version}"
        if idempotency_key != expected_key:
            raise RemediationOrchestrationError("job_idempotency_key_mismatch")

        async with session_factory() as session:
            await _set_database_rls(session, trusted_org_id)
            intent = await session.scalar(
                select(RemediationIntent).where(
                    RemediationIntent.id == intent_id,
                    RemediationIntent.org_id == trusted_org_id,
                ).with_for_update()
            )
            if intent is None:
                raise RemediationOrchestrationError("remediation_intent_not_found")
            if intent.status in _TERMINAL:
                return {"intent_id": intent.id, "status": intent.status, "version": intent.version}
            if operation == "reconcile" and intent.version != payload["expected_version"]:
                return {"intent_id": intent.id, "status": intent.status, "reason_code": "stale_reconciliation_noop"}
            organization = await session.scalar(select(Organization).where(Organization.id == trusted_org_id))
            device = await session.scalar(
                select(Device).where(Device.org_id == trusted_org_id, Device.id == intent.device_id)
            )
            if organization is None or organization.status != "active":
                await transition_remediation_intent(
                    session, org_id=trusted_org_id, intent_id=intent.id,
                    to_status="failed", reason_code="organization_not_active",
                )
                await session.commit()
                return {"intent_id": intent.id, "status": "failed", "reason_code": "organization_not_active"}
            if device is None or not device.is_active or device.enrolled_at is None or device.revoked_at is not None:
                await transition_remediation_intent(
                    session, org_id=trusted_org_id, intent_id=intent.id,
                    to_status="failed", reason_code="target_device_not_enrolled",
                )
                await session.commit()
                return {"intent_id": intent.id, "status": "failed", "reason_code": "target_device_not_enrolled"}
            if intent.status not in {"queued", "submitting", "approval_pending", "platform_pending", "awaiting_verification", "unknown_outcome"}:
                raise RemediationOrchestrationError("remediation_state_not_dispatchable")
            if intent.status != "submitting":
                await transition_remediation_intent(
                    session, org_id=trusted_org_id, intent_id=intent.id,
                    to_status="submitting", reason_code=None,
                )
            plan_payload = dict(intent.plan_payload)
            await session.commit()

        try:
            result = await processor.process(
                org_id=trusted_org_id,
                intent_id=intent_id,
                plan_payload=plan_payload,
                operation=operation,
                idempotency_key=f"remediation:{intent_id}",
            )
        except Exception:
            # A transport/process crash can happen after Platform acceptance. Mark
            # outcome unknown and let the durable job retry with the same plan key.
            async with session_factory() as session:
                await _set_database_rls(session, trusted_org_id)
                current = await session.scalar(
                    select(RemediationIntent).where(
                        RemediationIntent.id == intent_id,
                        RemediationIntent.org_id == trusted_org_id,
                    ).with_for_update()
                )
                if current is not None and current.status == "submitting":
                    await transition_remediation_intent(
                        session, org_id=trusted_org_id, intent_id=intent_id,
                        to_status="unknown_outcome", reason_code="processor_outcome_unknown",
                    )
                await session.commit()
            raise RemediationOrchestrationError("processor_outcome_unknown") from None

        status = getattr(result, "status", None)
        postcondition_ids = getattr(result, "postcondition_evidence_ids", ())
        outcome_claim = getattr(result, "business_outcome_verified", False) is True
        mapping = {
            "approval_pending": "approval_pending",
            "platform_not_completed": "platform_pending",
            "verification_failed": "verification_failed",
        }
        if status == "verified" and outcome_claim and isinstance(postcondition_ids, (tuple, list)) and len(postcondition_ids) > 0:
            target_status = "verified"
        elif status == "verified":
            target_status = "verification_failed"
        else:
            target_status = mapping.get(status, "failed")
        platform_state = getattr(result, "platform_state", None)
        if not isinstance(platform_state, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", platform_state):
            platform_state = "unknown"
        action_id = getattr(result, "action_id", None)
        run_id = getattr(result, "run_id", None)
        execution_id = getattr(result, "execution_id", None)
        platform_evidence = getattr(result, "platform_evidence_ids", ())
        audit_ids = getattr(result, "audit_event_ids", ())
        reason_code = getattr(result, "reason_code", None)
        if target_status == "verification_failed" and status == "verified":
            reason_code = "postcondition_evidence_missing_or_unverified"
        if target_status == "failed" and not isinstance(reason_code, str):
            reason_code = "processor_result_invalid"
        safe_action_id = str(action_id) if action_id is not None else ""
        if safe_action_id and not _SAFE_ID.fullmatch(safe_action_id):
            safe_action_id = ""
        safe_metadata = {
            "action_id": safe_action_id,
            "business_outcome_verified": target_status == "verified" and outcome_claim and bool(postcondition_ids),
        }
        async with session_factory() as session:
            await _set_database_rls(session, trusted_org_id)
            current = await session.scalar(
                select(RemediationIntent).where(
                    RemediationIntent.id == intent_id,
                    RemediationIntent.org_id == trusted_org_id,
                ).with_for_update()
            )
            if current is None:
                raise RemediationOrchestrationError("remediation_intent_not_found")
            if current.status in _TERMINAL:
                return {"intent_id": current.id, "status": current.status, "version": current.version}
            updated = await transition_remediation_intent(
                session,
                org_id=trusted_org_id,
                intent_id=intent_id,
                to_status=target_status,
                reason_code=reason_code if isinstance(reason_code, str) else None,
                platform_state=platform_state if isinstance(platform_state, str) else None,
                platform_run_id=str(run_id) if run_id is not None else None,
                platform_execution_id=str(execution_id) if execution_id is not None else None,
                platform_evidence_ids=platform_evidence,
                audit_event_ids=audit_ids,
                postcondition_evidence_ids=postcondition_ids,
                result_metadata=safe_metadata,
            )
            await session.commit()
        return {
            "intent_id": updated.id,
            "status": updated.status,
            "version": updated.version,
            "business_outcome_verified": safe_metadata["business_outcome_verified"],
        }

    return handle
