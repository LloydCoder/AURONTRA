"""Durable remediation intent, idempotency, tenant binding and crash recovery tests."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select

from core.config import settings
from core.database import AsyncSessionLocal
from core.job_queue import IdempotencyConflict
from core.remediation_orchestrator import (
    RemediationOrchestrationError,
    enqueue_remediation_intent,
    enqueue_stale_reconciliation_jobs,
    get_remediation_intent,
    make_remediation_job_handler,
    transition_remediation_intent,
)
from models.device import Device
from models.durable_job import DurableJob, OutboxEvent
from resilience.playbooks.planner import TrustedRemediationTarget, build_remediation_plan


def _plan():
    now = datetime.now(timezone.utc)
    target = TrustedRemediationTarget(
        tenant_id="test-tenant",
        device_id="device-01",
        actor_subject="operator-01",
        source_evidence_id="evidence-01",
        observed_at=now - timedelta(seconds=30),
    )
    return build_remediation_plan("high_cpu", target, {"cpu_percent": 95}, now=now)


async def _prepare_device(session):
    session.info["tenant_id"] = "test-tenant"
    session.add(Device(
        id="device-01",
        org_id="test-tenant",
        name="Enrolled test device",
        is_active=True,
        enrolled_at=datetime.now(timezone.utc),
        revoked_at=None,
    ))
    await session.flush()


@pytest.mark.asyncio
async def test_intent_outbox_and_job_are_atomic_and_idempotent_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "REMEDIATION_SUBMISSION_ENABLED", True)
    async with AsyncSessionLocal() as session:
        await _prepare_device(session)
        plan = _plan()
        first, created = await enqueue_remediation_intent(session, plan)
        duplicate, created_again = await enqueue_remediation_intent(session, plan)
        assert created is True
        assert created_again is False
        assert first.id == duplicate.id == plan.plan_id
        assert first.status == "queued"
        jobs = list((await session.scalars(select(DurableJob).where(
            DurableJob.org_id == "test-tenant",
            DurableJob.job_type == "remediation.submit",
        ))).all())
        events = list((await session.scalars(select(OutboxEvent).where(
            OutboxEvent.org_id == "test-tenant",
            OutboxEvent.event_type == "remediation.intent.created",
        ))).all())
        assert len(jobs) == 1
        assert len(events) == 1
        assert jobs[0].payload == {
            "org_id": "test-tenant", "intent_id": plan.plan_id, "operation": "submit"
        }
        await session.commit()


@pytest.mark.asyncio
async def test_intent_is_saved_as_proposal_when_submission_is_disabled(monkeypatch):
    monkeypatch.setattr(settings, "REMEDIATION_SUBMISSION_ENABLED", False)
    async with AsyncSessionLocal() as session:
        await _prepare_device(session)
        plan = _plan()
        intent, created = await enqueue_remediation_intent(session, plan)
        assert created is True
        assert intent.status == "proposed"
        assert await session.scalar(select(DurableJob).where(DurableJob.job_type == "remediation.submit")) is None
        await session.commit()


@pytest.mark.asyncio
async def test_idempotency_key_cannot_be_reused_for_modified_plan(monkeypatch):
    from dataclasses import replace
    monkeypatch.setattr(settings, "REMEDIATION_SUBMISSION_ENABLED", False)
    async with AsyncSessionLocal() as session:
        await _prepare_device(session)
        plan = _plan()
        await enqueue_remediation_intent(session, plan)
        with pytest.raises(IdempotencyConflict):
            await enqueue_remediation_intent(
                session, replace(plan, recommended_action="run_arbitrary_command")
            )


@pytest.mark.asyncio
async def test_unenrolled_or_revoked_device_cannot_receive_intent():
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        session.add(Device(id="device-01", org_id="test-tenant", name="Legacy inactive", is_active=True))
        await session.flush()
        with pytest.raises(RemediationOrchestrationError, match="not_enrolled"):
            await enqueue_remediation_intent(session, _plan())


@pytest.mark.asyncio
async def test_state_machine_rejects_illegal_transition_and_is_idempotent():
    async with AsyncSessionLocal() as session:
        await _prepare_device(session)
        plan = _plan()
        intent, _ = await enqueue_remediation_intent(session, plan)
        queued = await transition_remediation_intent(
            session, org_id="test-tenant", intent_id=intent.id, to_status="queued"
        )
        version = queued.version
        duplicate = await transition_remediation_intent(
            session, org_id="test-tenant", intent_id=intent.id, to_status="queued"
        )
        assert duplicate.version == version
        with pytest.raises(RemediationOrchestrationError, match="transition_not_allowed"):
            await transition_remediation_intent(
                session, org_id="test-tenant", intent_id=intent.id, to_status="verified"
            )
        await session.commit()


class _Processor:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    async def process(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.result


def _verified_result(plan):
    return SimpleNamespace(
        status="verified",
        action_id=plan.plan_id,
        platform_state="completed",
        run_id=None,
        execution_id=str(uuid4()),
        platform_evidence_ids=("platform-evidence-01",),
        audit_event_ids=("audit-event-01",),
        postcondition_evidence_ids=("verification-01",),
        reason_code="postcondition_confirmed",
        business_outcome_verified=True,
    )


@pytest.mark.asyncio
async def test_worker_persists_verified_result_only_with_postcondition_evidence(monkeypatch):
    monkeypatch.setattr(settings, "REMEDIATION_SUBMISSION_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    plan = _plan()
    processor = _Processor(_verified_result(plan))
    async with AsyncSessionLocal() as session:
        await _prepare_device(session)
        intent, _ = await enqueue_remediation_intent(session, plan)
        await session.commit()

    handler = make_remediation_job_handler(session_factory=AsyncSessionLocal, processor=processor)
    result = await handler(
        {"org_id": "test-tenant", "intent_id": plan.plan_id, "operation": "submit"},
        f"remediation:{plan.plan_id}:submit",
        "test-tenant",
    )
    assert result["status"] == "verified"
    assert result["business_outcome_verified"] is True
    assert len(processor.calls) == 1
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        persisted = await get_remediation_intent(session, org_id="test-tenant", intent_id=plan.plan_id)
        assert persisted.status == "verified"
        assert persisted.postcondition_evidence_ids == ["verification-01"]
        assert persisted.platform_evidence_ids == ["platform-evidence-01"]
        assert persisted.completed_at is not None


@pytest.mark.asyncio
async def test_processor_crash_records_unknown_outcome_then_reuses_same_idempotency_key(monkeypatch):
    monkeypatch.setattr(settings, "REMEDIATION_SUBMISSION_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    plan = _plan()
    async with AsyncSessionLocal() as session:
        await _prepare_device(session)
        await enqueue_remediation_intent(session, plan)
        await session.commit()

    failing = _Processor(error=RuntimeError("secret provider response must not persist"))
    handler = make_remediation_job_handler(session_factory=AsyncSessionLocal, processor=failing)
    key = f"remediation:{plan.plan_id}:submit"
    with pytest.raises(RemediationOrchestrationError, match="processor_outcome_unknown"):
        await handler(
            {"org_id": "test-tenant", "intent_id": plan.plan_id, "operation": "submit"},
            key, "test-tenant",
        )
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        persisted = await get_remediation_intent(session, org_id="test-tenant", intent_id=plan.plan_id)
        assert persisted.status == "unknown_outcome"
        assert persisted.last_error_code == "processor_outcome_unknown"

    succeeding = _Processor(_verified_result(plan))
    retry_handler = make_remediation_job_handler(session_factory=AsyncSessionLocal, processor=succeeding)
    retry = await retry_handler(
        {"org_id": "test-tenant", "intent_id": plan.plan_id, "operation": "submit"},
        key, "test-tenant",
    )
    assert retry["status"] == "verified"
    assert succeeding.calls[0]["idempotency_key"] == f"remediation:{plan.plan_id}"


@pytest.mark.asyncio
async def test_stale_pending_intent_gets_idempotent_reconciliation_job(monkeypatch):
    monkeypatch.setattr(settings, "REMEDIATION_SUBMISSION_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    async with AsyncSessionLocal() as session:
        await _prepare_device(session)
        plan = _plan()
        intent, _ = await enqueue_remediation_intent(session, plan)
        await transition_remediation_intent(
            session, org_id="test-tenant", intent_id=intent.id, to_status="submitting"
        )
        pending = await transition_remediation_intent(
            session, org_id="test-tenant", intent_id=intent.id, to_status="approval_pending"
        )
        pending.updated_at = datetime.now(timezone.utc) - timedelta(minutes=10)
        await session.flush()
        scheduled = await enqueue_stale_reconciliation_jobs(
            session, org_id="test-tenant", older_than_seconds=60
        )
        again = await enqueue_stale_reconciliation_jobs(
            session, org_id="test-tenant", older_than_seconds=60
        )
        assert scheduled == 1
        assert again == 0
        jobs = list((await session.scalars(select(DurableJob).where(
            DurableJob.org_id == "test-tenant",
            DurableJob.job_type == "remediation.reconcile",
        ))).all())
        assert len(jobs) == 1
        assert jobs[0].payload["expected_version"] == pending.version
        await session.commit()


@pytest.mark.asyncio
async def test_tenant_mismatch_is_rejected_before_processor_call(monkeypatch):
    monkeypatch.setattr(settings, "REMEDIATION_SUBMISSION_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    processor = _Processor(_verified_result(_plan()))
    handler = make_remediation_job_handler(session_factory=AsyncSessionLocal, processor=processor)
    with pytest.raises(RemediationOrchestrationError, match="tenant_context_mismatch"):
        await handler(
            {"org_id": "other-tenant", "intent_id": _plan().plan_id, "operation": "submit"},
            f"remediation:{_plan().plan_id}:submit",
            "test-tenant",
        )
    assert processor.calls == []


@pytest.mark.asyncio
async def test_verified_status_without_verified_postcondition_is_downgraded(monkeypatch):
    monkeypatch.setattr(settings, "REMEDIATION_SUBMISSION_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    plan = _plan()
    bad = _verified_result(plan)
    bad.business_outcome_verified = False
    bad.postcondition_evidence_ids = ()
    async with AsyncSessionLocal() as session:
        await _prepare_device(session)
        await enqueue_remediation_intent(session, plan)
        await session.commit()
    handler = make_remediation_job_handler(
        session_factory=AsyncSessionLocal, processor=_Processor(bad)
    )
    result = await handler(
        {"org_id": "test-tenant", "intent_id": plan.plan_id, "operation": "submit"},
        f"remediation:{plan.plan_id}:submit", "test-tenant",
    )
    assert result["status"] == "verification_failed"
    assert result["business_outcome_verified"] is False
