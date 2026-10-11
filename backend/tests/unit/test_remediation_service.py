"""Tests for governed remediation submission and independent postcondition checks."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from core.config import settings
from core.governed_actions import GovernedActionResult, TrustedPlatformContext
from resilience.playbooks.planner import TrustedRemediationTarget, build_remediation_plan
from resilience.playbooks.remediation_service import (
    PostconditionVerification,
    RemediationService,
    RemediationSubmissionError,
)

TENANT = "tenant-01"
ACTOR = "operator-01"
DEVICE = "device-01"
EVIDENCE = "evidence-01"
AGENT_ID = UUID("d78f76e7-09b5-4a80-aabb-5e45c59ef1bb")
TASK_ID = UUID("e8a80e54-fd5e-44f4-8dd9-2b2d5c0a61d4")
NOW = datetime.now(timezone.utc)


def _target():
    return TrustedRemediationTarget(
        tenant_id=TENANT, device_id=DEVICE, actor_subject=ACTOR,
        source_evidence_id=EVIDENCE, observed_at=NOW - timedelta(seconds=30),
    )


def _context():
    return TrustedPlatformContext(TENANT, ACTOR, AGENT_ID, TASK_ID)


def _plan():
    return build_remediation_plan("high_cpu", _target(), {"cpu_percent": 95}, now=NOW)


class FakeExecutor:
    def __init__(self, result=None, error=None):
        self.result = result or GovernedActionResult(
            action_id=UUID(_plan().plan_id),
            run_id=uuid4(),
            platform_state="completed",
            execution_id=uuid4(),
            evidence_ids=(uuid4(),),
            audit_event_ids=(uuid4(),),
            error_code=None,
            retryable=False,
            business_outcome_verified=False,
        )
        self.error = error
        self.calls = []

    async def submit(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.result


class FakeVerifier:
    def __init__(self, result=None, error=None):
        self.result = result or PostconditionVerification(True, "postcondition_confirmed", ("verification-01",))
        self.error = error
        self.calls = []

    async def verify(self, plan, target, result):
        self.calls.append((plan, target, result))
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def enable_submission(monkeypatch):
    monkeypatch.setattr(settings, "REMEDIATION_SUBMISSION_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)


@pytest.mark.asyncio
async def test_disabled_by_default_prevents_any_platform_call(monkeypatch):
    monkeypatch.setattr(settings, "REMEDIATION_SUBMISSION_ENABLED", False)
    executor = FakeExecutor()
    with pytest.raises(RemediationSubmissionError, match="disabled"):
        await RemediationService(executor).submit(
            plan=_plan(), target=_target(), platform_context=_context(), verifier=FakeVerifier()
        )
    assert executor.calls == []


@pytest.mark.asyncio
async def test_missing_verifier_prevents_platform_call(enable_submission):
    executor = FakeExecutor()
    with pytest.raises(RemediationSubmissionError, match="postcondition_verifier_required"):
        await RemediationService(executor).submit(
            plan=_plan(), target=_target(), platform_context=_context(), verifier=None
        )
    assert executor.calls == []


@pytest.mark.asyncio
async def test_plan_target_or_platform_identity_mismatch_fails_before_platform_call(enable_submission):
    executor = FakeExecutor()
    service = RemediationService(executor)
    with pytest.raises(RemediationSubmissionError, match="context_mismatch"):
        await service.submit(
            plan=_plan(),
            target=_target(),
            platform_context=TrustedPlatformContext("other-tenant", ACTOR, AGENT_ID, TASK_ID),
            verifier=FakeVerifier(),
        )
    assert executor.calls == []


@pytest.mark.asyncio
async def test_approval_pending_is_not_promoted_to_execution_or_verified_outcome(enable_submission):
    result = GovernedActionResult(
        action_id=UUID(_plan().plan_id), run_id=uuid4(),
        platform_state="waiting_approval", execution_id=None,
        evidence_ids=(), audit_event_ids=(), error_code=None, retryable=False,
    )
    executor, verifier = FakeExecutor(result), FakeVerifier()
    submitted = await RemediationService(executor).submit(
        plan=_plan(), target=_target(), platform_context=_context(), verifier=verifier
    )
    assert submitted.status == "approval_pending"
    assert submitted.postcondition_verified is False
    assert submitted.business_outcome_verified is False
    assert verifier.calls == []


@pytest.mark.asyncio
async def test_verified_postcondition_requires_independent_evidence(enable_submission):
    executor = FakeExecutor()
    verifier = FakeVerifier(PostconditionVerification(True, "verified", ("state-read-01",)))
    submitted = await RemediationService(executor).submit(
        plan=_plan(), target=_target(), platform_context=_context(), verifier=verifier
    )
    assert submitted.status == "verified"
    assert submitted.business_outcome_verified is True
    assert submitted.postcondition_evidence_ids == ("state-read-01",)
    assert executor.calls[0]["action_key"] == "remediation.cpu.diagnostics"
    assert executor.calls[0]["arguments"] == {
        "device_id": DEVICE, "cpu_percent": 95.0, "source_evidence_id": EVIDENCE,
    }


@pytest.mark.asyncio
async def test_verifier_success_without_evidence_is_not_verified(enable_submission):
    executor = FakeExecutor()
    verifier = FakeVerifier(PostconditionVerification(True, "verified", ()))
    submitted = await RemediationService(executor).submit(
        plan=_plan(), target=_target(), platform_context=_context(), verifier=verifier
    )
    assert submitted.status == "verification_failed"
    assert submitted.reason_code == "postcondition_evidence_missing"
    assert submitted.business_outcome_verified is False


@pytest.mark.asyncio
async def test_negative_postcondition_result_is_not_verified(enable_submission):
    executor = FakeExecutor()
    verifier = FakeVerifier(PostconditionVerification(False, "service_still_unhealthy", ("state-read-02",)))
    submitted = await RemediationService(executor).submit(
        plan=_plan(), target=_target(), platform_context=_context(), verifier=verifier
    )
    assert submitted.status == "verification_failed"
    assert submitted.business_outcome_verified is False


@pytest.mark.asyncio
async def test_verifier_exception_is_sanitized_and_fails_closed(enable_submission):
    executor = FakeExecutor()
    verifier = FakeVerifier(error=RuntimeError("private host data and secret"))
    submitted = await RemediationService(executor).submit(
        plan=_plan(), target=_target(), platform_context=_context(), verifier=verifier
    )
    assert submitted.status == "verification_failed"
    assert submitted.reason_code == "postcondition_verifier_error"
    assert "private host data" not in submitted.reason_code


@pytest.mark.asyncio
async def test_submission_uses_stable_plan_id_for_idempotent_platform_action(enable_submission):
    executor = FakeExecutor()
    await RemediationService(executor).submit(
        plan=_plan(), target=_target(), platform_context=_context(), verifier=FakeVerifier()
    )
    assert executor.calls[0]["action_id"] == UUID(_plan().plan_id)


@pytest.mark.asyncio
async def test_modified_plan_action_is_rejected_before_platform_call(enable_submission):
    from dataclasses import replace
    original = _plan()
    forged = replace(original, recommended_action="execute_arbitrary_command", risk="low", requires_approval=False)
    executor = FakeExecutor()
    with pytest.raises(RemediationSubmissionError, match="plan_integrity_failed"):
        await RemediationService(executor).submit(
            plan=forged, target=_target(), platform_context=_context(), verifier=FakeVerifier()
        )
    assert executor.calls == []


def test_postcondition_reason_and_evidence_are_strictly_validated():
    with pytest.raises(ValueError, match="reason code"):
        PostconditionVerification(False, "secret token must not be returned")
    with pytest.raises(ValueError, match="evidence reference"):
        PostconditionVerification(True, "verified", ("private data\nsecret",))


@pytest.mark.asyncio
async def test_plan_with_blocked_status_never_submits(enable_submission):
    blocked = build_remediation_plan("high_cpu", _target(), {"cpu_percent": 20}, now=NOW)
    executor = FakeExecutor()
    with pytest.raises(RemediationSubmissionError, match="not_proposed"):
        await RemediationService(executor).submit(
            plan=blocked, target=_target(), platform_context=_context(), verifier=FakeVerifier()
        )
    assert executor.calls == []
