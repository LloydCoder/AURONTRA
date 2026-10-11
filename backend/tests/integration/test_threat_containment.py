"""Threat containment state machine, identity binding, and verification tests."""
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from core.config import settings
from core.database import AsyncSessionLocal
from core.governed_actions import GovernedActionResult, TrustedPlatformContext
from core.threat_containment import (
    ContainmentVerification,
    ThreatContainmentError,
    ThreatContainmentService,
)
from models.device import Device
from models.threat_containment_attempt import ThreatContainmentAttempt
from models.threat_finding import ThreatFinding
from models.telemetry_record import TelemetryRecord


def _context():
    return TrustedPlatformContext(
        tenant_id="test-tenant",
        subject_id="test-runner",
        agent_id=uuid4(),
        task_id=uuid4(),
    )


async def _seed_finding(*, device_id="contain-device-01", last_seen=None):
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        session.add(Device(
            id=device_id,
            org_id="test-tenant",
            name="Containment test endpoint",
            is_active=True,
            enrolled_at=now,
            revoked_at=None,
            last_seen_at=last_seen or now,
        ))
        telemetry_id = str(uuid4())
        telemetry = TelemetryRecord(
            id=telemetry_id,
            org_id="test-tenant",
            device_id=device_id,
            event_id=str(uuid4()),
            schema_version="1",
            source="endpoint_agent",
            agent_version="test-agent/1.0",
            key_thumbprint="test-thumbprint",
            proof_jti=f"proof-{uuid4().hex}",
            request_id=f"request-{uuid4().hex}",
            request_hash="a" * 64,
            payload_hash="b" * 64,
            observed_at=now,
            metrics={"cpu_percent": 97},
            missing_metrics=[],
            quality_flags=[],
            computed_score=91,
            score_components={"cpu_percent": 97},
            score_status="ok",
            retention_expires_at=now + timedelta(days=90),
        )
        session.add(telemetry)
        finding = ThreatFinding(
            id=str(uuid4()),
            org_id="test-tenant",
            event_id=f"contain-event-{uuid4().hex}",
            device_id=device_id,
            telemetry_record_id=telemetry_id,
            source="endpoint_agent",
            detector_version="threat-heuristic.v2",
            observed_at=now,
            signal_sha256="a" * 64,
            signal={"src_ip": "192.0.2.90", "protocol": "QUIC"},
            assessment={"containment_recommended": True, "blocked": False, "containment_verified": False},
            score=91,
            threat_level="critical",
            mitre_ttp="T1071",
            decision_status="assessed",
            containment_verified=False,
        )
        session.add(finding)
        await session.commit()
        return finding.id, device_id


class FakeExecutor:
    def __init__(self, *, state="completed", execution=True, retryable=False):
        self.state = state
        self.execution = execution
        self.retryable = retryable
        self.calls = []

    async def submit(self, **kwargs):
        self.calls.append(kwargs)
        execution_id = uuid4() if self.execution else None
        return GovernedActionResult(
            action_id=kwargs["action_id"],
            run_id=uuid4(),
            platform_state=self.state,
            execution_id=execution_id,
            evidence_ids=(uuid4(),) if execution_id else (),
            audit_event_ids=(uuid4(),) if execution_id else (),
            error_code=None,
            retryable=self.retryable,
            business_outcome_verified=False,
        )


class FakeVerifier:
    def __init__(self, *, verified=True, isolation_active=True, wrong_device=False, stale=False):
        self.verified = verified
        self.isolation_active = isolation_active
        self.wrong_device = wrong_device
        self.stale = stale
        self.calls = []

    async def verify(self, *, tenant_id, device, finding, execution):
        self.calls.append((tenant_id, device.id, finding.id, execution.execution_id))
        return ContainmentVerification(
            verified=self.verified,
            isolation_active=self.isolation_active,
            tenant_id=tenant_id,
            device_id="other-device" if self.wrong_device else device.id,
            finding_id=finding.id,
            execution_id=str(execution.execution_id),
            observed_at=datetime.now(timezone.utc) - (timedelta(minutes=10) if self.stale else timedelta()),
            evidence_source="network_control_plane",
            evidence_ids=("network-isolation-evidence-01",),
            reason_code="isolation_confirmed" if self.verified and self.isolation_active else "isolation_unconfirmed",
        )


@pytest.fixture
def enable_containment(monkeypatch):
    monkeypatch.setattr(settings, "THREAT_CONTAINMENT_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)


@pytest.mark.asyncio
async def test_containment_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(settings, "THREAT_CONTAINMENT_ENABLED", False)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    finding_id, _ = await _seed_finding()
    executor = FakeExecutor()
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        with pytest.raises(ThreatContainmentError, match="containment_disabled"):
            await ThreatContainmentService(executor=executor, verifier=FakeVerifier()).contain(
                db=session, tenant_id="test-tenant", finding_id=finding_id, platform_context=_context()
            )
    assert executor.calls == []


@pytest.mark.asyncio
async def test_missing_independent_verifier_prevents_platform_submission(enable_containment):
    finding_id, _ = await _seed_finding()
    executor = FakeExecutor()
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        with pytest.raises(ThreatContainmentError, match="independent_verifier_not_configured"):
            await ThreatContainmentService(executor=executor, verifier=None).contain(
                db=session, tenant_id="test-tenant", finding_id=finding_id, platform_context=_context()
            )
    assert executor.calls == []


@pytest.mark.asyncio
async def test_containment_is_verified_only_with_independent_fresh_evidence(enable_containment):
    finding_id, device_id = await _seed_finding()
    executor, verifier = FakeExecutor(), FakeVerifier()
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        attempt, replay = await ThreatContainmentService(executor=executor, verifier=verifier).contain(
            db=session, tenant_id="test-tenant", finding_id=finding_id, platform_context=_context()
        )
        assert attempt.status == "contained"
        assert attempt.verification_evidence_ids == ["network-isolation-evidence-01"]
        assert replay is False
        finding = await session.scalar(select(ThreatFinding).where(ThreatFinding.id == finding_id))
        assert finding.device_id == device_id
        assert finding.containment_verified is True
        assert finding.assessment["blocked"] is True
        assert finding.assessment["containment_verified"] is True
        assert finding.assessment["containment_evidence_ids"] == ["network-isolation-evidence-01"]
    assert len(executor.calls) == 1
    assert executor.calls[0]["action_key"] == "threat.containment.isolate_endpoint"


@pytest.mark.asyncio
@pytest.mark.parametrize("verifier_kwargs", [
    {"verified": False},
    {"isolation_active": False},
    {"wrong_device": True},
    {"stale": True},
])
async def test_invalid_or_stale_verification_never_claims_containment(enable_containment, verifier_kwargs):
    finding_id, _ = await _seed_finding()
    executor, verifier = FakeExecutor(), FakeVerifier(**verifier_kwargs)
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        attempt, _ = await ThreatContainmentService(executor=executor, verifier=verifier).contain(
            db=session, tenant_id="test-tenant", finding_id=finding_id, platform_context=_context()
        )
        assert attempt.status == "verification_failed"
        finding = await session.scalar(select(ThreatFinding).where(ThreatFinding.id == finding_id))
        assert finding.containment_verified is False
        assert finding.assessment["blocked"] is False


@pytest.mark.asyncio
async def test_platform_approval_pending_never_calls_verifier(enable_containment):
    finding_id, _ = await _seed_finding()
    executor, verifier = FakeExecutor(state="waiting_approval", execution=False), FakeVerifier()
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        attempt, _ = await ThreatContainmentService(executor=executor, verifier=verifier).contain(
            db=session, tenant_id="test-tenant", finding_id=finding_id, platform_context=_context()
        )
        assert attempt.status == "approval_pending"
        finding = await session.scalar(select(ThreatFinding).where(ThreatFinding.id == finding_id))
        assert finding.containment_verified is False
    assert verifier.calls == []


@pytest.mark.asyncio
async def test_stale_endpoint_telemetry_prevents_containment(enable_containment):
    finding_id, _ = await _seed_finding(last_seen=datetime.now(timezone.utc) - timedelta(minutes=10))
    executor = FakeExecutor()
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        with pytest.raises(ThreatContainmentError, match="target_device_telemetry_stale"):
            await ThreatContainmentService(executor=executor, verifier=FakeVerifier()).contain(
                db=session, tenant_id="test-tenant", finding_id=finding_id, platform_context=_context()
            )
    assert executor.calls == []


@pytest.mark.asyncio
async def test_finding_without_device_binding_cannot_be_contained(enable_containment):
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        finding = ThreatFinding(
            id=str(uuid4()), org_id="test-tenant", event_id=f"unbound-{uuid4().hex}",
            device_id=None, source="network_signal", detector_version="threat-heuristic.v2",
            observed_at=now, signal_sha256="b" * 64, signal={"protocol": "QUIC"},
            assessment={"containment_recommended": True}, score=90, threat_level="critical",
            mitre_ttp="T1071", decision_status="assessed", containment_verified=False,
        )
        session.add(finding)
        await session.commit()
        finding_id = finding.id
    executor = FakeExecutor()
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        with pytest.raises(ThreatContainmentError, match="finding_not_bound_to_device"):
            await ThreatContainmentService(executor=executor, verifier=FakeVerifier()).contain(
                db=session, tenant_id="test-tenant", finding_id=finding_id, platform_context=_context()
            )
    assert executor.calls == []


@pytest.mark.asyncio
async def test_contained_finding_replay_does_not_submit_second_action(enable_containment):
    finding_id, _ = await _seed_finding()
    executor, verifier = FakeExecutor(), FakeVerifier()
    service = ThreatContainmentService(executor=executor, verifier=verifier)
    async with AsyncSessionLocal() as session:
        session.info["tenant_id"] = "test-tenant"
        first, first_replay = await service.contain(
            db=session, tenant_id="test-tenant", finding_id=finding_id, platform_context=_context()
        )
        second, second_replay = await service.contain(
            db=session, tenant_id="test-tenant", finding_id=finding_id, platform_context=_context()
        )
    assert first.status == second.status == "contained"
    assert first_replay is False
    assert second_replay is True
    assert len(executor.calls) == 1
    assert UUID(executor.calls[0]["action_id"].hex) == UUID(first.platform_action_id)
