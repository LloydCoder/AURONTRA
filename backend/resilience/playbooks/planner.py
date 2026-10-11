"""Typed, fail-closed planning and dispatch contracts for Aurontra remediation.

Planning is side-effect free. Dispatch crosses the Tinlance Agent Platform SDK;
there is no local command or filesystem fallback. Public automation remains
disabled until durable orchestration and postcondition verification are ready.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from core.config import settings
from core.governed_actions import (
    GovernedActionDefinition,
    GovernedActionError,
    GovernedActionRegistry,
    PlatformGovernedActionExecutor,
    TrustedPlatformContext,
)
from tinlance_agent_platform_sdk.async_client import AsyncAgentPlatform

PlaybookName = Literal["disk_full", "service_restart", "cert_expiry", "high_cpu"]
ServiceName = Literal["application", "api", "worker"]
Risk = Literal["low", "medium", "high", "critical"]
Reversibility = Literal["reversible", "partially_reversible", "irreversible"]
DataClass = Literal["public", "internal", "confidential", "restricted"]
BlastRadius = Literal["single_process", "single_service", "single_certificate", "single_device"]

MAX_TELEMETRY_AGE_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 30
MAX_CERTIFICATE_INVENTORY_AGE_SECONDS = 86_400
DISK_PRESSURE_THRESHOLD = 85.0
HIGH_CPU_THRESHOLD = 90.0
CERTIFICATE_RENEWAL_WINDOW_DAYS = 14
PROPOSAL_TTL_SECONDS = 300
MAX_CLEANUP_BYTES = 50 * 1024 * 1024
MIN_CLEANUP_AGE_SECONDS = 3_600
MAX_PROCESS_THROTTLE_SECONDS = 300
_ACTION_KEY_BY_PLAYBOOK = {
    "disk_full": "disk_full.cleanup_candidates",
    "service_restart": "service_restart.restart",
    "cert_expiry": "cert_expiry.renew_owned_certificate",
    "high_cpu": "high_cpu.throttle_process",
}
_RISK_CONTRACT = {
    "disk_full": ("high", "irreversible", "internal", "single_device"),
    "service_restart": ("high", "partially_reversible", "internal", "single_service"),
    "cert_expiry": ("high", "partially_reversible", "internal", "single_certificate"),
    "high_cpu": ("high", "reversible", "internal", "single_process"),
}


def _utc_now(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    return value.astimezone(timezone.utc)


def _normalized_text(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def _valid_public_domain(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.rstrip(".").lower()
    pattern = r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
    return re.fullmatch(pattern, normalized) is not None


class VerifiedTelemetry(BaseModel):
    """Normalized snapshot produced by the authenticated endpoint-agent pipeline."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=64)
    source: Literal["authenticated_endpoint_agent"]
    observed_at: datetime
    evidence_id: UUID
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    disk_percent: float | None = Field(default=None, ge=0, le=100)
    process_instance_id: UUID | None = None
    unhealthy_services: tuple[ServiceName, ...] = ()

    @field_validator("tenant_id", "device_id")
    @classmethod
    def identity_values_must_be_normalized(cls, value: str) -> str:
        if not _normalized_text(value):
            raise ValueError("tenant/device identifiers must be normalized")
        return value

    @field_validator("observed_at")
    @classmethod
    def observed_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("telemetry timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)


class VerifiedCertificateInventory(BaseModel):
    """Tenant-scoped certificate inventory record, not a caller-supplied domain."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=64)
    certificate_id: UUID
    domain: str = Field(min_length=3, max_length=253)
    ownership_verified: bool
    observed_at: datetime
    evidence_id: UUID
    days_until_expiry: int = Field(ge=-36_500, le=36_500)

    @field_validator("tenant_id", "device_id")
    @classmethod
    def identity_values_must_be_normalized(cls, value: str) -> str:
        if not _normalized_text(value):
            raise ValueError("tenant/device identifiers must be normalized")
        return value

    @field_validator("observed_at")
    @classmethod
    def observed_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("certificate inventory timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)

    @field_validator("domain")
    @classmethod
    def domain_must_be_normalized_public_dns_name(cls, value: str) -> str:
        normalized = value.rstrip(".").lower()
        pattern = r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
        if not re.fullmatch(pattern, normalized):
            raise ValueError("certificate domain must be a normalized public DNS name")
        return normalized


class PlaybookPlanningContext(BaseModel):
    """Trusted input assembled by tenant-scoped repositories and verification services."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=64)
    device_active: bool
    device_enrolled: bool
    telemetry: VerifiedTelemetry | None = None
    certificate: VerifiedCertificateInventory | None = None

    @field_validator("tenant_id", "device_id")
    @classmethod
    def identity_values_must_be_normalized(cls, value: str) -> str:
        if not _normalized_text(value):
            raise ValueError("tenant/device identifiers must be normalized")
        return value


class PlaybookRequest(BaseModel):
    """Validated playbook intent; it cannot supply a raw path, command, or arbitrary domain."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    playbook_name: PlaybookName
    service_name: ServiceName | None = None


class PlaybookActionProposal(BaseModel):
    """Immutable proposal envelope; its canonical JSON string prevents nested mutation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    proposal_id: UUID
    tenant_id: str
    device_id: str
    playbook_name: PlaybookName
    action_key: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=255)
    intent: str = Field(min_length=1, max_length=2048)
    arguments_json: str = Field(min_length=2, max_length=65_536)
    risk: Risk
    reversibility: Reversibility
    data_class: DataClass
    blast_radius: BlastRadius
    source_evidence_ids: tuple[UUID, ...] = Field(min_length=1, max_length=8)
    expected_postconditions: tuple[str, ...] = Field(min_length=1, max_length=8)
    required_evidence: tuple[str, ...] = Field(min_length=1, max_length=8)
    created_at: datetime
    expires_at: datetime
    execution_enabled: Literal[False] = False
    business_outcome_verified: Literal[False] = False

    @field_validator("tenant_id", "device_id", "action_key", "resource", "intent")
    @classmethod
    def proposal_text_must_be_normalized(cls, value: str, info) -> str:
        if not _normalized_text(value):
            raise ValueError(f"{info.field_name} must be normalized text")
        if info.field_name == "action_key" and not re.fullmatch(r"[a-z0-9_.-]{1,128}", value):
            raise ValueError("action_key must be a canonical identifier")
        if info.field_name == "resource" and not re.fullmatch(r"[A-Za-z0-9:_./-]{1,255}", value):
            raise ValueError("resource must be a canonical resource identifier")
        if info.field_name == "intent" and len(value) > 2048:
            raise ValueError("intent exceeds its size bound")
        return value

    @field_validator("expected_postconditions", "required_evidence")
    @classmethod
    def evidence_codes_must_be_machine_identifiers(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not re.fullmatch(r"[a-z0-9_]{1,80}", value) for value in values):
            raise ValueError("postconditions and evidence names must be machine identifiers")
        return values

    @field_validator("arguments_json")
    @classmethod
    def arguments_must_be_canonical_json_object(cls, value: str) -> str:
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("proposal arguments must be JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("proposal arguments must be a JSON object")
        canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if canonical != value:
            raise ValueError("proposal arguments must use canonical JSON serialization")
        return value

    @field_validator("created_at", "expires_at")
    @classmethod
    def proposal_timestamps_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("proposal timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_time_window(self) -> "PlaybookActionProposal":
        if self.expires_at <= self.created_at:
            raise ValueError("proposal expiry must be after creation")
        if (self.expires_at - self.created_at).total_seconds() > PROPOSAL_TTL_SECONDS:
            raise ValueError("proposal lifetime exceeds the bounded TTL")
        if not self.source_evidence_ids:
            raise ValueError("proposal must cite at least one source evidence identifier")
        return self

    @property
    def arguments(self) -> dict[str, Any]:
        """Return a fresh argument object so callers cannot mutate stored proposal intent."""
        return json.loads(self.arguments_json)


class PlaybookPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["proposed", "not_needed", "blocked"]
    reason_code: str = Field(min_length=1, max_length=100)
    proposal: PlaybookActionProposal | None = None

    @model_validator(mode="after")
    def proposal_matches_status(self) -> "PlaybookPlan":
        if (self.status == "proposed") != (self.proposal is not None):
            raise ValueError("only a proposed plan may contain an action proposal")
        return self


class PlaybookPlanner:
    """Builds safe, bounded proposals from verified evidence; never executes them."""

    def plan(
        self,
        request: PlaybookRequest,
        context: PlaybookPlanningContext,
        *,
        now: datetime | None = None,
    ) -> PlaybookPlan:
        now = _utc_now(now)
        if context.device_active is not True or context.device_enrolled is not True:
            return self._blocked("device_not_active_and_enrolled")

        if request.playbook_name == "cert_expiry":
            return self._plan_certificate(request, context, now)

        telemetry = context.telemetry
        reason = self._telemetry_problem(context, telemetry, now)
        if reason:
            return self._blocked(reason)
        assert telemetry is not None

        if request.playbook_name == "disk_full":
            if telemetry.disk_percent is None:
                return self._blocked("disk_metric_missing")
            if telemetry.disk_percent < DISK_PRESSURE_THRESHOLD:
                return self._not_needed("disk_pressure_below_threshold")
            return self._proposal(
                context=context,
                playbook_name="disk_full",
                action_key="disk_full.cleanup_candidates",
                resource=f"device:{context.device_id}",
                intent=f"Propose bounded application-cache cleanup on device {context.device_id}",
                arguments={
                    "scope": "app_cache",
                    "max_bytes": MAX_CLEANUP_BYTES,
                    "minimum_age_seconds": MIN_CLEANUP_AGE_SECONDS,
                },
                risk="high",
                reversibility="irreversible",
                data_class="internal",
                blast_radius="single_device",
                evidence_ids=(telemetry.evidence_id,),
                expected=("disk_usage_decreases", "endpoint_agent_reports_cleanup_complete"),
                required=("before_after_disk_usage", "agent_action_receipt", "platform_execution_evidence"),
                now=now,
            )

        if request.playbook_name == "service_restart":
            service_name = request.service_name
            if service_name is None:
                return self._blocked("service_not_allowlisted")
            if service_name not in telemetry.unhealthy_services:
                return self._blocked("service_not_verified_unhealthy")
            return self._proposal(
                context=context,
                playbook_name="service_restart",
                action_key="service_restart.restart",
                resource=f"device:{context.device_id}/service:{service_name}",
                intent=f"Request Platform-governed restart of unhealthy service {service_name}",
                arguments={
                    "service_name": service_name,
                    "grace_period_seconds": 30,
                    "health_check_timeout_seconds": 60,
                },
                risk="high",
                reversibility="partially_reversible",
                data_class="internal",
                blast_radius="single_service",
                evidence_ids=(telemetry.evidence_id,),
                expected=("service_health_check_passes", "endpoint_agent_reports_restart_result"),
                required=("pre_restart_health", "agent_action_receipt", "post_restart_health", "platform_execution_evidence"),
                now=now,
            )

        if request.playbook_name == "high_cpu":
            if telemetry.cpu_percent is None:
                return self._blocked("cpu_metric_missing")
            if telemetry.cpu_percent < HIGH_CPU_THRESHOLD:
                return self._not_needed("cpu_pressure_below_threshold")
            if telemetry.process_instance_id is None:
                return self._blocked("process_identity_missing")
            return self._proposal(
                context=context,
                playbook_name="high_cpu",
                action_key="high_cpu.throttle_process",
                resource=f"device:{context.device_id}/process:{telemetry.process_instance_id}",
                intent=f"Request bounded CPU throttling for a verified process on device {context.device_id}",
                arguments={
                    "process_instance_id": str(telemetry.process_instance_id),
                    "target_cpu_percent": 70,
                    "duration_seconds": MAX_PROCESS_THROTTLE_SECONDS,
                },
                risk="high",
                reversibility="reversible",
                data_class="internal",
                blast_radius="single_process",
                evidence_ids=(telemetry.evidence_id,),
                expected=("process_cpu_reduced", "throttle_expires_automatically"),
                required=("pre_action_process_identity", "agent_action_receipt", "post_action_cpu_sample", "platform_execution_evidence"),
                now=now,
            )

        return self._blocked("playbook_not_supported")

    def _plan_certificate(
        self,
        request: PlaybookRequest,
        context: PlaybookPlanningContext,
        now: datetime,
    ) -> PlaybookPlan:
        certificate = context.certificate
        if certificate is None:
            return self._blocked("certificate_inventory_missing")
        if certificate.tenant_id != context.tenant_id or certificate.device_id != context.device_id:
            return self._blocked("certificate_tenant_or_device_mismatch")
        if not certificate.ownership_verified:
            return self._blocked("domain_ownership_unverified")
        age = (now - certificate.observed_at).total_seconds()
        if age < -MAX_CLOCK_SKEW_SECONDS:
            return self._blocked("certificate_inventory_from_future")
        if age > MAX_CERTIFICATE_INVENTORY_AGE_SECONDS:
            return self._blocked("certificate_inventory_stale")
        if certificate.days_until_expiry > CERTIFICATE_RENEWAL_WINDOW_DAYS:
            return self._not_needed("certificate_outside_renewal_window")
        return self._proposal(
            context=context,
            playbook_name="cert_expiry",
            action_key="cert_expiry.renew_owned_certificate",
            resource=f"certificate:{certificate.certificate_id}",
            intent=f"Request Platform-governed renewal for verified certificate {certificate.certificate_id}",
            arguments={
                "certificate_id": str(certificate.certificate_id),
                "domain": certificate.domain,
            },
            risk="high",
            reversibility="partially_reversible",
            data_class="internal",
            blast_radius="single_certificate",
            evidence_ids=(certificate.evidence_id,),
            expected=("renewed_certificate_is_valid", "certificate_chain_validates", "endpoint_reports_new_expiry"),
            required=("ownership_proof", "pre_renewal_certificate_fingerprint", "renewal_receipt", "post_renewal_validation", "platform_execution_evidence"),
            now=now,
        )

    @staticmethod
    def _telemetry_problem(
        context: PlaybookPlanningContext,
        telemetry: VerifiedTelemetry | None,
        now: datetime,
    ) -> str | None:
        if telemetry is None:
            return "verified_telemetry_missing"
        if telemetry.tenant_id != context.tenant_id or telemetry.device_id != context.device_id:
            return "telemetry_tenant_or_device_mismatch"
        age = (now - telemetry.observed_at).total_seconds()
        if age < -MAX_CLOCK_SKEW_SECONDS:
            return "telemetry_from_future"
        if age > MAX_TELEMETRY_AGE_SECONDS:
            return "telemetry_stale"
        return None

    @staticmethod
    def _blocked(reason: str) -> PlaybookPlan:
        return PlaybookPlan(status="blocked", reason_code=reason, proposal=None)

    @staticmethod
    def _not_needed(reason: str) -> PlaybookPlan:
        return PlaybookPlan(status="not_needed", reason_code=reason, proposal=None)

    @staticmethod
    def _proposal(
        *,
        context: PlaybookPlanningContext,
        playbook_name: PlaybookName,
        action_key: str,
        resource: str,
        intent: str,
        arguments: dict[str, Any],
        risk: Risk,
        reversibility: Reversibility,
        data_class: DataClass,
        blast_radius: BlastRadius,
        evidence_ids: tuple[UUID, ...],
        expected: tuple[str, ...],
        required: tuple[str, ...],
        now: datetime,
    ) -> PlaybookPlan:
        proposal = PlaybookActionProposal(
            proposal_id=uuid4(),
            tenant_id=context.tenant_id,
            device_id=context.device_id,
            playbook_name=playbook_name,
            action_key=action_key,
            resource=resource,
            intent=intent,
            arguments_json=json.dumps(arguments, sort_keys=True, separators=(",", ":"), allow_nan=False),
            risk=risk,
            reversibility=reversibility,
            data_class=data_class,
            blast_radius=blast_radius,
            source_evidence_ids=evidence_ids,
            expected_postconditions=expected,
            required_evidence=required,
            created_at=now,
            expires_at=now + timedelta(seconds=PROPOSAL_TTL_SECONDS),
        )
        return PlaybookPlan(status="proposed", reason_code="verified_signal_proposal_created", proposal=proposal)


class PlaybookDispatchResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["not_dispatched", "submitted", "approval_pending", "completed_unverified", "platform_failed"]
    proposal_id: UUID
    reason_code: str | None = None
    retryable: bool = False
    run_id: UUID | None = None
    execution_id: UUID | None = None
    platform_state: str | None = None
    evidence_ids: tuple[UUID, ...] = ()
    audit_event_ids: tuple[UUID, ...] = ()
    business_outcome_verified: Literal[False] = False


def _proposal_contract_problem(proposal: PlaybookActionProposal, now: datetime) -> str | None:
    """Revalidate proposal shape at the dispatch boundary; do not trust a model alone."""
    if proposal.action_key != _ACTION_KEY_BY_PLAYBOOK[proposal.playbook_name]:
        return "proposal_action_key_mismatch"
    if (
        proposal.risk,
        proposal.reversibility,
        proposal.data_class,
        proposal.blast_radius,
    ) != _RISK_CONTRACT[proposal.playbook_name]:
        return "proposal_risk_contract_mismatch"
    if proposal.created_at > now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        return "proposal_created_in_future"
    if not proposal.source_evidence_ids:
        return "proposal_evidence_missing"

    args = proposal.arguments
    if proposal.playbook_name == "disk_full":
        if set(args) != {"scope", "max_bytes", "minimum_age_seconds"}:
            return "proposal_arguments_invalid"
        if (
            args["scope"] != "app_cache"
            or type(args["max_bytes"]) is not int
            or not 1 <= args["max_bytes"] <= MAX_CLEANUP_BYTES
            or type(args["minimum_age_seconds"]) is not int
            or not MIN_CLEANUP_AGE_SECONDS <= args["minimum_age_seconds"] <= 604_800
            or proposal.resource != f"device:{proposal.device_id}"
        ):
            return "proposal_arguments_out_of_bounds"
    elif proposal.playbook_name == "service_restart":
        if set(args) != {"service_name", "grace_period_seconds", "health_check_timeout_seconds"}:
            return "proposal_arguments_invalid"
        service = args["service_name"]
        if (
            not isinstance(service, str)
            or service not in {"application", "api", "worker"}
            or type(args["grace_period_seconds"]) is not int
            or not 0 <= args["grace_period_seconds"] <= 60
            or type(args["health_check_timeout_seconds"]) is not int
            or not 1 <= args["health_check_timeout_seconds"] <= 120
            or proposal.resource != f"device:{proposal.device_id}/service:{service}"
        ):
            return "proposal_arguments_out_of_bounds"
    elif proposal.playbook_name == "cert_expiry":
        if set(args) != {"certificate_id", "domain"}:
            return "proposal_arguments_invalid"
        try:
            certificate_id = UUID(args["certificate_id"])
        except (TypeError, ValueError, AttributeError):
            return "proposal_certificate_id_invalid"
        if (
            not _valid_public_domain(args["domain"])
            or args["domain"] != args["domain"].lower().rstrip(".")
            or proposal.resource != f"certificate:{certificate_id}"
        ):
            return "proposal_certificate_binding_invalid"
    elif proposal.playbook_name == "high_cpu":
        if set(args) != {"process_instance_id", "target_cpu_percent", "duration_seconds"}:
            return "proposal_arguments_invalid"
        try:
            process_id = UUID(args["process_instance_id"])
        except (TypeError, ValueError, AttributeError):
            return "proposal_process_id_invalid"
        if (
            type(args["target_cpu_percent"]) is not int
            or not 1 <= args["target_cpu_percent"] <= 99
            or type(args["duration_seconds"]) is not int
            or not 1 <= args["duration_seconds"] <= MAX_PROCESS_THROTTLE_SECONDS
            or proposal.resource != f"device:{proposal.device_id}/process:{process_id}"
        ):
            return "proposal_arguments_out_of_bounds"
    return None


class PlaybookActionDispatcher:
    """Optional Platform dispatcher; empty registry and disabled flag fail closed."""

    def __init__(
        self,
        registry: GovernedActionRegistry | None = None,
        *,
        client_factory: Callable[[UUID, str, TrustedPlatformContext], AsyncAgentPlatform] | None = None,
        credential_provider: Callable[[TrustedPlatformContext], str] | None = None,
    ) -> None:
        self._registry = registry if registry is not None else GovernedActionRegistry()
        self._executor = PlatformGovernedActionExecutor(
            self._registry,
            client_factory=client_factory,
            credential_provider=credential_provider,
        )

    async def dispatch(
        self,
        proposal: PlaybookActionProposal,
        context: TrustedPlatformContext,
        *,
        now: datetime | None = None,
    ) -> PlaybookDispatchResult:
        now = _utc_now(now)
        if not isinstance(context, TrustedPlatformContext):
            return self._not_dispatched(proposal, "trusted_platform_context_required")
        if proposal.expires_at <= now:
            return self._not_dispatched(proposal, "proposal_expired")
        if proposal.tenant_id != context.tenant_id:
            return self._not_dispatched(proposal, "proposal_tenant_mismatch")
        contract_problem = _proposal_contract_problem(proposal, now)
        if contract_problem:
            return self._not_dispatched(proposal, contract_problem)
        if not settings.AGENT_PLATFORM_ENABLED:
            return self._not_dispatched(proposal, "platform_integration_disabled")

        try:
            definition: GovernedActionDefinition = self._registry.get(proposal.action_key)
        except GovernedActionError as exc:
            return self._not_dispatched(proposal, exc.code, retryable=exc.retryable)

        if (
            definition.risk != proposal.risk
            or definition.reversibility != proposal.reversibility
            or definition.data_class != proposal.data_class
            or definition.blast_radius != proposal.blast_radius
        ):
            return self._not_dispatched(proposal, "action_binding_metadata_mismatch")
        arguments = proposal.arguments
        if not set(arguments).issubset(definition.allowed_arguments):
            return self._not_dispatched(proposal, "action_binding_argument_mismatch")
        if not definition.required_arguments.issubset(arguments):
            return self._not_dispatched(proposal, "action_binding_required_argument_missing")

        try:
            result = await self._executor.submit(
                action_id=proposal.proposal_id,
                context=context,
                action_key=proposal.action_key,
                resource=proposal.resource,
                intent=proposal.intent,
                arguments=arguments,
            )
        except GovernedActionError as exc:
            return self._not_dispatched(proposal, exc.code, retryable=exc.retryable, run_id=exc.run_id)

        if result.platform_state in {"failed", "cancelled"} or result.error_code:
            status: Literal["not_dispatched", "submitted", "approval_pending", "completed_unverified", "platform_failed"] = "platform_failed"
        elif result.platform_state == "waiting_approval":
            status = "approval_pending"
        elif result.platform_state == "completed":
            status = "completed_unverified"
        else:
            status = "submitted"
        return PlaybookDispatchResult(
            status=status,
            proposal_id=proposal.proposal_id,
            reason_code=result.error_code,
            retryable=result.retryable,
            run_id=result.run_id,
            execution_id=result.execution_id,
            platform_state=result.platform_state,
            evidence_ids=result.evidence_ids,
            audit_event_ids=result.audit_event_ids,
            business_outcome_verified=False,
        )

    @staticmethod
    def _not_dispatched(
        proposal: PlaybookActionProposal,
        reason_code: str,
        *,
        retryable: bool = False,
        run_id: UUID | None = None,
    ) -> PlaybookDispatchResult:
        return PlaybookDispatchResult(
            status="not_dispatched",
            proposal_id=proposal.proposal_id,
            reason_code=reason_code,
            retryable=retryable,
            run_id=run_id,
            business_outcome_verified=False,
        )
