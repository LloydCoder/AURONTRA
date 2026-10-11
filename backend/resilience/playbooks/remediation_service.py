"""Feature-gated remediation submission through the authoritative Agent Platform.

No local side-effect fallback exists. Platform approval/policy remains authoritative.
Every consequential result requires an independent postcondition verifier before
Aurontra can report the business outcome as verified.
"""
from __future__ import annotations

from dataclasses import dataclass
import logging
import re
from typing import Protocol
from uuid import UUID

from core.config import settings
from core.governed_actions import (
    GovernedActionDefinition,
    GovernedActionError,
    GovernedActionRegistry,
    GovernedActionResult,
    PlatformGovernedActionExecutor,
    TrustedPlatformContext,
)
from resilience.playbooks.planner import (
    RemediationPlan,
    TrustedRemediationTarget,
    build_remediation_plan,
)

logger = logging.getLogger(__name__)
_SAFE_EVIDENCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_REASON_CODE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")


class RemediationSubmissionError(RuntimeError):
    """Sanitized, machine-readable remediation submission failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class PostconditionVerification:
    verified: bool
    reason_code: str
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.verified) is not bool:
            raise ValueError("postcondition verified must be a boolean")
        if not isinstance(self.reason_code, str) or not _SAFE_REASON_CODE.fullmatch(self.reason_code):
            raise ValueError("postcondition reason code is invalid")
        if not isinstance(self.evidence_ids, tuple) or len(self.evidence_ids) > 32:
            raise ValueError("postcondition evidence references are invalid")
        if any(
            not isinstance(item, str) or not _SAFE_EVIDENCE_ID.fullmatch(item)
            for item in self.evidence_ids
        ):
            raise ValueError("postcondition evidence reference is invalid")


@dataclass(frozen=True, slots=True)
class RemediationSubmissionResult:
    plan_id: str
    status: str
    action_id: str
    platform_state: str | None
    execution_id: str | None
    platform_evidence_ids: tuple[str, ...]
    audit_event_ids: tuple[str, ...]
    postcondition_evidence_ids: tuple[str, ...]
    postcondition_verified: bool
    reason_code: str
    business_outcome_verified: bool


class PostconditionVerifier(Protocol):
    async def verify(
        self,
        plan: RemediationPlan,
        target: TrustedRemediationTarget,
        result: GovernedActionResult,
    ) -> PostconditionVerification:
        """Read tenant-scoped, independently sourced state; never trust tool output alone."""
        ...


# These are client-side request contracts, not permissions. The Platform operator
# must register matching capabilities/tools and apply policy/approval requirements.
# Unknown or absent registrations fail closed at the Platform boundary.
ACTION_DEFINITIONS = (
    GovernedActionDefinition(
        key="remediation.disk_cleanup.review",
        capability_id="aurontra.remediation.storage",
        capability_version="1",
        tool_name="inspect_cleanup_candidates",
        tool_version="1",
        action="inspect",
        allowed_arguments=frozenset({"device_id", "disk_percent", "source_evidence_id"}),
        required_arguments=frozenset({"device_id", "disk_percent", "source_evidence_id"}),
        risk="low",
        reversibility="reversible",
        data_class="internal",
        blast_radius="single",
        sandbox_required=True,
        evidence_required=True,
        requested_timeout_seconds=20,
        requested_tool_calls=1,
    ),
    GovernedActionDefinition(
        key="remediation.service.restart",
        capability_id="aurontra.remediation.service",
        capability_version="1",
        tool_name="restart_allowlisted_service",
        tool_version="1",
        action="restart",
        allowed_arguments=frozenset({"device_id", "service_name", "source_evidence_id"}),
        required_arguments=frozenset({"device_id", "service_name", "source_evidence_id"}),
        risk="high",
        reversibility="reversible",
        data_class="internal",
        blast_radius="single",
        sandbox_required=True,
        evidence_required=True,
        requested_timeout_seconds=30,
        requested_tool_calls=1,
    ),
    GovernedActionDefinition(
        key="remediation.certificate.renew",
        capability_id="aurontra.remediation.certificate",
        capability_version="1",
        tool_name="renew_verified_certificate",
        tool_version="1",
        action="renew",
        allowed_arguments=frozenset({
            "device_id", "domain", "days_until_expiry",
            "domain_ownership_evidence_id", "source_evidence_id",
        }),
        required_arguments=frozenset({
            "device_id", "domain", "domain_ownership_evidence_id", "source_evidence_id",
        }),
        risk="high",
        reversibility="irreversible",
        data_class="confidential",
        blast_radius="single",
        sandbox_required=True,
        evidence_required=True,
        requested_timeout_seconds=45,
        requested_tool_calls=1,
    ),
    GovernedActionDefinition(
        key="remediation.cpu.diagnostics",
        capability_id="aurontra.remediation.diagnostics",
        capability_version="1",
        tool_name="collect_process_diagnostics",
        tool_version="1",
        action="collect",
        allowed_arguments=frozenset({"device_id", "cpu_percent", "source_evidence_id"}),
        required_arguments=frozenset({"device_id", "cpu_percent", "source_evidence_id"}),
        risk="low",
        reversibility="reversible",
        data_class="internal",
        blast_radius="single",
        sandbox_required=True,
        evidence_required=True,
        requested_timeout_seconds=20,
        requested_tool_calls=1,
    ),
)
ACTION_REGISTRY = GovernedActionRegistry(ACTION_DEFINITIONS)

_ACTION_KEYS = {
    "disk_full": "remediation.disk_cleanup.review",
    "service_restart": "remediation.service.restart",
    "cert_expiry": "remediation.certificate.renew",
    "high_cpu": "remediation.cpu.diagnostics",
}


def _action_arguments(plan: RemediationPlan, target: TrustedRemediationTarget) -> dict:
    values = dict(plan.parameters)
    args = {
        "device_id": target.device_id,
        "source_evidence_id": target.source_evidence_id,
    }
    if plan.playbook == "disk_full":
        args["disk_percent"] = values["disk_percent"]
    elif plan.playbook == "service_restart":
        args["service_name"] = values["service_name"]
    elif plan.playbook == "cert_expiry":
        args.update({
            "domain": values["domain"],
            "days_until_expiry": values["days_until_expiry"],
            "domain_ownership_evidence_id": values["domain_ownership_evidence_id"],
        })
    elif plan.playbook == "high_cpu":
        args["cpu_percent"] = values["cpu_percent"]
    else:
        raise RemediationSubmissionError("playbook_not_allowlisted")
    return args


class RemediationService:
    """Submits only validated plans; refuses to operate without independent verification."""

    def __init__(self, executor: PlatformGovernedActionExecutor | None = None) -> None:
        self._executor = executor or PlatformGovernedActionExecutor(ACTION_REGISTRY)

    async def submit(
        self,
        *,
        plan: RemediationPlan,
        target: TrustedRemediationTarget,
        platform_context: TrustedPlatformContext,
        verifier: PostconditionVerifier | None,
    ) -> RemediationSubmissionResult:
        if not settings.REMEDIATION_SUBMISSION_ENABLED:
            raise RemediationSubmissionError("remediation_submission_disabled")
        if not settings.AGENT_PLATFORM_ENABLED:
            raise RemediationSubmissionError("platform_integration_disabled")
        if not isinstance(plan, RemediationPlan) or plan.status != "proposed":
            raise RemediationSubmissionError("remediation_plan_not_proposed")
        if not isinstance(target, TrustedRemediationTarget):
            raise RemediationSubmissionError("trusted_remediation_target_required")
        if not isinstance(platform_context, TrustedPlatformContext):
            raise RemediationSubmissionError("trusted_platform_context_required")
        if verifier is None or not callable(getattr(verifier, "verify", None)):
            raise RemediationSubmissionError("postcondition_verifier_required")
        if (
            plan.tenant_id != target.tenant_id
            or plan.device_id != target.device_id
            or plan.actor_subject != target.actor_subject
            or plan.source_evidence_id != target.source_evidence_id
        ):
            raise RemediationSubmissionError("plan_target_context_mismatch")
        # Rebuild the recommendation from its allowlisted parameters and current
        # evidence freshness. A caller cannot construct/alter a dataclass to
        # escalate risk, change the action, or replay a stale proposal.
        try:
            rebuilt_plan = build_remediation_plan(
                plan.playbook, target, dict(plan.parameters)
            )
        except (TypeError, ValueError):
            raise RemediationSubmissionError("remediation_plan_integrity_failed") from None
        if rebuilt_plan != plan:
            raise RemediationSubmissionError("remediation_plan_integrity_failed")
        if (
            platform_context.tenant_id != target.tenant_id
            or platform_context.subject_id != target.actor_subject
        ):
            raise RemediationSubmissionError("platform_context_mismatch")
        try:
            action_id = UUID(plan.plan_id)
            action_key = _ACTION_KEYS[plan.playbook]
            args = _action_arguments(plan, target)
            result = await self._executor.submit(
                action_id=action_id,
                context=platform_context,
                action_key=action_key,
                resource=f"device:{target.device_id}",
                intent=(
                    f"Aurontra remediation proposal {plan.plan_id}: "
                    f"{plan.recommended_action}"
                ),
                arguments=args,
            )
        except RemediationSubmissionError:
            raise
        except (GovernedActionError, KeyError, ValueError, TypeError) as exc:
            code = getattr(exc, "code", None)
            if not isinstance(code, str) or not code.replace("_", "").isalnum():
                code = "remediation_submission_rejected"
            raise RemediationSubmissionError(code) from None

        if result.execution_id is None or result.platform_state not in {"completed", "succeeded"}:
            status = "approval_pending" if result.platform_state in {
                "waiting_approval", "approval_required", "pending_approval"
            } else "platform_not_completed"
            return RemediationSubmissionResult(
                plan_id=plan.plan_id,
                status=status,
                action_id=str(result.action_id),
                platform_state=result.platform_state,
                execution_id=None if result.execution_id is None else str(result.execution_id),
                platform_evidence_ids=tuple(str(item) for item in result.evidence_ids),
                audit_event_ids=tuple(str(item) for item in result.audit_event_ids),
                postcondition_evidence_ids=(),
                postcondition_verified=False,
                reason_code=result.error_code or status,
                business_outcome_verified=False,
            )

        try:
            verification = await verifier.verify(plan, target, result)
            if not isinstance(verification, PostconditionVerification):
                raise TypeError("invalid verification result")
        except Exception as exc:
            logger.warning(
                "Remediation postcondition verification failed plan_id=%s error_type=%s",
                plan.plan_id,
                type(exc).__name__,
            )
            verification = PostconditionVerification(False, "postcondition_verifier_error")

        verified = verification.verified is True and bool(verification.evidence_ids)
        if verification.verified is True and not verification.evidence_ids:
            reason = "postcondition_evidence_missing"
        else:
            reason = verification.reason_code if verified else (
                verification.reason_code or "postcondition_not_verified"
            )
        return RemediationSubmissionResult(
            plan_id=plan.plan_id,
            status="verified" if verified else "verification_failed",
            action_id=str(result.action_id),
            platform_state=result.platform_state,
            execution_id=str(result.execution_id),
            platform_evidence_ids=tuple(str(item) for item in result.evidence_ids),
            audit_event_ids=tuple(str(item) for item in result.audit_event_ids),
            postcondition_evidence_ids=tuple(verification.evidence_ids),
            postcondition_verified=verified,
            reason_code=reason,
            business_outcome_verified=verified,
        )
