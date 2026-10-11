"""Pure, fail-closed remediation planning; this module never executes actions.

Plans are recommendations derived from tenant-scoped evidence. A plan is not an
authorization grant, approval, Platform tool registration, execution receipt, or
verified business outcome. Consequential actions must go through the Tinlance
Agent Platform and its independent policy/approval controls.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import math
import re
from typing import Any
from uuid import UUID, uuid5

_PLAN_NAMESPACE = UUID("8a7b9f82-3d11-4c0f-9c3f-73a90c9a7b01")
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$"
)
_ALLOWED_SERVICES = frozenset({"application", "api", "worker", "nginx", "postgresql", "redis"})
_MAX_EVIDENCE_AGE = timedelta(minutes=5)
_MAX_FUTURE_SKEW = timedelta(seconds=60)
_THRESHOLDS = {"disk_percent": 85.0, "cpu_percent": 85.0, "cert_days": 14.0}


@dataclass(frozen=True, slots=True)
class TrustedRemediationTarget:
    """Server-constructed target from verified identity and tenant-scoped records.

    Never construct this object directly from request JSON. The caller must load
    an active organization, an active enrolled device, and the referenced evidence
    using the authenticated tenant context before instantiating it.
    """

    tenant_id: str
    device_id: str
    actor_subject: str
    source_evidence_id: str
    observed_at: datetime

    def __post_init__(self) -> None:
        for name in ("tenant_id", "device_id", "actor_subject", "source_evidence_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
                raise ValueError(f"{name} is invalid")
        if not isinstance(self.observed_at, datetime) or self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    """Immutable recommendation; execution and outcome verification remain false."""

    plan_id: str
    tenant_id: str
    device_id: str
    actor_subject: str
    source_evidence_id: str
    playbook: str
    recommended_action: str
    risk: str
    reversible: bool
    requires_approval: bool
    status: str
    reason_code: str
    parameters: tuple[tuple[str, str | float | int], ...]
    execution_enabled: bool = False
    platform_submission_allowed: bool = False
    execution_attempted: bool = False
    enforcement_verified: bool = False
    business_outcome_verified: bool = False


def _plan_id(target: TrustedRemediationTarget, playbook: str, reason: str, params: dict[str, Any]) -> str:
    canonical = json.dumps(
        {
            "tenant_id": target.tenant_id,
            "device_id": target.device_id,
            "source_evidence_id": target.source_evidence_id,
            "playbook": playbook,
            "reason": reason,
            "parameters": params,
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return str(uuid5(_PLAN_NAMESPACE, canonical))


def _numeric(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{name}_invalid")
    if not 0 <= value <= 100:
        raise ValueError(f"{name}_out_of_range")
    return float(value)


def _blocked(target: TrustedRemediationTarget, playbook: str, reason: str) -> RemediationPlan:
    return RemediationPlan(
        plan_id=_plan_id(target, playbook, reason, {}),
        tenant_id=target.tenant_id,
        device_id=target.device_id,
        actor_subject=target.actor_subject,
        source_evidence_id=target.source_evidence_id,
        playbook=playbook,
        recommended_action="none",
        risk="unknown",
        reversible=False,
        requires_approval=True,
        status="blocked",
        reason_code=reason,
        parameters=(),
    )


def build_remediation_plan(
    playbook: str,
    target: TrustedRemediationTarget,
    evidence: dict[str, Any],
    *,
    now: datetime | None = None,
) -> RemediationPlan:
    """Build a deterministic, bounded plan from trusted target metadata and evidence.

    This function is pure: it performs no I/O, network probes, subprocess calls,
    filesystem changes, service restarts, certificate renewal, or Platform calls.
    Evidence must already be loaded and tenant-checked by the caller.
    """
    if playbook not in {"disk_full", "service_restart", "cert_expiry", "high_cpu"}:
        raise ValueError("playbook_not_allowlisted")
    if not isinstance(target, TrustedRemediationTarget):
        raise TypeError("trusted_remediation_target_required")
    if not isinstance(evidence, dict):
        return _blocked(target, playbook, "evidence_invalid")

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    age = current - target.observed_at
    if age < -_MAX_FUTURE_SKEW:
        return _blocked(target, playbook, "evidence_timestamp_in_future")
    if age > _MAX_EVIDENCE_AGE:
        return _blocked(target, playbook, "evidence_stale")

    try:
        if playbook == "disk_full":
            disk = _numeric(evidence.get("disk_percent"), "disk_percent")
            if disk < _THRESHOLDS["disk_percent"]:
                return _blocked(target, playbook, "threshold_not_met")
            action, risk, reversible, approval = (
                "review_app_owned_cleanup_candidates", "high", False, True
            )
            params = {"disk_percent": disk}
        elif playbook == "high_cpu":
            cpu = _numeric(evidence.get("cpu_percent"), "cpu_percent")
            if cpu < _THRESHOLDS["cpu_percent"]:
                return _blocked(target, playbook, "threshold_not_met")
            action, risk, reversible, approval = (
                "collect_process_diagnostics", "low", True, False
            )
            params = {"cpu_percent": cpu}
        elif playbook == "service_restart":
            service = evidence.get("service_name")
            if not isinstance(service, str) or service not in _ALLOWED_SERVICES:
                return _blocked(target, playbook, "service_not_allowlisted")
            action, risk, reversible, approval = (
                "request_allowlisted_service_restart", "high", True, True
            )
            params = {"service_name": service}
        else:
            domain = evidence.get("domain")
            days = evidence.get("days_until_expiry")
            ownership_ref = evidence.get("domain_ownership_evidence_id")
            if not isinstance(domain, str) or not _DOMAIN_PATTERN.fullmatch(domain):
                return _blocked(target, playbook, "domain_invalid")
            if domain.lower() in {"localhost", "local"} or domain.replace(".", "").isdigit():
                return _blocked(target, playbook, "domain_not_public_fqdn")
            if isinstance(days, bool) or not isinstance(days, (int, float)) or not math.isfinite(days):
                return _blocked(target, playbook, "certificate_expiry_invalid")
            if not 0 <= days <= 3650:
                return _blocked(target, playbook, "certificate_expiry_out_of_range")
            if days > _THRESHOLDS["cert_days"]:
                return _blocked(target, playbook, "threshold_not_met")
            if not isinstance(ownership_ref, str) or not _ID_PATTERN.fullmatch(ownership_ref):
                return _blocked(target, playbook, "verified_domain_ownership_evidence_required")
            action, risk, reversible, approval = (
                "prepare_renewal_for_verified_domain", "high", False, True
            )
            params = {
                "domain": domain.lower(),
                "days_until_expiry": float(days),
                "domain_ownership_evidence_id": ownership_ref,
            }
    except ValueError as exc:
        reason = str(exc)
        if not re.fullmatch(r"[a-z_]+", reason):
            reason = "evidence_invalid"
        return _blocked(target, playbook, reason)

    return RemediationPlan(
        plan_id=_plan_id(target, playbook, "plan_created", params),
        tenant_id=target.tenant_id,
        device_id=target.device_id,
        actor_subject=target.actor_subject,
        source_evidence_id=target.source_evidence_id,
        playbook=playbook,
        recommended_action=action,
        risk=risk,
        reversible=reversible,
        requires_approval=approval,
        status="proposed",
        reason_code="threshold_met",
        parameters=tuple(sorted(params.items())),
    )


def plan_as_dict(plan: RemediationPlan) -> dict[str, Any]:
    """Serialize the immutable plan without implying execution or verified outcome."""
    return {
        "plan_id": plan.plan_id,
        "tenant_id": plan.tenant_id,
        "device_id": plan.device_id,
        "actor_subject": plan.actor_subject,
        "source_evidence_id": plan.source_evidence_id,
        "playbook": plan.playbook,
        "recommended_action": plan.recommended_action,
        "risk": plan.risk,
        "reversible": plan.reversible,
        "requires_approval": plan.requires_approval,
        "status": plan.status,
        "reason_code": plan.reason_code,
        "parameters": dict(plan.parameters),
        "execution_enabled": False,
        "platform_submission_allowed": False,
        "execution_attempted": False,
        "enforcement_verified": False,
        "business_outcome_verified": False,
    }
