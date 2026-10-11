"""Security and safety tests for pure, fail-closed remediation planning."""
from datetime import datetime, timedelta, timezone

import pytest

from resilience.playbooks.planner import (
    TrustedRemediationTarget,
    build_remediation_plan,
    plan_as_dict,
)

NOW = datetime(2026, 10, 11, 0, 0, tzinfo=timezone.utc)


def target(**overrides):
    values = {
        "tenant_id": "tenant-01",
        "device_id": "device-01",
        "actor_subject": "operator-01",
        "source_evidence_id": "evidence-01",
        "observed_at": NOW - timedelta(seconds=30),
    }
    values.update(overrides)
    return TrustedRemediationTarget(**values)


def test_target_requires_normalized_identifiers_and_aware_timestamp():
    with pytest.raises(ValueError):
        target(device_id="../other-tenant")
    with pytest.raises(ValueError):
        target(observed_at=datetime(2026, 10, 11))


def test_disk_pressure_generates_deterministic_recommendation_not_execution():
    first = build_remediation_plan("disk_full", target(), {"disk_percent": 91.2}, now=NOW)
    second = build_remediation_plan("disk_full", target(), {"disk_percent": 91.2}, now=NOW)
    assert first == second
    assert first.status == "proposed"
    assert first.recommended_action == "review_app_owned_cleanup_candidates"
    assert first.requires_approval is True
    assert first.reversible is False
    assert first.execution_enabled is False
    assert first.platform_submission_allowed is False
    assert first.execution_attempted is False
    assert first.enforcement_verified is False
    assert first.business_outcome_verified is False


@pytest.mark.parametrize("value", [-1, 101, float("nan"), float("inf"), True, "99"])
def test_disk_metric_rejects_invalid_values(value):
    result = build_remediation_plan("disk_full", target(), {"disk_percent": value}, now=NOW)
    assert result.status == "blocked"
    assert result.reason_code in {"disk_percent_invalid", "disk_percent_out_of_range"}


def test_below_threshold_does_not_create_action():
    result = build_remediation_plan("high_cpu", target(), {"cpu_percent": 84.99}, now=NOW)
    assert result.status == "blocked"
    assert result.reason_code == "threshold_not_met"
    assert result.recommended_action == "none"


def test_high_cpu_is_read_only_and_does_not_kill_or_reprioritize_processes():
    result = build_remediation_plan("high_cpu", target(), {"cpu_percent": 99}, now=NOW)
    assert result.status == "proposed"
    assert result.recommended_action == "collect_process_diagnostics"
    assert result.risk == "low"
    assert result.reversible is True
    assert dict(result.parameters) == {"cpu_percent": 99.0}


@pytest.mark.parametrize("service", ["nginx", "postgresql", "redis", "application", "api", "worker"])
def test_allowlisted_service_restart_requires_approval(service):
    result = build_remediation_plan("service_restart", target(), {"service_name": service}, now=NOW)
    assert result.status == "proposed"
    assert result.requires_approval is True
    assert result.risk == "high"


@pytest.mark.parametrize("service", ["sshd", "docker", "../../etc", "systemd", "", None])
def test_non_allowlisted_service_is_blocked(service):
    result = build_remediation_plan("service_restart", target(), {"service_name": service}, now=NOW)
    assert result.status == "blocked"
    assert result.reason_code == "service_not_allowlisted"


@pytest.mark.parametrize("domain", ["http://example.com", "localhost", "127.0.0.1", "example.com:443", "bad_domain"])
def test_certificate_plan_rejects_url_localhost_ip_and_invalid_domains(domain):
    result = build_remediation_plan(
        "cert_expiry", target(), {
            "domain": domain,
            "days_until_expiry": 3,
            "domain_ownership_evidence_id": "asset-01",
        }, now=NOW
    )
    assert result.status == "blocked"


def test_certificate_plan_requires_ownership_evidence_and_approval():
    evidence = {
        "domain": "api.example.com",
        "days_until_expiry": 3,
        "domain_ownership_evidence_id": "asset-01",
    }
    result = build_remediation_plan("cert_expiry", target(), evidence, now=NOW)
    assert result.status == "proposed"
    assert result.requires_approval is True
    assert result.reversible is False
    assert dict(result.parameters)["domain"] == "api.example.com"
    assert "enforcement_verified" not in dict(result.parameters)


def test_certificate_plan_blocks_missing_ownership_evidence():
    result = build_remediation_plan(
        "cert_expiry", target(),
        {"domain": "api.example.com", "days_until_expiry": 2}, now=NOW
    )
    assert result.status == "blocked"
    assert result.reason_code == "verified_domain_ownership_evidence_required"


def test_stale_and_future_evidence_are_blocked():
    stale = build_remediation_plan(
        "disk_full", target(observed_at=NOW - timedelta(minutes=6)),
        {"disk_percent": 99}, now=NOW
    )
    future = build_remediation_plan(
        "disk_full", target(observed_at=NOW + timedelta(minutes=3)),
        {"disk_percent": 99}, now=NOW
    )
    assert stale.reason_code == "evidence_stale"
    assert future.reason_code == "evidence_timestamp_in_future"
    assert stale.status == future.status == "blocked"


def test_unknown_playbook_fails_closed():
    with pytest.raises(ValueError, match="not_allowlisted"):
        build_remediation_plan("shell_command", target(), {"command": "whoami"}, now=NOW)


def test_raw_dict_cannot_substitute_for_trusted_target():
    with pytest.raises(TypeError, match="trusted_remediation_target_required"):
        build_remediation_plan("disk_full", {"tenant_id": "tenant-01"}, {"disk_percent": 99}, now=NOW)


def test_serialization_preserves_non_execution_semantics():
    plan = build_remediation_plan("disk_full", target(), {"disk_percent": 88}, now=NOW)
    payload = plan_as_dict(plan)
    assert payload["status"] == "proposed"
    assert payload["execution_enabled"] is False
    assert payload["platform_submission_allowed"] is False
    assert payload["execution_attempted"] is False
    assert payload["business_outcome_verified"] is False


def test_untrusted_extra_fields_never_flow_into_plan():
    plan = build_remediation_plan(
        "disk_full", target(),
        {"disk_percent": 88, "command": "rm -rf /", "secret": "do-not-copy"}, now=NOW
    )
    serialized = plan_as_dict(plan)
    assert "command" not in serialized["parameters"]
    assert "secret" not in serialized["parameters"]
