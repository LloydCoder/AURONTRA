"""Regression tests for the pinned TSIC identity and event-envelope contracts."""
import pytest
from pydantic import ValidationError

from core.tsic_contracts import TSICIdentityContext, validate_event_envelope


def _context(**overrides):
    value = {
        "tenant_id": "tenant-1",
        "organization_id": "org-1",
        "workspace_id": "workspace-1",
        "actor_id": "service:aurontra",
        "execution_id": "execution-1",
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "correlation_id": "correlation-1",
    }
    value.update(overrides)
    return value


def _event(context, **overrides):
    value = {
        "id": "event-1",
        "source": "aurontra",
        "specversion": "1.0",
        "type": "aurontra.telemetry.accepted",
        "time": "2026-10-11T08:00:00Z",
        "subject": "device:device-1",
        "data": {"status": "accepted"},
        "data_content_type": "application/json",
        "tenant_id": context["tenant_id"],
        "execution_id": context["execution_id"],
        "trace_id": context["trace_id"],
        "correlation_id": context["correlation_id"],
    }
    value.update(overrides)
    return value


def test_identity_context_rejects_zero_or_malformed_trace_id():
    with pytest.raises(ValidationError):
        TSICIdentityContext.model_validate(_context(trace_id="0" * 32))
    with pytest.raises(ValidationError):
        TSICIdentityContext.model_validate(_context(trace_id="ABCDEF"))


def test_event_envelope_is_bound_to_verified_identity_context():
    context = TSICIdentityContext.model_validate(_context())
    event = validate_event_envelope(_event(_context()), context)
    assert event.tenant_id == context.tenant_id
    assert event.execution_id == context.execution_id
    assert event.trace_id == context.trace_id
    assert event.correlation_id == context.correlation_id


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", "other-tenant"),
        ("execution_id", "other-execution"),
        ("trace_id", "0" * 32),
        ("correlation_id", "other-correlation"),
    ],
)
def test_event_envelope_rejects_context_mismatch(field, value):
    context_data = _context()
    context = TSICIdentityContext.model_validate(context_data)
    event = _event(context_data, **{field: value})
    with pytest.raises((ValidationError, ValueError)):
        validate_event_envelope(event, context)


def test_event_envelope_rejects_naive_timestamp():
    context_data = _context()
    context = TSICIdentityContext.model_validate(context_data)
    with pytest.raises(ValidationError):
        validate_event_envelope(_event(context_data, time="2026-10-11T08:00:00"), context)


def test_event_envelope_rejects_unknown_fields():
    context_data = _context()
    context = TSICIdentityContext.model_validate(context_data)
    with pytest.raises(ValidationError):
        validate_event_envelope(_event(context_data, admin_override=True), context)
