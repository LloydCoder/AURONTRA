"""Versioned TSIC identity and event-envelope contracts.

This is a pinned Aurontra consumer snapshot of TSIC contract versions:
identity-context 1.0.0, event-envelope 1.0.0, trace-context 1.1.0.
TSIC remains the source of truth; update this module with the TSIC registry.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class TSICIdentityContext(BaseModel):
    """Verified, immutable tenant/actor context for downstream integration calls."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    tenant_id: StrictStr = Field(min_length=1, max_length=128)
    organization_id: StrictStr = Field(min_length=1, max_length=128)
    workspace_id: StrictStr = Field(min_length=1, max_length=128)
    actor_id: StrictStr = Field(min_length=1, max_length=128)
    execution_id: StrictStr = Field(min_length=1, max_length=128)
    trace_id: StrictStr = Field(min_length=32, max_length=32)
    correlation_id: StrictStr = Field(min_length=1, max_length=128)
    agent_id: StrictStr | None = Field(default=None, max_length=128)
    service_id: StrictStr | None = Field(default=None, max_length=128)
    causation_id: StrictStr | None = Field(default=None, max_length=128)

    @field_validator("tenant_id", "organization_id", "workspace_id", "actor_id", "execution_id", "correlation_id")
    @classmethod
    def identifiers_must_be_safe(cls, value: str) -> str:
        if not _SAFE_ID_RE.fullmatch(value):
            raise ValueError("identity context identifier is invalid")
        return value

    @field_validator("trace_id")
    @classmethod
    def trace_id_must_be_valid(cls, value: str) -> str:
        if not _TRACE_ID_RE.fullmatch(value) or value == "0" * 32:
            raise ValueError("trace_id must be 32 lowercase hex characters and non-zero")
        return value


class TSICEventEnvelope(BaseModel):
    """CloudEvents 1.0 envelope with required TSIC tenant and correlation fields."""

    model_config = ConfigDict(extra="forbid")

    id: StrictStr = Field(min_length=1, max_length=128)
    source: StrictStr = Field(min_length=1, max_length=512)
    specversion: Literal["1.0"]
    type: StrictStr = Field(min_length=1, max_length=256)
    time: datetime
    subject: StrictStr = Field(min_length=1, max_length=512)
    data: dict[str, Any]
    data_content_type: Literal["application/json"]
    tenant_id: StrictStr = Field(min_length=1, max_length=128)
    execution_id: StrictStr = Field(min_length=1, max_length=128)
    trace_id: StrictStr = Field(min_length=32, max_length=32)
    correlation_id: StrictStr = Field(min_length=1, max_length=128)

    @field_validator("time")
    @classmethod
    def timestamp_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event time must include a timezone")
        return value

    @field_validator("trace_id")
    @classmethod
    def event_trace_id_must_be_valid(cls, value: str) -> str:
        if not _TRACE_ID_RE.fullmatch(value) or value == "0" * 32:
            raise ValueError("event trace_id must be 32 lowercase hex characters and non-zero")
        return value

    @field_validator("correlation_id", "execution_id", "tenant_id")
    @classmethod
    def event_identifiers_must_be_safe(cls, value: str) -> str:
        if not _SAFE_ID_RE.fullmatch(value):
            raise ValueError("event context identifier is invalid")
        return value


def validate_event_envelope(
    payload: dict[str, Any],
    identity_context: TSICIdentityContext,
) -> TSICEventEnvelope:
    """Validate an event and bind it to the verified identity/correlation context."""
    event = TSICEventEnvelope.model_validate(payload)
    expected = {
        "tenant_id": identity_context.tenant_id,
        "execution_id": identity_context.execution_id,
        "trace_id": identity_context.trace_id,
        "correlation_id": identity_context.correlation_id,
    }
    for field, value in expected.items():
        if getattr(event, field) != value:
            raise ValueError("event identity context mismatch")
    return event
