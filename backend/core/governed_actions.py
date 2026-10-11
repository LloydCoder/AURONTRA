"""Aurontra's authority-neutral adapter to the Tinlance Agent Platform SDK.

This module submits only pre-registered action definitions to the Platform.
It never performs local infrastructure side effects and never treats a Platform
execution state as proof that the business postcondition was achieved.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any, Callable
from uuid import UUID, uuid4

from tinlance_agent_platform_sdk.async_client import AsyncAgentPlatform
from tinlance_agent_platform_sdk.config import ClientConfig
from tinlance_agent_platform_sdk.errors import SdkError
from tinlance_agent_platform_sdk.tools import ToolInvocation

from core.config import settings

logger = logging.getLogger(__name__)
_MAX_ARGUMENT_BYTES = 256 * 1024
_MAX_ARGUMENTS = 128
_MAX_TEXT_LENGTH = 2048
_ALLOWED_RUN_STATES_FOR_EXECUTION = frozenset({"created", "running"})


class GovernedActionError(RuntimeError):
    """Sanitized error from the governed-action boundary."""

    def __init__(
        self,
        code: str,
        *,
        retryable: bool = False,
        run_id: UUID | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.run_id = run_id


@dataclass(frozen=True, slots=True)
class GovernedActionDefinition:
    """Code-owned action contract; not a Platform authorization grant."""

    key: str
    capability_id: str
    capability_version: str
    tool_name: str
    tool_version: str
    action: str
    allowed_arguments: frozenset[str]
    required_arguments: frozenset[str] = frozenset()
    risk: str = "medium"
    reversibility: str = "reversible"
    data_class: str = "internal"
    blast_radius: str = "single"
    sandbox_required: bool = True
    evidence_required: bool = True
    requested_timeout_seconds: float = 30.0
    requested_tool_calls: int = 1

    def __post_init__(self) -> None:
        for field_name in (
            "key", "capability_id", "capability_version", "tool_name",
            "tool_version", "action", "risk", "reversibility", "data_class",
            "blast_radius",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be non-empty")
        if not self.required_arguments.issubset(self.allowed_arguments):
            raise ValueError("required arguments must be a subset of allowed arguments")
        if len(self.allowed_arguments) > _MAX_ARGUMENTS:
            raise ValueError("action argument allowlist is too large")
        if not 0 < self.requested_timeout_seconds <= 120:
            raise ValueError("requested timeout must be between 0 and 120 seconds")
        if not 1 <= self.requested_tool_calls <= 10:
            raise ValueError("requested tool-call budget must be between 1 and 10")


class GovernedActionRegistry:
    """Immutable-by-interface allowlist; user input cannot define Platform tools."""

    def __init__(self, definitions: tuple[GovernedActionDefinition, ...] = ()) -> None:
        items: dict[str, GovernedActionDefinition] = {}
        for definition in definitions:
            if definition.key in items:
                raise ValueError(f"duplicate governed action key: {definition.key}")
            items[definition.key] = definition
        self._items = items

    def get(self, key: str) -> GovernedActionDefinition:
        try:
            return self._items[key]
        except KeyError as exc:
            raise GovernedActionError("action_not_allowlisted") from exc

    def keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._items))


@dataclass(frozen=True, slots=True)
class GovernedActionResult:
    """Platform execution metadata; business_outcome_verified is deliberately false."""

    action_id: UUID
    run_id: UUID
    platform_state: str
    execution_id: UUID | None
    evidence_ids: tuple[UUID, ...]
    audit_event_ids: tuple[UUID, ...]
    error_code: str | None
    retryable: bool
    business_outcome_verified: bool = False


def _traceparent(action_id: UUID) -> str:
    """Create a valid W3C traceparent with stable trace ID and fresh span ID."""
    return f"00-{action_id.hex}-{uuid4().hex[:16]}-01"


def _configured_ids() -> tuple[UUID, UUID]:
    try:
        agent_id = UUID(settings.AGENT_PLATFORM_AGENT_ID)
        task_id = UUID(settings.AGENT_PLATFORM_TASK_ID)
    except (ValueError, TypeError, AttributeError) as exc:
        raise GovernedActionError("platform_agent_or_task_id_invalid") from exc
    return agent_id, task_id


def _new_platform_client(action_id: UUID, operation: str) -> AsyncAgentPlatform:
    """Build one client per operation so spans differ while trace ID stays stable."""
    if not settings.AGENT_PLATFORM_ENABLED:
        raise GovernedActionError("platform_integration_disabled")
    required = (
        settings.AGENT_PLATFORM_BASE_URL,
        settings.AGENT_PLATFORM_BEARER_TOKEN,
        settings.AGENT_PLATFORM_TENANT_ID,
        settings.AGENT_PLATFORM_SUBJECT_ID,
    )
    if any(not isinstance(value, str) or not value.strip() for value in required):
        raise GovernedActionError("platform_integration_not_configured")
    if settings.AGENT_PLATFORM_API_VERSION != "1.1":
        raise GovernedActionError("platform_api_version_unsupported")
    if settings.AGENT_PLATFORM_TIMEOUT_SECONDS <= 0:
        raise GovernedActionError("platform_timeout_invalid")
    if settings.ENVIRONMENT.lower() == "production":
        if not settings.AGENT_PLATFORM_BASE_URL.startswith("https://"):
            raise GovernedActionError("platform_https_required")
        if settings.AGENT_PLATFORM_ALLOW_INSECURE_HTTP:
            raise GovernedActionError("platform_insecure_transport_forbidden")
    try:
        config = ClientConfig(
            base_url=settings.AGENT_PLATFORM_BASE_URL,
            bearer_token=settings.AGENT_PLATFORM_BEARER_TOKEN,
            tenant_id=settings.AGENT_PLATFORM_TENANT_ID,
            subject_id=settings.AGENT_PLATFORM_SUBJECT_ID,
            timeout=settings.AGENT_PLATFORM_TIMEOUT_SECONDS,
            api_version=settings.AGENT_PLATFORM_API_VERSION,
            traceparent=_traceparent(action_id),
            allow_insecure_http=(
                settings.AGENT_PLATFORM_ALLOW_INSECURE_HTTP
                and settings.ENVIRONMENT.lower() != "production"
            ),
        )
        return AsyncAgentPlatform(config=config)
    except (TypeError, ValueError) as exc:
        raise GovernedActionError("platform_client_configuration_invalid") from exc


ClientFactory = Callable[[UUID, str], AsyncAgentPlatform]


class PlatformGovernedActionExecutor:
    """Submit a pre-allowlisted action through the official governed-execution SDK."""

    def __init__(
        self,
        registry: GovernedActionRegistry,
        *,
        client_factory: ClientFactory | None = None,
    ) -> None:
        self._registry = registry
        self._client_factory = client_factory or _new_platform_client

    async def submit(
        self,
        *,
        action_id: UUID,
        action_key: str,
        resource: str,
        intent: str,
        arguments: dict[str, Any],
    ) -> GovernedActionResult:
        definition = self._registry.get(action_key)
        if not isinstance(action_id, UUID):
            raise GovernedActionError("action_id_must_be_uuid")
        if not isinstance(resource, str) or not resource.strip() or len(resource) > _MAX_TEXT_LENGTH:
            raise GovernedActionError("resource_invalid")
        if not isinstance(intent, str) or not intent.strip() or len(intent) > _MAX_TEXT_LENGTH:
            raise GovernedActionError("intent_invalid")
        if not isinstance(arguments, dict) or len(arguments) > _MAX_ARGUMENTS:
            raise GovernedActionError("action_arguments_invalid")
        if any(not isinstance(key, str) or key not in definition.allowed_arguments for key in arguments):
            raise GovernedActionError("action_argument_not_allowlisted")
        if not definition.required_arguments.issubset(arguments):
            raise GovernedActionError("action_required_argument_missing")
        try:
            encoded_arguments = json.dumps(
                arguments, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise GovernedActionError("action_arguments_not_json") from exc
        if len(encoded_arguments) > _MAX_ARGUMENT_BYTES:
            raise GovernedActionError("action_arguments_too_large")

        agent_id, task_id = _configured_ids()
        run_id: UUID | None = None
        try:
            run_client = self._client_factory(action_id, "run")
            run = await run_client.runs.create(
                task_id=task_id,
                agent_id=agent_id,
                intent=intent,
                request_id=f"{action_id.hex}:run",
            )
            run_id = run.run_id
            if run.agent_id != agent_id or run.task_id != task_id:
                raise GovernedActionError("platform_run_identity_mismatch", run_id=run_id)
            # A run in any state other than an executable state is never promoted
            # locally. In particular, approval-gated/terminal states are returned.
            if run.state not in _ALLOWED_RUN_STATES_FOR_EXECUTION:
                return GovernedActionResult(
                    action_id=action_id,
                    run_id=run.run_id,
                    platform_state=run.state,
                    execution_id=None,
                    evidence_ids=(),
                    audit_event_ids=(),
                    error_code=None,
                    retryable=False,
                )

            execute_client = self._client_factory(action_id, "execute")
            execution = await execute_client.tools.execute(
                run_id=run.run_id,
                agent_id=agent_id,
                invocation=ToolInvocation(
                    tool_name=definition.tool_name,
                    capability=definition.capability_id,
                    action=definition.action,
                    resource=resource,
                    arguments=arguments,
                ),
                capability_version=definition.capability_version,
                tool_version=definition.tool_version,
                requested_timeout_seconds=definition.requested_timeout_seconds,
                requested_tool_calls=definition.requested_tool_calls,
                risk=definition.risk,
                reversibility=definition.reversibility,
                data_class=definition.data_class,
                blast_radius=definition.blast_radius,
                sandbox_required=definition.sandbox_required,
                evidence_required=definition.evidence_required,
                request_id=f"{action_id.hex}:execute",
                idempotency_key=f"{action_id.hex}:execute",
            )
            return GovernedActionResult(
                action_id=action_id,
                run_id=run.run_id,
                platform_state=execution.state,
                execution_id=execution.execution_id,
                evidence_ids=execution.evidence_ids,
                audit_event_ids=execution.audit_event_ids,
                error_code=execution.error_code,
                retryable=execution.retryable,
                business_outcome_verified=False,
            )
        except GovernedActionError:
            raise
        except SdkError as exc:
            code = getattr(exc, "error_code", None) or type(exc).__name__.lower()
            retryable = bool(getattr(exc, "retryable", False))
            logger.warning(
                "Governed Platform request failed operation=%s code=%s retryable=%s",
                "execute" if run_id else "run",
                code,
                retryable,
            )
            raise GovernedActionError(
                f"platform_{code}",
                retryable=retryable,
                run_id=run_id,
            ) from None
        except (TypeError, ValueError) as exc:
            logger.warning("Invalid Platform SDK response operation=%s", "execute" if run_id else "run")
            raise GovernedActionError(
                "platform_response_invalid",
                retryable=False,
                run_id=run_id,
            ) from None
        except Exception as exc:
            logger.warning(
                "Governed Platform request failed operation=%s error_type=%s",
                "execute" if run_id else "run",
                type(exc).__name__,
            )
            raise GovernedActionError(
                "platform_unavailable",
                retryable=True,
                run_id=run_id,
            ) from None
