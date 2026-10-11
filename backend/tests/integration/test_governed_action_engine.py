"""Contract tests for the Platform-governed action adapter (no live side effects)."""
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from core.config import settings
from core.governed_actions import (
    GovernedActionDefinition,
    GovernedActionError,
    GovernedActionRegistry,
    PlatformGovernedActionExecutor,
    TrustedPlatformContext,
)
from tinlance_agent_platform_sdk.errors import TransportError


AGENT_ID = UUID("d78f76e7-09b5-4a80-aabb-5e45c59ef1bb")
TASK_ID = UUID("e8a80e54-fd5e-44f4-8dd9-2b2d5c0a61d4")
RUN_ID = UUID("a89d6df6-5b0f-4c3f-a8d8-cf9a0a7b60e4")
EXECUTION_ID = UUID("a0f9ecb0-4ef3-4b78-b6f0-f4a13e2cdb65")
EVIDENCE_ID = UUID("1e54fd16-ec29-4b67-b8f8-86ac85e0d64a")
AUDIT_ID = UUID("1f7f1905-5f4a-4f57-a9b6-6b6a0aee40b4")


def _context(tenant_id="trusted-tenant", subject_id="aurontra-service", agent_id=AGENT_ID, task_id=TASK_ID):
    return TrustedPlatformContext(
        tenant_id=tenant_id,
        subject_id=subject_id,
        agent_id=agent_id,
        task_id=task_id,
    )


def _definition(**overrides):
    values = {
        "key": "diagnostic.read",
        "capability_id": "aurontra.diagnostics",
        "capability_version": "1",
        "tool_name": "read_diagnostic",
        "tool_version": "1",
        "action": "read",
        "allowed_arguments": frozenset({"metric", "window"}),
        "required_arguments": frozenset({"metric"}),
        "risk": "low",
        "sandbox_required": True,
        "evidence_required": True,
    }
    values.update(overrides)
    return GovernedActionDefinition(**values)


class FakePlatform:
    def __init__(
        self, calls, *, run_state="created", execution=None, execute_error=None,
        agent_id=AGENT_ID, task_id=TASK_ID,
    ):
        self.calls = calls
        self.run_state = run_state
        self.agent_id = agent_id
        self.task_id = task_id
        self.execution = execution or SimpleNamespace(
            execution_id=EXECUTION_ID,
            state="completed",
            evidence_ids=(EVIDENCE_ID,),
            audit_event_ids=(AUDIT_ID,),
            error_code=None,
            retryable=False,
            output="must-not-be-returned",
        )
        self.execute_error = execute_error
        self.runs = SimpleNamespace(create=self.create_run)
        self.tools = SimpleNamespace(execute=self.execute_tool)

    async def create_run(self, **kwargs):
        self.calls.append(("runs.create", kwargs))
        return SimpleNamespace(
            run_id=RUN_ID,
            task_id=self.task_id,
            agent_id=self.agent_id,
            state=self.run_state,
        )

    async def execute_tool(self, **kwargs):
        self.calls.append(("tools.execute", kwargs))
        if self.execute_error:
            raise self.execute_error
        return self.execution


def _executor(monkeypatch, *, run_state="created", execution=None, execute_error=None, factory_calls=None):
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_AGENT_ID", str(AGENT_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TASK_ID", str(TASK_ID))
    calls = []
    clients = []

    def factory(action_id, operation, context):
        if factory_calls is not None:
            factory_calls.append((action_id, operation))
        client = FakePlatform(
            calls,
            run_state=run_state,
            execution=execution,
            execute_error=execute_error,
            agent_id=context.agent_id,
            task_id=context.task_id,
        )
        clients.append(client)
        return client

    executor = PlatformGovernedActionExecutor(
        GovernedActionRegistry((_definition(),)),
        client_factory=factory,
    )
    return executor, calls, clients


@pytest.mark.asyncio
async def test_submits_allowlisted_action_through_platform_and_returns_evidence_refs(monkeypatch):
    executor, calls, _ = _executor(monkeypatch)
    action_id = uuid4()
    result = await executor.submit(
        action_id=action_id,
        context=_context(),
        action_key="diagnostic.read",
        resource="device:device-123",
        intent="Read device diagnostic metrics",
        arguments={"metric": "cpu", "window": "5m"},
    )

    assert result.action_id == action_id
    assert result.run_id == RUN_ID
    assert result.platform_state == "completed"
    assert result.execution_id == EXECUTION_ID
    assert result.evidence_ids == (EVIDENCE_ID,)
    assert result.audit_event_ids == (AUDIT_ID,)
    assert result.business_outcome_verified is False
    assert not hasattr(result, "output")
    assert [call[0] for call in calls] == ["runs.create", "tools.execute"]
    run_request = calls[0][1]
    execute_request = calls[1][1]
    assert run_request["task_id"] == TASK_ID
    assert run_request["agent_id"] == AGENT_ID
    assert run_request["request_id"] == f"{action_id.hex}:run"
    assert execute_request["request_id"] == f"{action_id.hex}:execute"
    assert execute_request["idempotency_key"] == f"{action_id.hex}:execute"
    invocation = execute_request["invocation"]
    assert invocation.tool_name == "read_diagnostic"
    assert invocation.capability == "aurontra.diagnostics"
    assert invocation.arguments == {"metric": "cpu", "window": "5m"}
    assert execute_request["sandbox_required"] is True
    assert execute_request["evidence_required"] is True


@pytest.mark.asyncio
async def test_non_executable_platform_run_state_is_never_promoted_or_executed(monkeypatch):
    executor, calls, _ = _executor(monkeypatch, run_state="waiting_approval")
    result = await executor.submit(
        action_id=uuid4(),
        context=_context(),
        action_key="diagnostic.read",
        resource="device:device-123",
        intent="Read diagnostic metrics",
        arguments={"metric": "cpu"},
    )
    assert result.platform_state == "waiting_approval"
    assert result.execution_id is None
    assert result.business_outcome_verified is False
    assert [call[0] for call in calls] == ["runs.create"]


@pytest.mark.asyncio
async def test_unregistered_action_fails_before_any_platform_request(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    calls = []
    executor = PlatformGovernedActionExecutor(
        GovernedActionRegistry(),
        client_factory=lambda *_: calls.append("client-created"),
    )
    with pytest.raises(GovernedActionError) as caught:
        await executor.submit(
            action_id=uuid4(),
            context=_context(),
            action_key="arbitrary.command",
            resource="host:api",
            intent="Run a command",
            arguments={"command": "rm -rf /"},
        )
    assert caught.value.code == "action_not_allowlisted"
    assert calls == []


@pytest.mark.asyncio
async def test_argument_allowlist_required_fields_and_json_bounds_fail_closed(monkeypatch):
    executor, calls, _ = _executor(monkeypatch)
    base = {
        "action_id": uuid4(),
        "context": _context(),
        "action_key": "diagnostic.read",
        "resource": "device:device-123",
        "intent": "Read diagnostic metrics",
    }
    with pytest.raises(GovernedActionError, match="action_argument_not_allowlisted"):
        await executor.submit(**base, arguments={"metric": "cpu", "command": "shell"})
    with pytest.raises(GovernedActionError, match="action_required_argument_missing"):
        await executor.submit(**base, arguments={"window": "5m"})
    with pytest.raises(GovernedActionError, match="action_arguments_not_json"):
        await executor.submit(**base, arguments={"metric": float("nan")})
    with pytest.raises(GovernedActionError, match="action_arguments_too_large"):
        await executor.submit(**base, arguments={"metric": "x" * (256 * 1024)})
    assert calls == []


@pytest.mark.asyncio
async def test_platform_transport_failure_is_sanitized_and_retains_run_correlation(monkeypatch):
    executor, calls, _ = _executor(
        monkeypatch,
        execute_error=TransportError("secret-token-must-not-escape"),
    )
    with pytest.raises(GovernedActionError) as caught:
        await executor.submit(
            action_id=uuid4(),
            context=_context(),
            action_key="diagnostic.read",
            resource="device:device-123",
            intent="Read diagnostic metrics",
            arguments={"metric": "cpu"},
        )
    assert caught.value.run_id == RUN_ID
    assert caught.value.retryable is True
    assert "secret-token-must-not-escape" not in str(caught.value)
    assert "secret-token-must-not-escape" not in repr(caught.value)
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_default_client_factory_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", False)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_AGENT_ID", "")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TASK_ID", "")
    executor = PlatformGovernedActionExecutor(GovernedActionRegistry((_definition(),)))
    with pytest.raises(GovernedActionError) as caught:
        await executor.submit(
            action_id=uuid4(),
            context=_context(),
            action_key="diagnostic.read",
            resource="device:device-123",
            intent="Read diagnostic metrics",
            arguments={"metric": "cpu"},
        )
    assert caught.value.code == "platform_integration_disabled"


def test_registry_rejects_duplicate_action_keys():
    definition = _definition()
    with pytest.raises(ValueError, match="duplicate governed action key"):
        GovernedActionRegistry((definition, definition))


def test_definition_rejects_required_arguments_outside_allowlist():
    with pytest.raises(ValueError, match="subset"):
        _definition(required_arguments=frozenset({"not_allowed"}))


@pytest.mark.asyncio
async def test_invalid_resource_and_control_characters_are_rejected_before_network(monkeypatch):
    executor, calls, _ = _executor(monkeypatch)
    base = {
        "action_id": uuid4(),
        "context": _context(),
        "action_key": "diagnostic.read",
        "intent": "Read diagnostic metrics",
        "arguments": {"metric": "cpu"},
    }
    with pytest.raises(GovernedActionError, match="resource_invalid"):
        await executor.submit(**base, resource="device:\nforged")
    with pytest.raises(GovernedActionError, match="intent_invalid"):
        await executor.submit(**{**base, "resource": "device:device-123", "intent": "read\x00metrics"})
    assert calls == []


def test_traceparent_uses_action_id_as_stable_trace_and_fresh_span_ids():
    from core.governed_actions import _traceparent

    action_id = uuid4()
    first = _traceparent(action_id)
    second = _traceparent(action_id)
    assert first.startswith(f"00-{action_id.hex}-")
    assert second.startswith(f"00-{action_id.hex}-")
    assert first != second
    assert len(first.split("-")) == 4
    assert first.split("-")[2] != "0" * 16


def test_platform_sdk_configuration_is_rejected_without_https_in_production(monkeypatch):
    from core.governed_actions import _new_platform_client

    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_BASE_URL", "http://platform.example.invalid")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_BEARER_TOKEN", "injected-test-token")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TENANT_ID", "tenant-test")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_SUBJECT_ID", "subject-test")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_AGENT_ID", str(AGENT_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TASK_ID", str(TASK_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_API_VERSION", "1.1")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TIMEOUT_SECONDS", 10.0)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ALLOW_INSECURE_HTTP", True)
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    with pytest.raises(GovernedActionError, match="platform_https_required"):
        _new_platform_client(uuid4(), "run", _context("tenant-test", "subject-test"))


@pytest.mark.asyncio
async def test_platform_run_identity_mismatch_never_executes_tool(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_AGENT_ID", str(AGENT_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TASK_ID", str(TASK_ID))
    calls = []

    class MismatchedRunClient(FakePlatform):
        async def create_run(self, **kwargs):
            self.calls.append(("runs.create", kwargs))
            return SimpleNamespace(
                run_id=RUN_ID,
                task_id=TASK_ID,
                agent_id=uuid4(),
                state="created",
            )

    def factory(action_id, operation, context):
        return MismatchedRunClient(calls)

    executor = PlatformGovernedActionExecutor(
        GovernedActionRegistry((_definition(),)),
        client_factory=factory,
    )
    with pytest.raises(GovernedActionError, match="platform_run_identity_mismatch") as caught:
        await executor.submit(
            action_id=uuid4(),
            context=_context(),
            action_key="diagnostic.read",
            resource="device:device-123",
            intent="Read diagnostic metrics",
            arguments={"metric": "cpu"},
        )
    assert caught.value.run_id == RUN_ID
    assert [call[0] for call in calls] == ["runs.create"]


def test_client_factory_binds_trusted_context_and_w3c_trace(monkeypatch):
    import re

    from tinlance_agent_platform_sdk.async_client import AsyncAgentPlatform
    from core.governed_actions import _new_platform_client

    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_BASE_URL", "https://platform.example.invalid")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_BEARER_TOKEN", "test-injected-credential")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TENANT_ID", "trusted-tenant")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_SUBJECT_ID", "aurontra-service")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_AGENT_ID", str(AGENT_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TASK_ID", str(TASK_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_API_VERSION", "1.1")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TIMEOUT_SECONDS", 7.0)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ALLOW_INSECURE_HTTP", False)
    monkeypatch.setattr(settings, "ENVIRONMENT", "test")

    action_id = uuid4()
    client = _new_platform_client(action_id, "execute", _context())
    assert isinstance(client, AsyncAgentPlatform)
    assert client._sync._base_url == "https://platform.example.invalid"
    assert client._sync._tenant_id == "trusted-tenant"
    assert client._sync._subject_id == "aurontra-service"
    assert client._sync._api_version == "1.1"
    assert client._sync._timeout == 7.0
    assert re.fullmatch(r"00-[0-9a-f]{32}-[0-9a-f]{16}-01", client._sync._traceparent)
    assert client._sync._traceparent.split("-")[1] == action_id.hex


def test_client_factory_rejects_noncanonical_base_url(monkeypatch):
    from core.governed_actions import _new_platform_client

    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_BASE_URL", "https://platform.example.invalid/prefix")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_BEARER_TOKEN", "test-injected-credential")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TENANT_ID", "trusted-tenant")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_SUBJECT_ID", "aurontra-service")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_AGENT_ID", str(AGENT_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TASK_ID", str(TASK_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_API_VERSION", "1.1")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TIMEOUT_SECONDS", 7.0)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ALLOW_INSECURE_HTTP", False)
    monkeypatch.setattr(settings, "ENVIRONMENT", "test")
    with pytest.raises(GovernedActionError, match="platform_base_url_invalid"):
        _new_platform_client(uuid4(), "run", _context())


def test_action_definition_rejects_mutable_allowlist():
    with pytest.raises(ValueError, match="immutable frozensets"):
        _definition(allowed_arguments={"metric", "window"})


@pytest.mark.asyncio
async def test_action_intent_is_snapshotted_before_first_await(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_AGENT_ID", str(AGENT_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TASK_ID", str(TASK_ID))
    calls = []
    caller_arguments = {"metric": "cpu"}

    class MutatingRunClient(FakePlatform):
        async def create_run(self, **kwargs):
            caller_arguments["metric"] = "disk"
            return await super().create_run(**kwargs)

    def factory(action_id, operation, context):
        if operation == "run":
            return MutatingRunClient(calls)
        return FakePlatform(calls)

    executor = PlatformGovernedActionExecutor(
        GovernedActionRegistry((_definition(),)),
        client_factory=factory,
    )
    await executor.submit(
        action_id=uuid4(),
        context=_context(),
        action_key="diagnostic.read",
        resource="device:device-123",
        intent="Read diagnostic metrics",
        arguments=caller_arguments,
    )
    assert caller_arguments["metric"] == "disk"
    assert calls[-1][1]["invocation"].arguments == {"metric": "cpu"}


@pytest.mark.asyncio
async def test_nil_uuid_action_id_is_rejected_before_network(monkeypatch):
    executor, calls, _ = _executor(monkeypatch)
    with pytest.raises(GovernedActionError, match="action_id_invalid"):
        await executor.submit(
            action_id=UUID(int=0),
            context=_context(),
            action_key="diagnostic.read",
            resource="device:device-123",
            intent="Read diagnostic metrics",
            arguments={"metric": "cpu"},
        )
    assert calls == []


def test_platform_client_rejects_nonfinite_timeout(monkeypatch):
    from core.governed_actions import _new_platform_client

    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_BASE_URL", "https://platform.example.invalid")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_BEARER_TOKEN", "test-injected-credential")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TENANT_ID", "trusted-tenant")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_SUBJECT_ID", "aurontra-service")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_AGENT_ID", str(AGENT_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TASK_ID", str(TASK_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_API_VERSION", "1.1")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TIMEOUT_SECONDS", float("nan"))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ALLOW_INSECURE_HTTP", False)
    monkeypatch.setattr(settings, "ENVIRONMENT", "test")
    with pytest.raises(GovernedActionError, match="platform_timeout_invalid"):
        _new_platform_client(uuid4(), "run", _context())


@pytest.mark.asyncio
async def test_unexpected_programming_error_is_not_advertised_as_retryable(monkeypatch):
    executor, _, _ = _executor(monkeypatch, execute_error=RuntimeError("secret internal detail"))
    with pytest.raises(GovernedActionError) as caught:
        await executor.submit(
            action_id=uuid4(),
            context=_context(),
            action_key="diagnostic.read",
            resource="device:device-123",
            intent="Read diagnostic metrics",
            arguments={"metric": "cpu"},
        )
    assert caught.value.code == "platform_unavailable"
    assert caught.value.retryable is False
    assert "secret internal detail" not in str(caught.value)


@pytest.mark.asyncio
async def test_untrusted_execution_error_text_is_not_returned_as_machine_code(monkeypatch):
    suspicious = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.signature"
    execution = SimpleNamespace(
        execution_id=EXECUTION_ID,
        state="failed",
        evidence_ids=(),
        audit_event_ids=(AUDIT_ID,),
        error_code=suspicious,
        retryable=False,
        output=suspicious,
    )
    executor, _, _ = _executor(monkeypatch, execution=execution)
    result = await executor.submit(
        action_id=uuid4(),
        context=_context(),
        action_key="diagnostic.read",
        resource="device:device-123",
        intent="Read diagnostic metrics",
        arguments={"metric": "cpu"},
    )
    assert result.error_code == "execution_error"
    assert suspicious not in repr(result)


@pytest.mark.asyncio
async def test_untrusted_sdk_error_code_is_replaced_with_generic_code(monkeypatch):
    from tinlance_agent_platform_sdk.errors import PlatformError

    suspicious = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.signature"
    executor, _, _ = _executor(monkeypatch, execute_error=PlatformError(
        "opaque platform failure", error_code=suspicious, retryable=False
    ))
    with pytest.raises(GovernedActionError) as caught:
        await executor.submit(
            action_id=uuid4(),
            context=_context(),
            action_key="diagnostic.read",
            resource="device:device-123",
            intent="Read diagnostic metrics",
            arguments={"metric": "cpu"},
        )
    assert caught.value.code == "platform_sdk_error"
    assert suspicious not in str(caught.value)


@pytest.mark.asyncio
async def test_feature_flag_cannot_be_bypassed_by_custom_client_factory(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", False)
    factory_calls = []
    executor = PlatformGovernedActionExecutor(
        GovernedActionRegistry((_definition(),)),
        client_factory=lambda *_: factory_calls.append("called"),
    )
    with pytest.raises(GovernedActionError, match="platform_integration_disabled"):
        await executor.submit(
            action_id=uuid4(),
            context=_context(),
            action_key="diagnostic.read",
            resource="device:device-123",
            intent="Read diagnostic metrics",
            arguments={"metric": "cpu"},
        )
    assert factory_calls == []


def test_static_platform_credential_cannot_cross_tenant_context(monkeypatch):
    from core.governed_actions import _new_platform_client

    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_BASE_URL", "https://platform.example.invalid")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_BEARER_TOKEN", "tenant-a-credential")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TENANT_ID", "tenant-a")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_SUBJECT_ID", "service-a")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_AGENT_ID", str(AGENT_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TASK_ID", str(TASK_ID))
    monkeypatch.setattr(settings, "AGENT_PLATFORM_API_VERSION", "1.1")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TIMEOUT_SECONDS", 10.0)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ALLOW_INSECURE_HTTP", False)
    monkeypatch.setattr(settings, "ENVIRONMENT", "test")
    with pytest.raises(GovernedActionError, match="platform_identity_context_mismatch"):
        _new_platform_client(uuid4(), "run", _context("tenant-b", "service-b"))


def test_dynamic_credential_provider_binds_each_client_to_trusted_context(monkeypatch):
    from core.governed_actions import _new_platform_client

    monkeypatch.setattr(settings, "AGENT_PLATFORM_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_BASE_URL", "https://platform.example.invalid")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_API_VERSION", "1.1")
    monkeypatch.setattr(settings, "AGENT_PLATFORM_TIMEOUT_SECONDS", 10.0)
    monkeypatch.setattr(settings, "AGENT_PLATFORM_ALLOW_INSECURE_HTTP", False)
    monkeypatch.setattr(settings, "ENVIRONMENT", "test")
    context = _context("tenant-b", "service-b")
    client = _new_platform_client(
        uuid4(),
        "run",
        context,
        credential_provider=lambda verified: f"credential-for-{verified.tenant_id}",
    )
    assert client._sync._tenant_id == "tenant-b"
    assert client._sync._subject_id == "service-b"
    assert client._sync._bearer_token == "credential-for-tenant-b"


@pytest.mark.asyncio
async def test_tenant_context_selects_its_own_platform_agent_and_task(monkeypatch):
    executor, calls, _ = _executor(monkeypatch)
    tenant_agent = uuid4()
    tenant_task = uuid4()
    await executor.submit(
        action_id=uuid4(),
        context=_context("tenant-b", "service-b", agent_id=tenant_agent, task_id=tenant_task),
        action_key="diagnostic.read",
        resource="device:device-456",
        intent="Read tenant B diagnostic metrics",
        arguments={"metric": "cpu"},
    )
    run_request = calls[0][1]
    execute_request = calls[1][1]
    assert run_request["agent_id"] == tenant_agent
    assert run_request["task_id"] == tenant_task
    assert execute_request["agent_id"] == tenant_agent
    assert execute_request["run_id"] == RUN_ID
