# Phase 09 — Governed Action Engine

**Status:** Implementation in progress on `phase-09-governed-action-engine`.  
**Authority:** Tinlance Agent Platform.  
**Integration contract:** Tinlance Agent Platform SDK 1.0.0 / Platform API 1.1 / `governed-execution.v1`.  
**Reviewed SDK source:** `LloydCoder/tinlance-agent-platform-sdk@615eef529831fdfbe37e050e45d9a1a8c4472291`.  
**Canonical ecosystem integration authority:** TSIC adapter baseline `bdb5b7f9f2295562ad8681c591a8a927500b4d8c`.

## Goal

Replace any product-side assumption that a playbook can authorize or execute an action with a typed, auditable request to the official Tinlance Agent Platform SDK. Aurontra provides domain intent and a code-owned action contract; the Platform alone authenticates the service principal, binds tenant and agent identity, evaluates capability/policy/budget/approval/sandbox/secret requirements, executes registered tools, and owns authoritative evidence.

## Contract requirements

- Use only the official SDK public surface; do not copy or reimplement its HTTP protocol.
- The pinned SDK's `ClientConfig.as_client_kwargs()` currently supplies `tracestate` and `trace_context` keywords that the pinned `AgentPlatform.__init__` signature does not accept. Aurontra uses the SDK's validated direct constructor with the supported `traceparent` parameter and has a regression test for it; this compatibility finding is documented rather than silently bypassed.
- Pin the SDK to the reviewed full commit SHA, not a branch or floating version.
- Platform API version is exactly `1.1`; contract is `governed-execution.v1`.
- Use the SDK's `POST /v1/agent-platform` transport with bearer credential, `X-Tinlance-API-Version`, request ID, idempotency key for consequential operations, and W3C trace context.
- Tenant and subject metadata are deployment-configured and immutable from caller input. Platform authentication remains authoritative.
- Consequential operations use stable action-derived request/idempotency identifiers so retries preserve intent. Reusing an idempotency key with changed input must remain a Platform conflict.
- Tool/capability names and versions come from a code-owned allowlist; callers cannot select arbitrary tool names or actions.
- Requests are bounded JSON, bounded in size, and reject unknown argument names, missing required arguments, non-finite numbers and control characters in resource/intent identifiers.
- A run is sent to `tools.execute` only when its authoritative state is `created` or `running`. Approval-gated or terminal states are returned without local promotion or side effect.
- Platform execution state and evidence references are preserved, but Aurontra never treats them alone as proof that an IT/business postcondition succeeded.
- SDK errors are converted to sanitized error codes. Credentials, raw SDK payloads, and tool output are not logged or returned by this adapter.
- The integration is disabled by default and no public playbook route is wired to it in this phase. Phase 10 owns safe playbook mapping and independent postcondition verification.

## Implementation scope

- `backend/core/governed_actions.py`: immutable-by-interface action allowlist, strict argument validation, SDK client configuration, trace context, stable run/execution request IDs, governed submission, and result metadata.
- `backend/tests/integration/test_governed_action_engine.py`: mocked contract tests for SDK request shapes, idempotency, evidence references, non-executable run states, argument validation, disabled-by-default behavior, error sanitization, trace context and production TLS requirements.
- `backend/core/config.py` and `.env.example`: explicit, disabled-by-default Platform configuration.
- `backend/requirements.txt`: immutable SDK source revision.

## Required production configuration

Configure the following only through deployment secrets/configuration after the Platform operator provisions the service principal, task, agent and allowed capability/tool registrations:

- `AGENT_PLATFORM_ENABLED=true`
- `AGENT_PLATFORM_BASE_URL=https://...`
- `AGENT_PLATFORM_BEARER_TOKEN` from the approved secret manager
- `AGENT_PLATFORM_TENANT_ID` and `AGENT_PLATFORM_SUBJECT_ID` as trusted server configuration
- `AGENT_PLATFORM_AGENT_ID` and `AGENT_PLATFORM_TASK_ID` as Platform-provisioned UUIDs
- `AGENT_PLATFORM_API_VERSION=1.1`

Production must not enable insecure HTTP. These settings do not open Aurontra's product-wide business data plane; `DATA_PLANE_ENABLED` remains separately gated.

## Exit criteria

1. Pinned SDK installs reproducibly and `pip check`, compilation, backend tests and security scans pass.
2. Tests prove unknown actions and untrusted argument shapes are rejected before a Platform request.
3. Tests prove the SDK receives stable idempotency identifiers and the correct tenant/subject/agent/task metadata.
4. Tests prove waiting-approval/terminal run states never trigger `tools.execute`.
5. Tests prove Platform evidence/audit references are preserved and `business_outcome_verified` remains false.
6. A forensic audit confirms there is no local `subprocess`, `systemctl`, Certbot, shell, or filesystem side-effect fallback.
7. Documentation clearly separates repository CI evidence from live Platform connectivity and production deployment.
8. PR CI, PostgreSQL RLS/restore checks, and secret/history/archive scan are green before merge.

## Explicit exclusions

This phase does not enable any existing playbook, decide approvals locally, implement endpoint remediation, add a live production credential, claim a deployed Platform connection, or open the business data plane. Those remain separate phase/runtime gates.
