# Aurontra

**Aurontra — Autonomous IT Resilience Platform.** Detect operational risk, assist IT service workflows, coordinate governed remediation, and produce auditable operational evidence.

Aurontra is a Tinlance ecosystem product. It integrates with the authoritative Tinlance Agent System through documented, versioned interfaces; it must not duplicate the Agent Platform's identity, authorization, policy, approval, sandbox, secrets, execution, or audit authority.

## Product scope

- IT service-desk assistance with risk-based escalation.
- Device and infrastructure health telemetry and evaluated predictive signals.
- Governed remediation through authenticated endpoint agents.
- Threat analysis and containment with independently verified enforcement outcomes.
- Enterprise integrations, operational reporting, and evidence provenance.

## Current release status

**Not certified production-ready.** The repository is undergoing security-first hardening. Existing test success is not equivalent to production readiness, and a decision score is not proof that a threat was blocked.

Until secure endpoint execution and authorization are implemented and tested:
- Public self-healing execution is disabled.
- The threat-containment endpoint is disabled; analysis must not be represented as containment.
- Billing webhooks are rejected when signature verification cannot be performed.
- Public organization registration and checkout are disabled until secure tenant lifecycle and provider-backed billing are implemented.
- The production business data plane is disabled by default until JWT verification and durable tenant isolation are configured.
- ROI outputs are illustrative models, not measured savings; control mappings are not compliance certification.
- Deployment status is reported separately from test status.

## Development and verification

Backend CI uses Python 3.12 and pytest. The CI workflow is the source of truth for currently enforced checks. Durable job/outbox worker primitives are covered by CI; production scheduler/broker configuration, frontend build/integration, remaining subsystem persistence, inbound billing-webhook idempotency, and deployment verification remain release gates. Ticket and device APIs now use durable tenant-scoped persistence; CI verifies cross-tenant behavior, PostgreSQL RLS for tenant-owned tables (including durable replay records), and a backup/restore smoke test. Other business modules remain gated, and no production database migration or tenant-isolated data-plane release is claimed.

## Endpoint-agent identity (Phase 08)

The endpoint-agent API uses Platform-approved, short-lived DPoP-bound access tokens. Aurontra verifies issuer/JWKS, audience, tenant/device subject, scopes, key thumbprint, fresh per-request proof, request URI/method, access-token hash, and a body-hash extension. Replay identifiers are persisted with forced PostgreSQL RLS. Enrollment, telemetry, and key rotation require separate scopes and active device lifecycle state. Agent authentication remains disabled by default; no production enablement is claimed until the approved identity provider is configured and the full data-plane release gate passes. See [docs/PHASE_08_AGENT_IDENTITY.md](docs/PHASE_08_AGENT_IDENTITY.md).

## Governed action engine (Phase 09)

The governed-action adapter is implemented in PR #4 against the pinned Tinlance Agent Platform SDK. It uses a code-owned action allowlist, trusted tenant/subject/agent/task context, stable idempotency keys, bounded JSON arguments, and Platform-owned policy/approval/execution/evidence. It does not execute local shell commands or treat execution acceptance as proof of a business outcome.

The integration remains **disabled by default** and is not connected to public playbook routes. The environment-token configuration is single-tenant; multi-tenant deployment requires an approved tenant-scoped credential provider and per-tenant Platform registration. CI and PostgreSQL RLS/restore checks passed for the implementation, but deployment was skipped and no live Platform connection or production action is claimed. See [Phase 09 implementation](docs/PHASE_09_GOVERNED_ACTION_ENGINE.md) and the [Phase 09 forensic audit](docs/audits/PHASE_09_FORENSIC_AUDIT.md).

## Architecture and security principles

1. Default-deny for privileged actions.
2. Authenticate and authorize every non-public operation at tenant and resource level.
3. Never execute a requested device action on the API host as a substitute for an endpoint agent.
4. Distinguish observed, detected, decided, requested, enforced, and verified states.
5. Persist operational records and audit evidence durably.
6. Keep secrets out of source control, logs, API responses, and artifacts.
7. Report modeled ROI separately from measured outcomes.
8. Do not claim NIS2/DORA compliance or certification based only on caller-supplied metrics.

## Roadmap

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the canonical Tinlance Agent System boundary, [docs/ROADMAP.md](docs/ROADMAP.md) for the phase plan, and [docs/SECURITY_BASELINE.md](docs/SECURITY_BASELINE.md) for safety constraints and release gates.
