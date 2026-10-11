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
- Phase 10 provides a pure remediation planner and feature-gated Platform submission service with independent postcondition-verification contracts. Phase 11 adds durable tenant-scoped remediation intents, atomic job/outbox creation, crash-safe unknown-outcome state, and idempotent reconciliation scheduling. Neither phase is wired to a production worker or public route; submission remains disabled until exact Platform tools, a real tenant-scoped verifier, and a scheduler are configured.
- ROI outputs are illustrative models, not measured savings; control mappings are not compliance certification.
- Deployment status is reported separately from test status.

## Development and verification

Backend CI uses Python 3.12 and pytest. The CI workflow is the source of truth for currently enforced checks. Durable job/outbox worker primitives are covered by CI; production scheduler/broker configuration, frontend build/integration, remaining subsystem persistence, inbound billing-webhook idempotency, and deployment verification remain release gates. Ticket and device APIs now use durable tenant-scoped persistence; CI verifies cross-tenant behavior, PostgreSQL RLS for tenant-owned tables (including durable replay and remediation intent records), and a backup/restore smoke test. Other business modules remain gated, and no production database migration or tenant-isolated data-plane release is claimed.

## Endpoint-agent identity (Phase 08)

The endpoint-agent API uses Platform-approved, short-lived DPoP-bound access tokens. Aurontra verifies issuer/JWKS, audience, tenant/device subject, scopes, key thumbprint, fresh per-request proof, request URI/method, access-token hash, and a body-hash extension. Replay identifiers are persisted with forced PostgreSQL RLS. Enrollment, telemetry, and key rotation require separate scopes and active device lifecycle state. Agent authentication remains disabled by default; no production enablement is claimed until the approved identity provider is configured and the full data-plane release gate passes. See [docs/PHASE_08_AGENT_IDENTITY.md](docs/PHASE_08_AGENT_IDENTITY.md).

## Safe remediation playbooks (Phase 10)

Phase 10 adds deterministic, evidence-freshness-bounded plans for disk pressure, allowlisted service restarts, certificate expiry, and read-only high-CPU diagnostics. A gated internal service submits only validated plans through code-owned contracts and requires independent postcondition evidence. It performs no local shell, filesystem, process, service, or certificate side effects. Submission is disabled by default; public routes remain disabled until Platform tool registrations and a concrete tenant-scoped verifier are provisioned. See [Phase 10 design](docs/PHASE_10_SAFE_REMEDIATION.md) and [Phase 10 forensic audit](docs/audits/PHASE_10_FORENSIC_AUDIT.md).

## Durable remediation orchestration (Phase 11)

Phase 11 persists remediation intents with deterministic plan/idempotency keys, state/version transitions, platform/evidence references, and tenant-scoped RLS. Intent, submit job, and outbox event are committed atomically. The worker gets tenant identity from the claimed job row, marks ambiguous external outcomes as `unknown_outcome`, and schedules idempotent reconciliation for stale external states. A plan is only marked verified when Platform execution is completed and independent postcondition evidence exists. The processor and scheduler are not configured in production; no live execution is claimed. See [Phase 11 design](docs/PHASE_11_ORCHESTRATION_RECOVERY.md) and [Phase 11 forensic audit](docs/audits/PHASE_11_FORENSIC_AUDIT.md).

## Telemetry evidence and predictive evaluation (Phases 12–13)

Phase 12 adds tenant-scoped telemetry evidence with DPoP replay protection, event idempotency, payload provenance hashes, timestamp freshness/order checks, partial-metric safeguards, per-device rate limiting, forced PostgreSQL RLS, and a bounded retention primitive. Production ingestion and retention scheduling remain disabled until the approved identity provider, signed endpoint-agent release, evidence consumers, scheduler and customer environment are verified.

Phase 13 adds strict predictor input validation, time-aware trend slopes, trusted-digest checks before model artifact deserialization, and offline evaluation reports for anomaly detection and temporal forecast errors. Anomaly confidence is explicitly uncalibrated; 72-hour forecasts remain linear heuristics. CI passed **411 tests, 1 skipped, 85.19% coverage**, plus PostgreSQL tenant RLS/backup-restore and secret/history/archive scans. Deployment was skipped.

These checks validate code paths and synthetic fixtures, not real-world predictive performance. Production decisioning remains blocked on a representative, authorized, labeled holdout dataset, calibration/drift evaluation, monitoring and human-approved thresholds. See [Phase 12 design](docs/PHASE_12_TELEMETRY_EVIDENCE.md), [Phase 12 audit](docs/audits/PHASE_12_FORENSIC_AUDIT.md), [Phase 13 design](docs/PHASE_13_PREDICTIVE_EVALUATION.md), and [Phase 13 audit](docs/audits/PHASE_13_FORENSIC_AUDIT.md).

## AI service desk and knowledge retrieval (Phase 14)

Phase 14 is **complete at code/CI level**. The resolver is draft-only; unknown, security and high-impact tickets require human review; reporter email is excluded from prompts; common PII/credentials are redacted; provider calls and serialized prompts are bounded; and prompt, response, triage, escalation and knowledge-reference provenance are persisted. Retrieval is deterministic lexical ranking over approved, published global or same-tenant knowledge articles, with content-digest verification and PostgreSQL RLS. CI passed **433 tests, 1 skipped, 85.56% coverage**, plus PostgreSQL tenant RLS/backup-restore and secret/history/archive scans. Deployment was skipped and the production data plane remains closed. See [Phase 14 design](docs/PHASE_14_AI_SERVICE_DESK.md) and [Phase 14 forensic audit](docs/audits/PHASE_14_FORENSIC_AUDIT.md).

## Governed action engine (Phase 09)

The governed-action adapter was merged in PR #4 at `90b8760560b7efb773861e0297c86235638a014a` against the pinned Tinlance Agent Platform SDK. It uses a code-owned action allowlist, trusted tenant/subject/agent/task context, stable idempotency keys, bounded JSON arguments, and Platform-owned policy/approval/execution/evidence. It does not execute local shell commands or treat execution acceptance as proof of a business outcome.

The integration remains **disabled by default** and is not connected to public playbook routes. The environment-token configuration is single-tenant; multi-tenant deployment requires an approved tenant-scoped credential provider and per-tenant Platform registration. PR CI and post-merge main CI passed, including PostgreSQL RLS/restore and secret/history/archive scans. Deployment was skipped; no live Platform connection or production action is claimed. See [Phase 09 implementation](docs/PHASE_09_GOVERNED_ACTION_ENGINE.md) and the [Phase 09 forensic audit](docs/audits/PHASE_09_FORENSIC_AUDIT.md).

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
