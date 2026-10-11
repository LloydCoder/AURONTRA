# Aurontra Enterprise Hardening Roadmap

Aurontra is a Tinlance ecosystem product and a consumer of the four-repository Tinlance Agent System. It must not duplicate the Agent Platform's authoritative identity, authorization, policy, approval, sandbox, secrets, execution, or evidence controls.

Phases are sequential release gates. A phase is complete only after implementation, tests, documentation reconciliation, security review, and CI evidence. Passing CI does not certify production readiness. Phases 01–11 are complete at the repository/CI level with per-phase reviews. Phase 08 is merged at `830047fa11b75c97f2b7b67847cd28f727b3b4a8`; Phase 09's governed-action adapter was merged in PR #4 at `90b8760560b7efb773861e0297c86235638a014a` and passed CI (325 passed, 1 skipped; 84.08% coverage), PostgreSQL RLS/backup-restore checks, and secret/history/archive scan; post-merge main CI and scan are green. The deployment job is skipped; no live Platform connection or production action is claimed. Phase 08 issuer configuration and Phase 09 tenant-scoped Platform credentials/tool registrations remain external release prerequisites. Phase 10 and Phase 11 are merged only after their implementation, documentation reconciliation, security scan and CI gates are green. Phase 11 is accepted at repository/CI level; the production data plane remains closed because external Platform registration, concrete tenant-scoped verification, worker/scheduler deployment, and other business subsystems are not yet ready.

| Phase | Scope | Acceptance evidence | Status |
|---|---|---|---|
| 01 | Forensic baseline, requirements and supply-chain inventory | Immutable baseline SHA, archive/history scan, risk register | Complete — legacy archive removed; history scan green |
| 02 | Immediate containment and safe defaults | Negative tests for unsafe public actions; fail-closed webhook; audit | Complete — CI green |
| 03 | Authentication and role-based API perimeter | JWT signature/issuer/audience checks, HTTPS identity config, role-policy tests | Complete — business data plane remains closed |
| 04 | Threat model and security design | STRIDE/trust-boundary model, abuse cases, mitigation/evidence mapping | Complete — 18 threats and verification matrix reviewed; CI green |
| 05 | Durable tenant persistence and resource-level authorization | Migrations, tenant-scoped ticket/device repositories, PostgreSQL RLS, cross-tenant tests, transaction/backup tests | Complete — core ticket/device repositories, active-tenant gate, FK enforcement, RLS, rollback and restore smoke tests pass; other subsystems remain gated |
| 06 | Durable jobs and event processing | Retry, idempotency, replay, cancellation, lease recovery, dead-letter, outbox atomicity, PostgreSQL RLS and CI evidence | Complete — 285 passed, 1 skipped; PostgreSQL RLS/restore and history scan green; deployment remains intentionally skipped |
| 07 | Organization/device lifecycle | Tenant-scoped provisioning, inactive-by-default devices, idempotent revocation, offboarding, retention, negative isolation tests | **Complete — PR #2 merged; 292 passed, PostgreSQL RLS/restore green; secret/history scan green** |
| 08 | Authenticated endpoint agent | Platform-bound DPoP tokens, per-request proof, body binding, replay table/RLS, enrollment, scoped key rotation, telemetry, versioning tests | **Complete — PR #3 merged; 300 passed, 1 skipped; 83.06% coverage; PostgreSQL RLS/restore and secret/history scan green; production identity-provider configuration remains a release prerequisite** |
| 09 | Governed action engine | Official Platform SDK/TSIC contracts, pinned reviewed dependency, policy/approval/evidence contract tests, no local execution authority | **Complete — PR #4 merged at `90b8760560b7efb773861e0297c86235638a014a`; 325 passed, 1 skipped; 84.08% coverage; PostgreSQL RLS/restore and secret/history/archive scan green; post-merge main CI green; deployment skipped** |
| 10 | Safe remediation playbooks | Allowlist, least privilege, bounded Platform submission, postcondition verification contract and adversarial tests | **Complete at code/CI level — PR #6; 371 passed, 1 skipped, 84.79% coverage; PostgreSQL RLS/restore and secret/history/archive scans green. Public execution remains disabled pending exact Platform tool registration and a concrete tenant-scoped verifier.** |
| 11 | Orchestration recovery | Durable action intents, crash/retry/duplicate/partial-failure recovery, leases, reconciliation and outbox integration | **Complete at code/CI level — PR #7; 382 passed, 1 skipped, 84.93% coverage; PostgreSQL RLS/backup-restore and secret/history/archive scans green. No production worker or live action is claimed.** |
| 12 | Telemetry pipeline | Provenance, freshness, schema, missing-data and retention tests | **Complete at code/CI level — 392 passed, 1 skipped; 85.04% coverage; SQLite migration, PostgreSQL RLS/backup-restore, and secret/history/archive scans green. Production ingestion and retention scheduler remain disabled/release-gated.** |
| 13 | Predictive resilience evaluation | Reproducible labeled benchmark and model-quality report | **Next — Phase 12 implementation and forensic audit complete; no predictive-performance claim until separated labeled evaluation data is available** |
| 14 | AI service desk and retrieval | Prompt-injection, privacy, escalation, timeout and output validation tests | Not started |
| 15 | Threat detection evidence pipeline | Reproducible dataset, calibrated metrics and finding provenance | Not started |
| 16 | Verified threat containment | Enforcement acknowledgements, state verification and failure tests | Not started |
| 17 | Tinlance ecosystem integrations | Versioned contracts, auth, timeout/retry/circuit-breaker tests | Not started |
| 18 | Real customer console | Reproducible frontend build and authenticated end-to-end tests | Not started |
| 19 | Billing and entitlements | Provider checkout, idempotent webhooks and reconciliation tests | Not started |
| 20 | Enterprise administration | Roles, policies, credentials, integrations and audit tests | Not started |
| 21 | Audit, compliance evidence and ROI integrity | Durable provenance, tamper tests and evidence-backed reporting | Not started |
| 22 | SRE, observability and disaster recovery | SLOs, alerting, restore drills, RTO/RPO evidence | Not started |
| 23 | Security assurance and release integrity | SAST, dependency/secret scans, integration/load/fault tests, provenance | Not started |
| 24 | Production release certification gate | Full forensic audit, clean deployment, rollback/recovery and go/no-go | Not started |

## Phase 10 implementation evidence

- Pure planner supports disk pressure, allowlisted service restart, certificate expiry, and read-only high-CPU diagnostics. It enforces evidence freshness, numeric ranges, allowlists, deterministic IDs, and explicit non-execution state.
- Internal submission service maps only four code-owned action contracts to the official Platform SDK adapter. Submission is disabled by default, requires verified target/context agreement, a valid unmodified plan, and an independent postcondition verifier. Platform approval-pending and incomplete states are never promoted to success.
- No public automation route is connected to the service. Exact Platform tool registrations are not confirmed, and no concrete tenant-scoped postcondition verifier is configured. The production data plane remains closed.
- Phase 10 CI: [run 38101939727](https://github.com/LloydCoder/AURONTRA/actions/runs/38101939727) — 371 passed, 1 skipped, 84.79% coverage; PostgreSQL RLS/backup-restore passed. [Secret/history/archive scan](https://github.com/LloydCoder/AURONTRA/actions/runs/38101939719) passed. Deployment was skipped; no production runtime was exercised.

## Phase 12 implementation evidence

- Phase 12 was audited at code commit `6b2e3a1f72afbf4bc1899b6b0bda96b1e7702ef4`; the design and forensic audit are reconciled in the Phase 12 PR.
- CI: [run 38104429834](https://github.com/LloydCoder/AURONTRA/actions/runs/38104429834) — **392 passed, 1 skipped, 85.04% coverage**; clean SQLite migration, compile, PostgreSQL tenant RLS and backup/restore passed.
- Secret/history/archive scan: [run 38104429792](https://github.com/LloydCoder/AURONTRA/actions/runs/38104429792) passed. Deployment was skipped; no production telemetry source, scheduler or identity provider was exercised.
- The implementation provides strict schema and freshness validation, per-device rate limiting, event idempotency, DPoP proof replay protection, payload provenance, ordering and partial-metric safeguards, forced PostgreSQL RLS, and a bounded tenant-specific retention primitive.
- Full design and release gates: [Phase 12 design](PHASE_12_TELEMETRY_EVIDENCE.md) and [Phase 12 forensic audit](audits/PHASE_12_FORENSIC_AUDIT.md).
- Production remains closed pending real identity-provider configuration, signed agent release, scheduled retention, evidence consumers, observability and customer-environment validation.

## Phase 11 implementation evidence

- `remediation_intents` is a durable tenant-scoped table with a forward Alembic migration, composite organization/device foreign key, unique plan/idempotency constraints, state/version fields, platform/evidence references, and forced PostgreSQL RLS.
- Intent creation, optional durable submit job, and initial transactional outbox event share the caller-owned transaction. Duplicate creation is idempotent; semantically modified plans fail closed.
- A tenant-aware worker mode passes the authoritative organization ID from the claimed durable job row, not from JSON payload. The remediation handler validates this binding, active organization, enrolled device, state transition, and idempotency key.
- Processor failures after possible external acceptance become `unknown_outcome`; retries reuse the same deterministic plan key. Reconciliation jobs are scheduled idempotently for stale approval/platform/verification states. Verified state requires completed Platform state, execution ID, independent postcondition evidence, and explicit verified outcome.
- Phase 11 CI: [run 38102735277](https://github.com/LloydCoder/AURONTRA/actions/runs/38102735277) — 382 passed, 1 skipped, 84.93% coverage; PostgreSQL RLS and backup/restore passed. [Secret/history/archive scan](https://github.com/LloydCoder/AURONTRA/actions/runs/38102735270) passed. Deployment was skipped.
- Residual blockers: the processor is injected, not registered in a production worker; no live Platform connection, concrete evidence verifier, or scheduler is configured. Public remediation remains disabled.

## Current implementation evidence

- Public playbook execution is disabled; local playbooks are recommendation-only.
- Phase 09 adds a pinned official Agent Platform SDK adapter with immutable action allowlists, trusted tenant/agent/task context, stable idempotency, Platform evidence references and fail-closed defaults. It is not wired to public routes and has no live production credential; multi-tenant credential-provider and endpoint/tool registration remain release prerequisites.
- Threat containment is disabled until a real enforcement adapter and independent verification exist.
- Billing webhook signatures fail closed; checkout and onboarding remain disabled.
- JWT/JWKS verification and conservative role policy are implemented and tested. Ticket and device APIs now use durable tenant-scoped queries, require an active organization, and have cross-tenant negative tests. This is not a complete object-level authorization claim for every business route.
- Organization, API-key metadata, audit-event, webhook inbox metadata, durable job and transactional outbox models plus Alembic migrations exist. Ticket/device routes use durable SQLAlchemy persistence, explicit tenant predicates, and active-organization checks; remaining legacy in-memory modules are not enabled in production.
- Production startup no longer mutates schema with `create_all`; it requires the configured migration revision when the data plane is requested.
- Phase 07 introduces Alembic revision `0004_device_lifecycle` and adds device lifecycle timestamps/version metadata. Administrative provisioning creates an inactive record; `enrolled_at` remains NULL until the authenticated endpoint-agent protocol in Phase 08 proves enrollment. Device revocation is tenant-scoped and idempotent. Organization offboarding is a retained-evidence state transition that disables all devices; ordinary data access remains denied for offboarded tenants.
- The production data plane remains closed by a code-level release gate until every business subsystem is durable, tenant-scoped, and independently tested.
- Ticket creation writes a tenant-scoped `ticket.created` outbox event in the same database transaction; the outbox payload contains identifiers only, not ticket content or reporter PII.
- Durable worker loops use explicit handler/publisher allowlists, bounded timeouts, lease ownership, retries, cooperative cancellation, idempotency keys and dead-letter behavior. Delivery is at-least-once, not exactly-once.
- No production worker scheduler, message broker, external publisher, or production deployment has been configured. Queue primitives and CI tests are not evidence of a running production worker.
- The old deployment archive is removed from the working tree. The security workflow rejects future tracked tarballs and scans historical blobs as data only.

## Serial execution protocol

1. Record the exact commit SHA and workflow state before each phase.
2. Complete one phase, inspect every changed file, run tests and security scans, then audit its acceptance criteria before starting the next phase.
3. Reconcile code, tests, configuration, docs, release notes, and threat register after every phase.
4. Inspect workflow job logs, not just the summary badge.
5. Record unresolved external dependencies explicitly; do not claim a green production release if credentials or environment access are missing.
6. After Phase 24, audit the complete repository, history, archives, integrations and release evidence.

## Non-negotiable status distinctions

- Unit tests passing is not full CI.
- Full CI passing is not successful deployment.
- Deployment success is not verified runtime correctness.
- A threat decision is not verified containment.
- Control mapping is not compliance certification.
- Estimated ROI is not measured savings.
