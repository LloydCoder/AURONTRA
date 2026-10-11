# Aurontra Enterprise Hardening Roadmap

Aurontra is a Tinlance ecosystem product and a consumer of the four-repository Tinlance Agent System. It must not duplicate the Agent Platform's authoritative identity, authorization, policy, approval, sandbox, secrets, execution, or evidence controls.

Phases are sequential release gates. A phase is complete only after implementation, tests, documentation reconciliation, security review, and CI evidence. Passing CI does not certify production readiness. Phase 04's threat model is reviewed. Phase 05's foundational ticket/device tenant persistence and RLS acceptance checks are complete. Phase 06 durable jobs/outbox implementation and Phase 07 organization/device lifecycle implementation and forensic audit are complete; merged candidate CI and secret/history scan are green. Phase 08 is next. The production data plane remains closed because several other business subsystems are not yet migrated.

| Phase | Scope | Acceptance evidence | Status |
|---|---|---|---|
| 01 | Forensic baseline, requirements and supply-chain inventory | Immutable baseline SHA, archive/history scan, risk register | Complete — legacy archive removed; history scan green |
| 02 | Immediate containment and safe defaults | Negative tests for unsafe public actions; fail-closed webhook; audit | Complete — CI green |
| 03 | Authentication and role-based API perimeter | JWT signature/issuer/audience checks, HTTPS identity config, role-policy tests | Complete — business data plane remains closed |
| 04 | Threat model and security design | STRIDE/trust-boundary model, abuse cases, mitigation/evidence mapping | Complete — 18 threats and verification matrix reviewed; CI green |
| 05 | Durable tenant persistence and resource-level authorization | Migrations, tenant-scoped ticket/device repositories, PostgreSQL RLS, cross-tenant tests, transaction/backup tests | Complete — core ticket/device repositories, active-tenant gate, FK enforcement, RLS, rollback and restore smoke tests pass; other subsystems remain gated |
| 06 | Durable jobs and event processing | Retry, idempotency, replay, cancellation, lease recovery, dead-letter, outbox atomicity, PostgreSQL RLS and CI evidence | Complete — 285 passed, 1 skipped; PostgreSQL RLS/restore and history scan green; deployment remains intentionally skipped |
| 07 | Organization/device lifecycle | Tenant-scoped provisioning, inactive-by-default devices, idempotent revocation, offboarding, retention, negative isolation tests | **Complete — PR #2 merged; 292 passed, PostgreSQL RLS/restore green; secret/history scan green** |
| 08 | Authenticated endpoint agent | Device identity, signed requests, replay protection, versioning tests | **Next — blocked on a reviewed Platform-owned agent identity/credential contract; no duplicate identity authority** |
| 09 | Governed action engine | Tinlance Agent Platform contract tests, policy/approval evidence | Not started |
| 10 | Safe remediation playbooks | Allowlist, least privilege, bounded execution and postcondition tests | Not started |
| 11 | Orchestration recovery | Crash, retry, duplicate, partial failure and reconciliation tests | Not started |
| 12 | Telemetry pipeline | Provenance, freshness, schema, missing-data and retention tests | Not started |
| 13 | Predictive resilience evaluation | Reproducible labeled benchmark and model-quality report | Not started |
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

## Current implementation evidence

- Public playbook execution is disabled; local playbooks are recommendation-only.
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
