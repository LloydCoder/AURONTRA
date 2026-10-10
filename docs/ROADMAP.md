# Aurontra Enterprise Hardening Roadmap

Aurontra is part of the Tinlance ecosystem. It must consume the authoritative Tinlance Agent System through supported contracts and must not duplicate the Agent Platform's identity, authorization, policy, approval, sandbox, secrets, runtime or audit authority.

Phases are sequential release gates. A phase is complete only when implementation, tests, documentation, security review and CI evidence are reconciled. Roadmap entries do not imply completion.

| Phase | Scope | Acceptance evidence | Status |
|---|---|---|---|
| 01 | Forensic baseline, requirements and supply-chain inventory | Immutable baseline SHA, file/archive/history review, risk register | In progress |
| 02 | Immediate containment and safe defaults | Negative tests for unsafe public actions; webhook fails closed | In progress |
| 03 | Authentication and tenant/resource authorization | Positive and negative identity/RBAC/cross-tenant tests | Not started |
| 04 | Threat model and security design | Threat register, owners, mitigations, test mapping | Not started |
| 05 | Durable persistence and migrations | Migration, transaction, tenancy, backup/restore tests | Not started |
| 06 | Durable jobs and event processing | Retry, idempotency, replay, cancellation and dead-letter tests | Not started |
| 07 | Organization/device lifecycle | Enrollment, revocation, ownership and offboarding tests | Not started |
| 08 | Authenticated endpoint agent | Device identity, signed requests, replay protection, versioning tests | Not started |
| 09 | Governed action engine | Agent Platform contract tests, policy and approval evidence | Not started |
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

## Serial execution protocol

1. Record the exact commit SHA and CI state before each phase.
2. Implement one phase at a time; do not start the next until the current phase's required checks pass.
3. Add or update tests with each behavior change.
4. Reconcile code, tests, configuration, docs, release notes and threat register.
5. Inspect workflow job logs, not just the summary badge.
6. Audit the completed phase against acceptance criteria and inspect changed files before proceeding.
7. Record unresolved external dependencies explicitly; do not claim a green production release if deployment credentials or environment access are missing.
8. After Phase 24, audit the complete repository, history, artifacts, integrations and release evidence.

## Non-negotiable status distinctions

- Unit tests passing is not equivalent to full CI passing.
- Full CI passing is not equivalent to successful deployment.
- Deployment success is not equivalent to verified runtime correctness.
- A threat decision is not a verified containment event.
- Control mapping is not compliance certification.
- Estimated ROI is not measured savings.


## Phase 2 — durable tenant and evidence foundation (in progress)

- Added schema definitions for organizations, hashed API-key metadata, append-only ORM audit events, and provider/event idempotency records.
- These model definitions are not yet a production migration and do not by themselves enable the business data plane.
- Remaining phase gates: Alembic migration history, tenant foreign keys and repository adoption across all routes, transactional writes, PostgreSQL/RLS design, API-key verification/rotation/revocation, audit-chain concurrency tests, webhook replay tests, backup/restore validation, and a full cross-tenant isolation suite.
