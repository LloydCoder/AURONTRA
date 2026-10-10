# Aurontra Enterprise Hardening Roadmap

Aurontra is a Tinlance ecosystem product and a consumer of the four-repository Tinlance Agent System. It must not duplicate the Agent Platform's authoritative identity, authorization, policy, approval, sandbox, secrets, execution, or evidence controls.

Phases are sequential release gates. A phase is complete only after implementation, tests, documentation reconciliation, security review, and CI evidence. Passing CI does not certify production readiness.

| Phase | Scope | Acceptance evidence | Status |
|---|---|---|---|
| 01 | Forensic baseline, requirements and supply-chain inventory | Immutable baseline SHA, archive/history scan, risk register | In progress |
| 02 | Immediate containment and safe defaults | Negative tests for unsafe public actions; fail-closed webhook; audit | In progress |
| 03 | Authentication and tenant/resource authorization | JWT verification, RBAC, positive/negative cross-tenant tests | In progress — perimeter only |
| 04 | Threat model and security design | Threat register, mitigations, test mapping | Not started |
| 05 | Durable persistence and migrations | Alembic migration, tenant-scoped repositories, transaction/backup tests | In progress — schema foundation only |
| 06 | Durable jobs and event processing | Retry, idempotency, replay, cancellation and dead-letter tests | Not started |
| 07 | Organization/device lifecycle | Enrollment, revocation, ownership and offboarding tests | Not started |
| 08 | Authenticated endpoint agent | Device identity, signed requests, replay protection, versioning tests | Not started |
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

- Unsafe local playbook execution is disabled and playbooks are recommendation-only.
- Threat containment is disabled until a real enforcement adapter and independent verification exist.
- Billing webhook signatures fail closed; checkout and onboarding remain disabled.
- JWT/JWKS perimeter verification has been added, but no route-level RBAC or durable tenant isolation is claimed.
- Organization, API-key metadata, audit-event and webhook-idempotency models plus an Alembic bootstrap migration exist. These are not yet connected to route repositories.
- Production startup no longer mutates schema with `create_all`; it requires the configured migration revision when the data plane is requested.
- The production data plane remains closed by a code-level release gate.

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
