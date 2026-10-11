# Phase 11 — Forensic Audit

**Result:** Accepted at repository/CI level; production orchestration remains disabled.  
**PR:** [#7 — Phase 11: durable remediation intent and crash recovery](https://github.com/LloydCoder/AURONTRA/pull/7)  
**Audited implementation head:** `08bc628080c4f5c6dd6dc30d2757d0850679cd6d`  
**CI:** [Run 38102735277](https://github.com/LloydCoder/AURONTRA/actions/runs/38102735277)  
**Secret/history/archive scan:** [Run 38102735270](https://github.com/LloydCoder/AURONTRA/actions/runs/38102735270)

## CI evidence

- Backend suite: **382 passed, 1 skipped**, **84.93% total coverage**; configured 60% minimum passed.
- Clean SQLite Alembic migration, compile checks, full backend suite and dependency checks passed.
- PostgreSQL migrations, non-owner tenant RLS tests and backup/restore smoke test passed with the new `remediation_intents` table.
- Working-tree, reachable Git-history and nested-archive secret scan passed.
- Deployment was **skipped by configuration**. No live worker, scheduler, endpoint or Platform action was exercised.

## Implementation and security findings

1. **Durable intent:** `RemediationIntent` persists plan, tenant/device identity, deterministic plan/idempotency keys, status/version, Platform execution/evidence references, reason/error codes and timestamps.
2. **Tenant boundary:** the model uses an organization foreign key and composite organization/device foreign key; PostgreSQL forced RLS scopes records to `app.current_org_id`. Creation and reads require a tenant-scoped session.
3. **Plan provenance:** intent creation requires a typed trusted target, exact tenant/device/actor/evidence agreement, fresh evidence, and reconstruction of the plan from allowlisted parameters. Modified plan objects are rejected.
4. **Atomic enqueue:** intent, optional `remediation.submit` job, and initial outbox event are written inside the caller-owned transaction. Stable idempotency keys prevent duplicate intents/jobs/events; conflicting content is rejected.
5. **State machine:** allowed transitions are explicit and locked; terminal states cannot be reopened. State changes increment a version and append an outbox event. Reason codes and error codes are distinct; existing Platform evidence is preserved across transitions.
6. **Tenant-aware worker:** `process_job_batch` can pass the organization ID from the claimed durable-job row as a trusted third argument. The remediation handler verifies the payload tenant matches that value and establishes the database RLS context from the trusted row value.
7. **Enrollment check:** the handler re-checks active organization and active, enrolled, non-revoked device before invoking the injected processor.
8. **Crash and retry:** a processor exception after a potentially accepted Platform request becomes `unknown_outcome`; the durable job retries and the processor receives the same stable plan idempotency key. This avoids assuming a timeout means the remote action did not happen.
9. **Reconciliation:** stale `approval_pending`, `platform_pending`, `awaiting_verification`, and `unknown_outcome` intents can be re-enqueued with a version-bound idempotency key. Stale reconciliation jobs become no-ops if the intent version has changed.
10. **Outcome semantics:** a processor response cannot mark an intent `verified` unless it reports completed/succeeded Platform state, a valid execution ID, explicit verified outcome, and non-empty bounded postcondition evidence references. Invalid evidence or missing verification downgrades the intent to `verification_failed`.
11. **Failure hygiene:** exception text is not persisted. Error/reason codes and external evidence identifiers are bounded and validated. Local shell/process/filesystem/service actions are not used as fallbacks.
12. **Adversarial tests:** coverage includes duplicate intent creation, altered plan rejection, unenrolled devices, invalid state transitions, tenant mismatch, processor crash/retry, stale reconciliation, and verified claims without postcondition evidence.

## Residual blockers and non-claims

- The processor is an injected interface, not a production implementation. It must load current tenant-scoped evidence and target state, reconstruct a trusted target, use the Phase 10 Platform service, and return only validated evidence references.
- No worker service is registered to dispatch `remediation.submit` or `remediation.reconcile` in production. The handler is not enabled by default.
- The reconciliation scheduling function is not called by a production scheduler. No live clock/queue integration has been tested.
- The transactional outbox publisher is not connected to a production broker/event destination.
- No live Platform tool registration, credential provider, endpoint agent, production database, customer environment, or postcondition verifier was tested.
- Source evidence is referenced by identifier but not yet backed by the full telemetry/evidence pipeline; Phase 12 must supply provenance, freshness, retention, and tenant-scoped evidence reads.
- This is not a production-readiness certification, independent penetration test, compliance attestation, or proof of exactly-once execution. The delivery contract is at-least-once with idempotency/reconciliation.

## Decision

Phase 11 is accepted at repository/CI level: durable intent state, transactionally coupled jobs/outbox, tenant-aware dispatch, crash-safe unknown outcomes, versioned reconciliation and negative tests are implemented and CI is green. Public remediation and production dispatch remain disabled until the processor, tenant-scoped verifier, worker/scheduler deployment and external Platform configuration are implemented and tested. Proceed to Phase 12 telemetry/evidence provenance without enabling production execution.
