# Phase 11 — Durable Remediation Orchestration and Recovery

**Status:** Complete at code/CI level; production dispatch remains disabled.  
**Authority:** The Tinlance Agent Platform remains the sole policy, approval, execution and authoritative evidence system.

## Architecture

1. A trusted application service constructs a remediation plan from a tenant-scoped active device and current evidence.
2. `enqueue_remediation_intent(session, plan, target)` validates target/plan agreement and reconstructs the plan to reject mutation or stale evidence.
3. In one caller-owned database transaction, Aurontra persists the intent and creation outbox event. If submission is enabled, it also enqueues a `remediation.submit` durable job. Duplicate writes reuse deterministic idempotency keys.
4. The worker claims a durable job under a lease. Tenant-aware handlers receive the authoritative organization ID from the claimed job row—not solely from JSON payload—and set PostgreSQL RLS context before tenant queries.
5. The handler re-checks active organization/device enrollment, validates the job operation/idempotency key, records `submitting`, then calls an injected processor. That processor must reload evidence/target and call the Phase 10 Platform-governed service.
6. An ambiguous processor failure is recorded as `unknown_outcome`; the job retries using the same stable plan key. The system never assumes timeout means the Platform did not accept the action.
7. Results are persisted as `approval_pending`, `platform_pending`, `verified`, `verification_failed`, or `failed`. `verified` requires a completed Platform state, execution ID, explicit outcome verification and non-empty postcondition evidence.
8. A reconciliation scheduler may enqueue version-bound jobs for stale approval/platform/verification/unknown states. Stale reconciliation jobs become no-ops when the intent version changed.

## State model

- `proposed` — durable plan, no submission queued.
- `queued` — durable submit job exists.
- `submitting` — processor call may be in progress.
- `approval_pending` — Platform requires approval; no success claim.
- `platform_pending` — Platform accepted or returned a nonterminal state.
- `awaiting_verification` — execution needs independent postcondition checks.
- `unknown_outcome` — processor/transport failed after a possible external acceptance; reconcile with the same idempotency key.
- `verified` — Platform completion plus independent postcondition evidence.
- `verification_failed` — outcome is not verified, even if execution was accepted.
- `failed` / `cancelled` — terminal operational outcomes.

State transitions use row locks, a monotonically increasing version and an outbox event. `reason_code` is distinct from `last_error_code`. Terminal states cannot be reopened by a worker retry.

## Database and tenant isolation

Revision `0006_remediation_intents` creates a durable table with unique tenant/idempotency and tenant/plan constraints, an organization foreign key, a composite organization/device foreign key, state checks and reconciliation indexes. PostgreSQL enables and forces RLS with `app.current_org_id`. The CI RLS test exercises cross-tenant reads/writes and the backup/restore workflow includes the new table.

## Safe rollout

- `REMEDIATION_SUBMISSION_ENABLED=false` remains the default.
- No production worker registers the remediation handler by default.
- The processor is dependency-injected; no local shell, filesystem, process, service or certificate side effect is permitted.
- The reconciliation function is not scheduled by a production timer.
- The outbox publisher is not connected to a production broker.
- External Platform tool registration, approved credentials, concrete tenant-scoped verifier and evidence pipeline are prerequisites to enable dispatch.

## Verification

See [Phase 11 forensic audit](docs/audits/PHASE_11_FORENSIC_AUDIT.md). CI run 38102735277 passed 382 tests with 1 skipped and 84.93% coverage; PostgreSQL RLS/backup-restore and secret/history/archive scans passed. Deployment was skipped.
