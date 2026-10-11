# Phase 06 — Durable Jobs and Event Processing: Forensic Audit

**Product:** Aurontra (formerly ResilientAI)  
**Owner:** Tinlance Limited  
**Phase status:** Complete at the code/CI gate; production worker deployment is not claimed.  
**Reviewed implementation commit:** `91c80eb9ef167fd7a44a5d30fde1c7f7789dab89`  
**CI:** [Run 38097810533](https://github.com/LloydCoder/AURONTRA/actions/runs/38097810533)  
**Secret/archive/history scan:** [Run 38097810453](https://github.com/LloydCoder/AURONTRA/actions/runs/38097810453)

## Objective

Provide durable, tenant-scoped asynchronous work and reliable domain-event publication without creating a second execution authority or falsely claiming exactly-once delivery.

## Implementation reviewed

- `backend/models/durable_job.py`: tenant-owned `DurableJob` and `OutboxEvent` records with unique per-tenant idempotency keys, bounded state enums, attempt/lease metadata and indexed claim paths.
- `backend/alembic/versions/0003_durable_jobs_and_outbox.py`: forward migration after revision `0002_tenant_foreign_keys_and_rls`; adds both tables and forced PostgreSQL RLS. Downgrade is deliberately refused because operational records are not safely discarded by an automatic rollback.
- `backend/core/job_queue.py`: idempotent enqueue; idempotency conflict on semantic key reuse; `FOR UPDATE SKIP LOCKED` claiming; expiring leases; retries/backoff; cancellation; stale-lease recovery; terminal dead-letter handling; outbox acknowledgement and safe error-code allowlisting.
- `backend/workers/job_worker.py`: explicit handler/publisher registry injection, bounded batch and timeout parameters, validated result shape/size, no implicit handler execution, and cancellation behavior that leaves unacknowledged work for lease recovery.
- `backend/api/routes/tickets.py`: `ticket.created` outbox event is persisted in the same transaction as ticket creation; payload carries only ticket ID and source.
- `backend/tests/integration/test_durable_job_queue.py`: idempotency, semantic conflict, retries, worker lease ownership, cancellation, dead-letter behavior, outbox atomicity, publication, explicit-handler dispatch and expired-lease recovery.
- `backend/tests/integration/test_tenant_rls.py`: non-owner PostgreSQL tests for organizations, devices, tickets, durable jobs and outbox events, including cross-tenant reads/writes.
- `.github/workflows/ci.yml`: migration upgrade, backend test suite, PostgreSQL RLS and backup/restore smoke checks.

## Acceptance results

| Gate | Result |
|---|---|
| Clean SQLite Alembic upgrade through revision 0003 | Pass |
| Python compile | Pass |
| Backend test suite | 285 passed, 1 skipped |
| Total test coverage | 83.65% |
| PostgreSQL RLS under non-owner/non-BYPASSRLS role | Pass |
| PostgreSQL dump/restore smoke test and queue-table RLS verification | Pass |
| Secret scan of current tree, archives and reachable history | Pass |
| CI workflow conclusion | Success |
| Production deployment | Skipped by explicit deployment gate; not a production pass |

## Forensic findings and residual risks

1. **At-least-once, not exactly-once.** A publisher may send an event and crash before persisting the acknowledgement. Downstream consumers must deduplicate. The code and documentation do not claim exactly-once semantics.
2. **No production worker is running by virtue of this commit.** A scheduler/process supervisor, publisher destination, deployment configuration, queue monitoring and operational runbook still need implementation and verification.
3. **Inbound payment webhooks are separate.** The outbox handles outbound product events. Lemon Squeezy webhook event deduplication, transactional inbox processing and provider-state reconciliation remain blocked.
4. **No privileged execution in the generic worker.** Unknown job types are dead-lettered. Registered handlers must re-check tenant/resource authorization, use idempotency, and route consequential infrastructure actions through Tinlance Agent Platform.
5. **Payload discipline remains an operational contract.** Queue payloads must not contain credentials, raw ticket content or unnecessary PII. Events carry identifiers; consumers refetch authorized records.
6. **Data plane remains closed.** Other business modules still contain legacy in-memory or caller-supplied state and have not passed the complete tenant isolation gate.
7. **Production deployment is not verified.** The CI deploy job was skipped because `vars.DEPLOY_ENABLED` is not enabled. No production host or customer database was changed by this phase.

## Decision

**Phase 06 is complete for source implementation and automated acceptance.** Its production operationalization is not certified. Proceed to Phase 07 (organization/device lifecycle) while keeping the production data plane closed and all unsafe execution/containment paths disabled.
