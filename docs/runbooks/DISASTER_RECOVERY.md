# Disaster Recovery Runbook

## Status and objectives

- **Runbook status:** operational template; not yet exercised against production infrastructure.
- **Proposed RTO:** 4 hours, pending service-owner approval.
- **Proposed RPO:** 15 minutes, pending database-backup and replication evidence.
- **Current evidence:** CI validates PostgreSQL backup/restore mechanics and RLS policy preservation. This is not a measured production RTO/RPO.

## Activation criteria

Activate for confirmed data loss/corruption, prolonged database unavailability, failed deployment with unsafe rollback, or suspected compromise of the primary environment. Assign an incident commander and database/recovery operator.

## Recovery procedure

1. Declare the incident, record UTC start time, preserve relevant deployment IDs/log references, and freeze non-emergency writes and schema changes.
2. Determine whether the incident is application-only, database-only, credential-related, or a broader infrastructure failure. Do not promote a recovery environment based solely on `/health/live`.
3. Identify the latest known-good encrypted backup and its timestamp. Verify backup integrity and access authorization before restoring.
4. Restore into an isolated environment first. Do not overwrite the primary database during initial validation.
5. Verify Alembic revision, required RLS policies and forced-RLS flags, append-only triggers, critical table counts, tenant boundary tests, and application-level digest checks.
6. Compare the restore point to the last known-good transaction/replication marker and record estimated data loss. If RPO cannot be demonstrated, obtain explicit incident-commander approval before promotion.
7. Run smoke tests with a non-owner database role, including cross-tenant read/write rejection. Verify the business data plane remains disabled until the restored schema and credentials are approved.
8. Promote the recovery database only after database-owner and security approval. Rotate credentials if compromise is plausible; never copy secrets into incident notes.
9. Validate `/health/ready`, representative tenant-scoped reads, outbox/job state, audit-chain continuity, and error/latency metrics. Confirm no unexpected replay or duplicate external side effects.
10. Record actual RTO/RPO, validation evidence, deviations, approvals, and follow-up actions. Re-enable traffic gradually and monitor for at least one agreed observation window.

## Rollback and stop conditions

- Stop promotion if tenant RLS is missing/disabled, schema revision mismatches, audit/report digests fail, or cross-tenant tests do not pass.
- Keep the business data plane disabled if external identity, Platform, verifier, worker, or database prerequisites are not configured.
- Do not retry ambiguous external remediation actions as part of database recovery; reconcile through the Agent Platform and preserve idempotency keys.
- If the restored state is uncertain, retain both environments read-only and escalate rather than guessing.

## Post-incident review

Within the agreed review period, reconcile timelines, backup age, measured data loss, restore duration, failed controls, alert effectiveness, and corrective owners. Update SLOs only after service-owner approval.