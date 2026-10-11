# Phase 12 — Telemetry Evidence Pipeline

**Status:** Implementation under CI validation. Production telemetry ingestion and retention remain disabled until Platform issuer configuration, database migration, collector deployment, and scheduled retention are verified.

## Purpose and boundaries

This phase turns authenticated endpoint telemetry into durable, tenant-scoped evidence. It does not certify predictive quality, prove a device is safe, or enable remediation. The Tinlance Agent Platform remains authoritative for agent identity and governed execution.

## Ingestion contract

- Endpoint identity and tenant identity come from the validated Platform-issued DPoP-bound access token, never from the JSON body.
- Each request is bound to a signed HTTP method, canonical path, body hash, DPoP proof JTI, device key thumbprint, tenant and device.
- Enrollment, key rotation and telemetry require distinct scopes and active, non-revoked device enrollment.
- Telemetry uses strict schema version `1`; unknown fields, invalid ranges, NaN/Infinity and timezone-naive timestamps are rejected.
- At least one of CPU, memory or disk must be present. Missing values are represented explicitly, never replaced with zero.
- Observation timestamps are bounded by `TELEMETRY_MAX_AGE_SECONDS` and `TELEMETRY_FUTURE_SKEW_SECONDS`; stale and excessive-future samples are rejected.
- Same tenant/device/event ID plus the same canonical payload hash is idempotent. Reusing an event ID with changed content returns HTTP 409. Each DPoP proof is consumed once, including rejected conflicting event attempts.
- Older-but-still-fresh observations may be stored with an `out_of_order` quality flag but may not overwrite current device state.
- Partial metric samples are stored as evidence with `insufficient_data` score status and no composite score. They never overwrite the current resilience score.

## Provenance and persistence

Migration `0007_telemetry_evidence` adds `telemetry_records` with tenant/device foreign keys, tenant-scoped event uniqueness, DPoP JTI uniqueness, schema and score bounds, source, agent version, device-key thumbprint, request and payload hashes, observation/receipt timestamps, metric completeness, quality flags, score components/status, and expiry timestamp.

The database transaction persists the telemetry record and its `telemetry.accepted` outbox event atomically. Outbox payloads contain bounded identifiers, hashes, quality metadata and score status; they do not include raw endpoint secrets. PostgreSQL enables and forces RLS, with a policy bound to `app.current_org_id`. The CI non-owner role test covers cross-tenant reads and writes, and backup/restore verifies the telemetry RLS policy survives restoration.

## Scoring semantics

The current score is a deterministic health heuristic over CPU, memory and disk utilization. It is not a predictive model, root-cause finding, threat verdict, or guarantee of availability. A score is persisted only when all three required metrics are present. Partial samples preserve component observations but cannot create a misleading overall score.

## Retention

`TELEMETRY_RETENTION_DAYS` sets a bounded expiry (default 90 days; allowed range 1–3650). `purge_expired_telemetry` deletes at most 1,000 expired records per call, requires an explicitly matching tenant-bound session, sets transaction-local PostgreSQL RLS context, and requires a timezone-aware cutoff. The function is a maintenance primitive; no production scheduler is configured in this phase. A production deployment must schedule it per tenant, record maintenance outcomes, monitor backlog, and prove restore/retention behavior before enabling ingestion.

## Operational and security gates

- `AGENT_AUTH_ENABLED=false` and `DATA_PLANE_ENABLED=false` remain secure defaults.
- CI covers schema/migration checks, DPoP replay, enrollment/revocation, provenance, idempotency/conflicting event IDs, freshness bounds, out-of-order ordering, partial-metric behavior, retention bounds, PostgreSQL RLS, backup/restore, and repository/history/archive secret scans.
- Production remains blocked on real issuer/JWKS configuration, TLS, tenant credentials, agent release/signing, telemetry consumer contracts, retention scheduler, observability/alerting, and a customer-environment verification run.
