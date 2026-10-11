# Phase 12 — Forensic Audit: Telemetry Evidence Pipeline

**Decision:** Accepted at repository/CI level for the audited code revision. Production telemetry ingestion remains disabled until the external release gates below are satisfied.  
**Audited implementation commit:** `6b2e3a1f72afbf4bc1899b6b0bda96b1e7702ef4`  
**CI:** https://github.com/LloydCoder/AURONTRA/actions/runs/38104429834  
**Secret/history/archive scan:** https://github.com/LloydCoder/AURONTRA/actions/runs/38104429792  
**Pull request:** https://github.com/LloydCoder/AURONTRA/pull/9

## Verification results

- Backend: **392 passed, 1 skipped**, **85.04% total coverage**.
- Dependency consistency, clean SQLite Alembic migration, Python compile checks and backend tests passed.
- PostgreSQL migrations, non-owner tenant RLS tests, and backup/restore smoke test passed.
- Secret scan of current files, reachable Git history and nested archives passed.
- Deployment job was skipped by configuration. No production host, live identity provider, deployed agent, scheduler or customer telemetry source was exercised.

## Implementation findings

1. **Authenticated identity binding:** the Platform-issued DPoP-bound token supplies tenant/device identity. Optional collector `device_id` is a routing hint only and is rejected if it conflicts with the token subject.
2. **Strict payload contract:** schema version 1, timezone-aware observation timestamp, numeric bounds, rejection of unknown fields, and explicit missing-metric representation.
3. **Freshness controls:** stale and excessive-future observations are rejected. The accepted future skew is flagged.
4. **Replay resistance:** signed method/path/body binding and one-time DPoP proof JTI are persisted. Conflicting event-ID attempts consume the proof and return 409.
5. **Idempotency and provenance:** canonical payload hash, request hash, proof JTI, key thumbprint, source, agent version, observed/received timestamps, quality flags, score components/status and expiry are persisted. Telemetry record and outbox event are committed in one transaction.
6. **Ordering correctness:** out-of-order but still-fresh events are retained for evidence, marked `out_of_order`, and cannot overwrite current state. Persisted naive timestamps from SQLite are normalized to UTC before comparison.
7. **Partial-sample safety:** incomplete CPU/memory/disk samples are retained with `insufficient_data`, no composite score and no update to the device's current resilience score.
8. **Resource bound:** per-device ingestion is limited to a configurable default of 120 new events/minute; excessive new events receive 429 and `Retry-After: 60`. Duplicate events are checked before throttling to preserve idempotency.
9. **Tenant isolation:** the telemetry table has organization/device foreign keys, tenant-scoped event uniqueness, unique DPoP JTI, schema/score checks, and forced PostgreSQL RLS. CI exercises non-owner cross-tenant reads/writes.
10. **Retention primitive:** deletion is tenant-bound, validates session context and timezone-aware cutoff, and deletes at most 1,000 expired records per invocation. Retention expiry defaults to 90 days and is configurable within the documented range.

## Residual release blockers

- Production remains closed: `AGENT_AUTH_ENABLED=false` and `DATA_PLANE_ENABLED=false` are the defaults.
- No production identity-provider/JWKS configuration, signed agent release, customer environment, or TLS deployment verification has been exercised.
- Retention cleanup is a tested maintenance primitive only; no production scheduler, backlog monitor, or retention-run audit destination is configured.
- The outbox publisher and telemetry consumers are not wired to a production broker or evidence store.
- The per-device rate limit is not a tenant-wide quota and is not a substitute for edge/WAF, global rate controls, or storage-capacity planning.
- Current resilience scoring is a deterministic heuristic, not a validated predictive model. Real-world predictive quality, calibration, drift, and operational usefulness belong to Phase 13 and require labeled, separated evaluation data.
- The evidence record and hash fields establish provenance references, but do not alone make the data cryptographically immutable or prove the endpoint's underlying measurement is truthful.

## Research alignment

- OWASP API Security Top 10 (2023) highlights object-level authorization, authentication and unrestricted resource consumption as API risk areas: https://api-security.owasp.org/editions/2023/en/0x11-t10/
- NIST SP 800-92 describes enterprise log-management lifecycle practices for collection, retention and management: https://csrc.nist.gov/pubs/sp/800/92/final
- NIST AI RMF MEASURE and scikit-learn evaluation guidance support documented test sets, repeatable metrics, uncertainty, and keeping evaluation data separate from training data: https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf and https://scikit-learn.org/stable/model_selection.html

## Final verdict

Phase 12 satisfies the repository/CI acceptance gate on the audited implementation commit. It does **not** certify production readiness, predictive performance, or a live telemetry deployment. Proceed to Phase 13: reproducible predictive-resilience evaluation, keeping all production execution and data-plane switches closed.
