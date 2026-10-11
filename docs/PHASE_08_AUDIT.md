# Phase 08 Forensic Audit — Platform-Bound Endpoint Agent Identity

**Scope:** endpoint-agent token verification, DPoP proof-of-possession, replay persistence, device enrollment, telemetry authorization, key rotation, tenant isolation, migration/RLS, and ecosystem authority boundaries.

**Candidate tested:** `1042a54bac25afe473d31fa8e655691f720f8cca`

## Implementation audit

- [x] Aurontra acts only as a resource server. It does not issue agent tokens, generate/store private keys, or create generic execution authority.
- [x] Access tokens are verified against configured issuer/JWKS and exact audience; required claims include expiry, issued-at, subject, token ID, tenant, scope, and sender-constraint `cnf.jkt`.
- [x] Token lifetime is bounded; malformed subject/tenant/token identifiers are rejected.
- [x] DPoP proofs require `typ=dpop+jwt`, asymmetric signing, public-only JWK, key/token thumbprint match, method/URI binding, freshness, access-token hash, and body hash (`bht` Aurontra extension).
- [x] One-use proof IDs are persisted in `agent_request_replays` with a unique key, tenant/device foreign key, expiry index, and forced PostgreSQL RLS.
- [x] Agent enrollment requires the Platform-approved enrollment scope and only activates an existing unrevoked device after proof verification.
- [x] Telemetry requires the Platform-approved telemetry scope, matching subject/tenant, active enrollment, non-revoked state, and the enrolled key thumbprint.
- [x] Key rotation requires a separate Platform-approved scope bound to the new key; the previous key is rejected after rotation.
- [x] Enrollment and key rotation create non-secret transactional outbox evidence in the same transaction as the lifecycle change.
- [x] Replay rejection, body tampering, wrong scope, cross-tenant device reference, revoked device, enrollment, key rotation, and default-disabled behavior have integration tests.
- [x] Production requires HTTPS issuer/JWKS and a canonical HTTPS origin; agent authentication is disabled by default.
- [x] The product-wide production data plane remains closed; tests are not represented as production deployment evidence.

## Validation record

- Backend CI: **300 passed, 1 skipped, 83.06% coverage** — [workflow run](https://github.com/LloydCoder/AURONTRA/actions/runs/38099516440).
- SQLite migration upgrade and Python compilation: passed in the same workflow.
- PostgreSQL RLS tests using a non-owner/non-bypass role: passed.
- PostgreSQL custom-format backup/restore with tenant policies preserved: passed.
- Secret/archive scan: passed — [workflow run](https://github.com/LloydCoder/AURONTRA/actions/runs/38099516437).
- Deployment: skipped by design; no production readiness claim is made.

This audit record is added after the tested candidate. The final PR SHA must pass the same backend CI, PostgreSQL RLS/backup-restore, and secret/history scan before merge.

## Production prerequisites (not implied by green CI)

1. The Platform-approved identity provider must provision a workload principal for each device ID and issue DPoP-bound tokens with the documented claims/scopes.
2. Configure `AGENT_AUTH_ENABLED=true`, issuer, JWKS, audience, and canonical HTTPS origin only after issuer behavior and key-binding semantics are verified.
3. Keep the business data plane disabled until every remaining Aurontra subsystem has durable tenant-scoped persistence, authorization, and release evidence.
