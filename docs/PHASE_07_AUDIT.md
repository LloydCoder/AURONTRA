# Phase 07 Forensic Audit — Organization and Device Lifecycle

**Audit scope:** organization lifecycle, device provisioning/revocation, tenant isolation, migration behavior, role policy, and release-gate documentation.

**Review rule:** this phase is not accepted until the current pull-request CI and secret/history scan are green on the exact candidate SHA. A green secret scan alone is insufficient. Deployment remains intentionally disabled while the business data plane is closed.

## Acceptance checklist

- [x] Alembic revision `0004_device_lifecycle` adds nullable `enrolled_at`, `revoked_at`, and `agent_version` fields and the organization/activity index.
- [x] Existing devices without enrollment proof are disabled during migration; their enrollment timestamps remain NULL.
- [x] Administrative provisioning creates an inactive device and does not claim the endpoint agent is enrolled.
- [x] Telemetry ingestion requires an active device and non-null enrollment timestamp.
- [x] Device revocation is tenant-scoped, idempotent, and preserves prior revocation timestamps.
- [x] Organization offboarding retains records, disables all tenant devices, and preserves existing revocation timestamps.
- [x] Normal tenant data dependencies reject offboarded organizations; the narrowly scoped lifecycle dependency permits only own-status inspection and idempotent offboarding.
- [x] Organization/device lifecycle operations require organization-admin/owner role under the JWT policy.
- [x] Negative tests cover cross-tenant revocation, inactive provisioning, offboarding, denied post-offboarding business access, and telemetry without enrollment proof.
- [x] Architecture and roadmap documents state that Phase 08 must provide cryptographic endpoint-agent enrollment and that provisioning is not enrollment.
- [x] Production data plane remains closed; no deployment or production readiness is claimed.
- [x] Full backend CI (unit/integration/SQLite migration/PostgreSQL RLS and backup/restore) green on tested candidate `aa03237b07e9b4eb0a5f4fb4a733153f25f43753` — [workflow run](https://github.com/LloydCoder/AURONTRA/actions/runs/38098658403).
- [x] Secret/archive scan green on tested candidate `aa03237b07e9b4eb0a5f4fb4a733153f25f43753` — [workflow run](https://github.com/LloydCoder/AURONTRA/actions/runs/38098658401).
- [x] Final diff review: this PR contains the Phase 07 audit record and two test-fixture corrections discovered by CI; no unrelated application changes.

## Files reviewed

- `backend/models/device.py`
- `backend/alembic/versions/0004_device_lifecycle.py`
- `backend/core/database.py`
- `backend/core/auth.py`
- `backend/api/routes/devices.py`
- `backend/api/routes/organizations.py`
- `backend/main.py`
- `backend/tests/integration/test_organization_device_lifecycle.py`
- `backend/tests/test_auth_baseline.py`
- `backend/tests/unit/test_predictor.py`
- `docs/ROADMAP.md`
- `docs/ARCHITECTURE.md`
- `docs/SECURITY_BASELINE.md`

## Known boundary / deferred work

Phase 07 does not implement cryptographic agent identity, signed request verification, nonce/replay storage, agent key rotation, or authenticated heartbeat/telemetry. These are mandatory Phase 08 gates. The API data plane remains disabled outside explicit test mode until all business subsystems have durable tenant-scoped persistence and the complete route inventory is independently verified.

## External design references

- NIST SP 800-207, Zero Trust Architecture: authenticate and authorize subject and device independently; network location and ownership are not implicit trust.
- RFC 9421, HTTP Message Signatures: Phase 08 should bind request signatures to the relevant HTTP components and apply explicit freshness/nonce policy; signatures do not replace TLS.
- OWASP API Security Top 10 (2023): test object-level authorization for every identifier-bearing route.


## Validation record

- Tested candidate: `aa03237b07e9b4eb0a5f4fb4a733153f25f43753`
- Backend suite: **292 passed, 1 skipped**, 83.56% coverage.
- SQLite Alembic upgrade and Python compilation: passed.
- PostgreSQL tenant RLS negative tests using a non-owner role: passed.
- PostgreSQL custom-format backup/restore and RLS policy preservation: passed.
- Secret scan: working tree, nested archives, and reachable Git history passed.
- Deployment: not attempted by the pull-request workflow; production data plane remains closed.
- This audit document was updated after the above successful candidate run. The final documentation-only commit must itself pass the same CI and secret/history gates before merge.
