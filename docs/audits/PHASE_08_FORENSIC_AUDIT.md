# Phase 08 — Forensic Audit Record

**Phase:** Platform-bound endpoint-agent identity  
**Result:** Pass for repository implementation and CI acceptance; production activation remains gated.  
**Merged commit:** `830047fa11b75c97f2b7b67847cd28f727b3b4a8`  
**Pull request:** [#3 — Phase 08: endpoint agent identity](https://github.com/LloydCoder/AURONTRA/pull/3)  
**CI run:** [38099722168](https://github.com/LloydCoder/AURONTRA/actions/runs/38099722168)  
**Secret/history/archive scan:** [38099722150](https://github.com/LloydCoder/AURONTRA/actions/runs/38099722150)

## Acceptance evidence

- Backend suite: **300 passed, 1 skipped**, one warning; **83.06% line coverage**. Coverage threshold is 60%, so passing this gate does not imply uniformly high coverage for every module.
- PostgreSQL migration chain reached `0005_agent_dpop_identity`.
- PostgreSQL tenant RLS tests passed using a non-owner role.
- PostgreSQL custom-format backup/restore smoke test passed and verified tenant-owned RLS flags/policies on the restored database, including the replay-protection table.
- Gitleaks scan of the working tree, reachable Git history, and nested archives passed; tracked deployment archives are rejected.
- Main CI overall conclusion was success. The deployment job was **skipped by configuration**, not deployed or runtime-verified.

## Files and controls reviewed

- `backend/core/agent_auth.py`: JWT/JWKS verification, issuer/audience/TTL checks, DPoP public-key thumbprint binding, request method/URI, access-token hash, request-body hash, freshness and proof identifier validation.
- `backend/api/routes/agent.py`: scoped enrollment, telemetry, key rotation, device lifecycle checks, transactional replay records and outbox lifecycle evidence.
- `backend/models/agent_request_replay.py`, `backend/models/device.py`, and Alembic revision `0005_agent_dpop_identity`: durable replay state, tenant/device ownership, indexes, PostgreSQL forced RLS, enrolled key thumbprint and rotation timestamp.
- `backend/tests/integration/test_agent_dpop.py`: enrollment, proof replay, exact-body binding, tenant binding, scope enforcement, key rotation, old-key rejection, disabled-by-default behavior and revoked-device rejection.
- `backend/main.py` and `backend/core/config.py`: fail-closed defaults and production issuer/origin configuration validation.
- `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, and this phase specification: authority boundary and release-gate status.

## Forensic findings and remaining release prerequisites

1. **No production issuer has been configured or end-to-end tested.** This repository verifies tokens; it does not issue them or own device private keys. A Platform-approved issuer contract, per-device principal provisioning, real JWKS/TLS validation and a deployed endpoint agent are still required before enabling agent authentication.
2. **The product-wide data plane remains closed.** Ticket/device persistence and RLS are not evidence that all legacy business modules are tenant-safe. Do not set `DATA_PLANE_ENABLED=true` until Phases 09–23 and the product-wide release gate establish every route's durable persistence and authorization.
3. **Telemetry is currently reduced to device score and last-seen state.** Raw, time-series telemetry persistence, freshness/retention policy, and provenance belong to Phase 12; the endpoint API response must not be represented as a complete telemetry archive.
4. **Request-size enforcement at the application middleware checks declared Content-Length.** Production gateway/proxy must enforce streamed body-size limits, request timeouts, per-tenant rate limits and concurrency budgets. This is explicitly not certified by this phase.
5. **DPoP body-hash claim `bht` is an Aurontra protocol extension.** The endpoint agent and issuer integration must implement the same canonical byte-level signing contract. It must not be described as an unmodified RFC 9449 claim.
6. **CI deploy was skipped.** CI is green, but no production deployment, live issuer connectivity, live endpoint handshake, production backup configuration or runtime SLO has been verified.

## Phase boundary decision

No repository-level blocker was found that prevents proceeding to Phase 09's contract-first governed action-engine integration. The above external/runtime prerequisites remain release blockers, not reasons to open the data plane. Phase 09 must consume the reviewed Tinlance Agent Platform SDK and TSIC contracts; Aurontra must not mint authority, execute local privileged actions, or duplicate Platform policy, approvals, sandboxing, secrets, execution, budgets or authoritative evidence.
