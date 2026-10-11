# Phase 10 — Forensic Audit

**Result:** Original Phase 10 implementation passed its historical repository/CI gate; current safety-envelope follow-up requires fresh CI. Production remediation remains disabled.  
**PR:** [#6 — Phase 10: add safe deterministic remediation planner](https://github.com/LloydCoder/AURONTRA/pull/6)  
**Audited head:** `aa40ac0cc7779fe4522ace7a9bc2979c7aa7ef49`  
**CI:** [Run 38101939727](https://github.com/LloydCoder/AURONTRA/actions/runs/38101939727)  
**Secret/history/archive scan:** [Run 38101939719](https://github.com/LloydCoder/AURONTRA/actions/runs/38101939719)

## Follow-up forensic finding (2026-10-11)

The open PR #8 was compared against current main. Its branch predates Phases 11–16, proposes an alternate incompatible planner API, adds no tests for that 688-line planner/dispatcher, and contains an undefined `service_is_allowlisted` reference in `service_restart.py`. The alternate planner is not safe to merge as-is. The useful response-envelope hardening was ported to main: actions are empty, recommendations are separate, caller-supplied signals are marked unverified, missing service targets fail closed, and timestamps explicitly mean recommendation creation. Regression tests cover these invariants. PR #8 is to be closed as superseded after the current CI and security workflows pass; no production execution is enabled.

## CI evidence

- Backend suite: **371 passed, 1 skipped**, **84.79% total coverage**; configured 60% minimum passed.
- Dependency validation, clean SQLite Alembic migration, backend compilation and full tests passed.
- PostgreSQL migrations, non-owner tenant RLS tests and backup/restore smoke test passed.
- Working tree, reachable Git history and nested-archive secret scan passed.
- Production deployment was **skipped by configuration**. No live Platform tool, endpoint, production database, or customer action was exercised.

## Code and security review

1. **Pure planner:** `backend/resilience/playbooks/planner.py` performs no I/O, network requests, filesystem changes, process operations, service commands, or Platform calls.
2. **Trusted target boundary:** planning requires a typed server-constructed target with normalized tenant/device/actor/evidence identifiers and a timezone-aware observation timestamp. The calling service must load and verify these values from active tenant-scoped records; request JSON must not construct the object.
3. **Freshness and numeric checks:** evidence older than five minutes or more than one minute in the future is blocked. Metrics reject booleans, strings, NaN, infinity and out-of-range values.
4. **Allowlisting:** unknown playbooks fail closed. Service restarts are limited to the code-owned service set. Certificate renewal rejects URLs, localhost and malformed domains, requires a domain-ownership evidence reference, and performs no DNS/TLS probing.
5. **Bounded parameters:** only known parameters are copied into a plan. Unknown fields, shell commands, secrets and arbitrary request content do not flow to the Platform action request.
6. **Risk and approval metadata:** disk cleanup candidate review and certificate renewal are marked high risk/non-reversible as appropriate; service restart is high risk and approval-required; high-CPU remediation is read-only diagnostics. These local labels are descriptive only; the Platform remains authoritative for policy and approvals.
7. **Gated submission:** `RemediationService` is disabled by `REMEDIATION_SUBMISSION_ENABLED=false` by default and also requires Platform integration to be enabled. It checks tenant/device/actor/evidence agreement, reconstructs the plan to detect mutation and stale evidence, uses stable plan UUIDs for idempotency, and submits only allowlisted action keys through the official SDK adapter.
8. **No local fallback:** failures do not fall back to local `subprocess`, `systemctl`, Certbot, filesystem cleanup or process reprioritization.
9. **Approval and state semantics:** waiting-approval or non-completed Platform states do not call the postcondition verifier and are not promoted to success.
10. **Independent outcome verification:** a successful Platform execution is not enough. A separate verifier must return a strict boolean and bounded evidence references. Missing evidence, verifier exceptions, invalid evidence references or negative verification return `verification_failed`; the business outcome remains unverified.
11. **Adversarial tests:** tests cover stale/future evidence, threshold/range validation, non-allowlisted services, URL/local-domain rejection, forged plan mutation, default-disabled submission, tenant mismatch, approval-pending states, missing verifier, missing verification evidence, verifier exceptions and untrusted extra fields.

## Residual blockers and non-claims

- The action definitions in Aurontra are client-side request contracts. The Platform operator must register the exact matching capabilities/tools and configure their approval, budget, sandbox, and evidence policies. This was not validated against a live Platform.
- The `PostconditionVerifier` is an interface contract. A real implementation must query independently sourced, durable, tenant-scoped device state and return evidence IDs. Fake-verifier tests do not prove production verification.
- No durable remediation intent or crash/retry/reconciliation record exists. Phase 11 must add durable intent persistence, leases, retry safety, idempotency/reconciliation and outbox coordination before any public workflow can be enabled.
- No public route invokes the service. This is intentional while the full data plane remains closed.
- No endpoint-agent registration, production credential, live action, deployment, rollback, SLO, or customer environment was tested.
- This is not a production-readiness certification, compliance attestation, or independent penetration test.

## Decision

Phase 10 is accepted at repository/CI level because safe planning, gated SDK submission, independent-verification contracts, negative tests and forensic documentation are implemented and CI is green. Production execution remains explicitly blocked by missing exact Platform registrations, a concrete tenant-scoped verifier, durable orchestration, deployment configuration and full data-plane release gates. Proceed to Phase 11 without enabling public execution.
