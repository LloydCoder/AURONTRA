# Phase 10 — Forensic Audit

**Result:** Phase 10 accepted at repository/CI level after the 2026-10-11 follow-up audit. Production remediation remains disabled.  
**PR:** [#6 — Phase 10: add safe deterministic remediation planner](https://github.com/LloydCoder/AURONTRA/pull/6)  
**Original audited head:** `aa40ac0cc7779fe4522ace7a9bc2979c7aa7ef49`  
**Follow-up implementation audit SHA:** `8fe28b3ba661f1287699e76984546b7b31884019`  
**Original Phase 10 CI:** [Run 38101939727](https://github.com/LloydCoder/AURONTRA/actions/runs/38101939727)  
**Follow-up PR CI:** [Run 38120645677](https://github.com/LloydCoder/AURONTRA/actions/runs/38120645677)  
**Follow-up secret/archive scan:** [Run 38120645640](https://github.com/LloydCoder/AURONTRA/actions/runs/38120645640)

## Follow-up forensic finding (2026-10-11)

PR [#8](https://github.com/LloydCoder/AURONTRA/pull/8) was closed as superseded. Its branch predates Phases 11–16, proposes an alternate incompatible planner API, adds no tests for its 688-line planner/dispatcher, and contains an undefined `service_is_allowlisted` reference. The alternate planner was not merged. Useful safety-envelope changes were ported into the current architecture: `actions_taken` is always empty, recommendations are separate, caller-supplied metrics/domains/services/device IDs are marked unverified, missing service targets fail closed, and the dispatcher enforces non-execution status, outcome and timestamp semantics even for contradictory legacy playbook results. Regression tests cover these invariants.

## CI evidence

- Follow-up backend suite: **488 passed, 1 skipped**, **84.85% total coverage**; configured 60% minimum passed. [PR CI run 38120645677](https://github.com/LloydCoder/AURONTRA/actions/runs/38120645677).
- Dependency validation, clean SQLite Alembic migration, backend compilation and full tests passed.
- PostgreSQL migrations, non-owner tenant RLS tests and backup/restore smoke test passed.
- Secret/archive scan passed: [PR run 38120645640](https://github.com/LloydCoder/AURONTRA/actions/runs/38120645640).
- Production deployment was **skipped by configuration**. No live Platform tool, endpoint, production database, or customer action was exercised.

## Code and security review

1. **Pure planner:** `backend/resilience/playbooks/planner.py` performs no I/O, network requests, filesystem changes, process operations, service commands, or Platform calls.
2. **Trusted target boundary:** planning requires a typed server-constructed target with normalized tenant/device/actor/evidence identifiers and a timezone-aware observation timestamp. The calling service must load and verify these values from active tenant-scoped records; request JSON must not construct the object.
3. **Freshness and numeric checks:** evidence older than five minutes or more than one minute in the future is blocked. Metrics reject booleans, strings, NaN, infinity and out-of-range values.
4. **Allowlisting:** unknown playbooks fail closed. Service restarts are limited to the code-owned service set. Certificate renewal rejects URLs, localhost and malformed domains, requires a domain-ownership evidence reference, and performs no DNS/TLS probing.
5. **Bounded parameters:** only known parameters are copied into a plan. Unknown fields, shell commands, secrets and arbitrary request content do not flow to the Platform action request.
6. **Risk and approval metadata:** disk cleanup candidate review and certificate renewal are marked high risk/non-reversible as appropriate; service restart is high risk and approval-required; high-CPU remediation is recommendation-only; no diagnostics collection occurs. These local labels are descriptive only; the Platform remains authoritative for policy and approvals.
7. **Gated submission:** `RemediationService` is disabled by `REMEDIATION_SUBMISSION_ENABLED=false` by default and also requires Platform integration to be enabled. It checks tenant/device/actor/evidence agreement, reconstructs the plan to detect mutation and stale evidence, uses stable plan UUIDs for idempotency, and submits only allowlisted action keys through the official SDK adapter.
8. **No local fallback:** failures do not fall back to local `subprocess`, `systemctl`, Certbot, filesystem cleanup or process reprioritization.
9. **Approval and state semantics:** waiting-approval or non-completed Platform states do not call the postcondition verifier and are not promoted to success.
10. **Independent outcome verification:** a successful Platform execution is not enough. A separate verifier must return a strict boolean and bounded evidence references. Missing evidence, verifier exceptions, invalid evidence references or negative verification return `verification_failed`; the business outcome remains unverified.
11. **Adversarial tests:** tests cover stale/future evidence, threshold/range validation, non-allowlisted services, URL/local-domain rejection, forged plan mutation, default-disabled submission, tenant mismatch, approval-pending states, missing verifier, missing verification evidence, verifier exceptions and untrusted extra fields.

## Residual blockers and non-claims

- The action definitions in Aurontra are client-side request contracts. The Platform operator must register the exact matching capabilities/tools and configure their approval, budget, sandbox, and evidence policies. This was not validated against a live Platform.
- The `PostconditionVerifier` is an interface contract. A real implementation must query independently sourced, durable, tenant-scoped device state and return evidence IDs. Fake-verifier tests do not prove production verification.
- Durable remediation intents, atomic job/outbox creation, idempotency, lease/retry primitives and stale-state reconciliation scheduling were added in Phase 11 and are covered by their own tests. The processor is injected and no production worker/scheduler is configured, so public workflow enablement remains blocked.
- No public route invokes the service. This is intentional while the full data plane remains closed.
- No endpoint-agent registration, production credential, live action, deployment, rollback, SLO, or customer environment was tested.
- This is not a production-readiness certification, compliance attestation, or independent penetration test.

## Decision

Phase 10 is accepted at repository/CI level because safe planning, gated SDK submission, independent-verification contracts, negative tests, fail-closed response envelopes and forensic documentation are implemented and CI/security scanning are green. Production execution remains explicitly blocked by missing exact Platform registrations, a concrete tenant-scoped verifier, production worker/scheduler configuration, and full data-plane release gates. Phase 17 may proceed at repository/CI level; no public execution is enabled.
