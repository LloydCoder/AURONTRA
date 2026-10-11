# Phase 10 — Safe Remediation Playbooks

**Status:** Complete at repository/CI level after the follow-up forensic audit; production remediation remains disabled. Baseline CI at `9685e413ac1be3529d118eec65d290637d24cb3a` passed 488 tests (1 skipped, 84.85% coverage); see [run 38120377781](https://github.com/LloydCoder/AURONTRA/actions/runs/38120377781). No public remediation route is enabled.  
**Authority:** Tinlance Agent Platform remains the only execution/policy/approval authority.  
**Research basis:** NIST SP 800-53 Rev. 5 AC-5/AC-6 and CM-3; OWASP Authorization Cheat Sheet and Secure-by-Default guidance. These sources support least privilege, separation of duties, explicit change control, and default-deny behavior. See [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), and [OWASP Secure by Default](https://devguide.owasp.org/en/04-design/02-web-app-checklist/01-secure-by-default/).

## Scope

Phase 10 creates a deterministic, pure remediation planner for the existing disk pressure, service restart, certificate expiry, and high CPU playbooks. It does not enable execution or connect public routes to Platform tools. Plans can be proposed only from a server-constructed target and tenant-scoped evidence; the public route stays disabled until durable intent/reconciliation, Platform registration, approved tenant credentials, and independent postcondition verification are available.

## Safety contract

- The planner performs no I/O, network probes, filesystem operations, shell/subprocess calls, service restarts, Certbot calls, process inspection, or Platform calls.
- Legacy playbook responses use `status=simulated`, `execution_mode=recommendation_only`, `execution_enabled=false`, `business_outcome_verified=false`, and an empty `actions_taken` list. Proposed actions are emitted under `recommendations`; caller-supplied metrics/domains/services are explicitly marked unverified.
- Caller-supplied request JSON is not a trusted target. The application must first verify tenant, active device enrollment, actor, and evidence ownership and then construct `TrustedRemediationTarget`.
- Evidence is freshness-bounded to five minutes with a one-minute future-skew tolerance. Stale, future-dated, malformed, or below-threshold evidence blocks a proposal.
- Inputs are validated with strict type/range checks. Boolean values are not accepted as numeric metrics.
- Playbook and service names are code-owned allowlists. Unknown names fail closed.
- The plan includes only allowlisted parameters; arbitrary request fields, commands, secrets, and free-form shell instructions are not forwarded.
- Disk cleanup is destructive and always requires approval; the only proposal is review of app-owned cleanup candidates.
- Service restart is disruptive, restricted to a small allowlist, and always requires approval.
- Certificate renewal requires a syntactically valid public FQDN and a reference to domain-ownership evidence. The planner does not probe the domain and does not assert that a reference itself proves ownership; the calling service must resolve and validate it from the tenant's durable asset inventory.
- High-CPU handling proposes read-only diagnostics; it does not inspect processes or collect host telemetry. No process killing, reprioritization, or arbitrary command execution occurs.
- Every plan explicitly marks execution, Platform submission, enforcement, and business outcome verification as false. Plan IDs are deterministic for identical tenant/device/evidence/action inputs to support idempotent orchestration. Phase 11 now persists remediation intents, atomically creates job/outbox records, and schedules reconciliation; the production worker/scheduler remains unconfigured.
- A plan is not an approval or authorization grant. Platform policy, approvals, budgets, sandbox, secrets, tool registration and evidence remain authoritative.

## Verification record

- Original implementation PR: [#6 — Phase 10 safe remediation](https://github.com/LloydCoder/AURONTRA/pull/6).
- Follow-up PR [#8](https://github.com/LloydCoder/AURONTRA/pull/8) was reviewed and closed as superseded because it was based on a stale pre-Phase-11 branch, proposed an incompatible duplicate planner, and contained an undefined variable. Selected safety-envelope improvements were ported to main; the duplicate planner is not accepted as a second execution path.
- Audited implementation commit: `aa40ac0cc7779fe4522ace7a9bc2979c7aa7ef49`.
- CI: [run 38101939727](https://github.com/LloydCoder/AURONTRA/actions/runs/38101939727) — 371 passed, 1 skipped, 84.79% coverage; PostgreSQL tenant RLS and backup/restore passed.
- Secret/history/archive scan: [run 38101939719](https://github.com/LloydCoder/AURONTRA/actions/runs/38101939719) — success.
- Deployment: skipped by configuration. No live Platform tool registration, endpoint, or production runtime was tested.

## Follow-up audit evidence (2026-10-11)

- Implementation audit SHA: `8fe28b3ba661f1287699e76984546b7b31884019`.
- Parent-main baseline: [CI run 38120377781](https://github.com/LloydCoder/AURONTRA/actions/runs/38120377781) passed 488 tests, 1 skipped, 84.85% coverage.
- Follow-up PR validation: [CI run 38120645677](https://github.com/LloydCoder/AURONTRA/actions/runs/38120645677) passed 488 tests, 1 skipped, 84.85% coverage; SQLite migration, compile, PostgreSQL RLS and backup/restore passed.
- Follow-up secret/archive scan: [run 38120645640](https://github.com/LloydCoder/AURONTRA/actions/runs/38120645640) passed.
- Post-merge main CI: [run 38120944398](https://github.com/LloydCoder/AURONTRA/actions/runs/38120944398) passed 488 tests, 1 skipped, 84.85% coverage; [post-merge secret/archive scan 38120944414](https://github.com/LloydCoder/AURONTRA/actions/runs/38120944414) passed.
- Deployment job was skipped; no live Platform action, endpoint, or production database was exercised.

## Exit criteria

1. Unit tests cover strict validation, thresholds, freshness, allowlists, deterministic plan IDs, untrusted fields, approval requirements, and no-execution semantics.
2. Existing playbook and full backend tests remain green.
3. Public automation remains disabled and the Platform adapter and remediation submission remain disabled by default.
4. Submission requires exact Platform tool registrations and an independently implemented tenant-scoped verifier; the current verifier is an injected protocol contract tested with fakes, not a production integration.
5. Phase-specific forensic audit documents exactly what is implemented and what still requires external registration/deployment.
