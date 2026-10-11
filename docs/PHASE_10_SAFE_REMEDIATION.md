# Phase 10 — Safe Remediation Playbooks

**Status:** Implementation in progress; no public remediation route is enabled.  
**Authority:** Tinlance Agent Platform remains the only execution/policy/approval authority.  
**Research basis:** NIST SP 800-53 Rev. 5 AC-5/AC-6 and CM-3; OWASP Authorization Cheat Sheet and Secure-by-Default guidance. These sources support least privilege, separation of duties, explicit change control, and default-deny behavior. See [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html), and [OWASP Secure by Default](https://devguide.owasp.org/en/04-design/02-web-app-checklist/01-secure-by-default/).

## Scope

Phase 10 creates a deterministic, pure remediation planner for the existing disk pressure, service restart, certificate expiry, and high CPU playbooks. It does not enable execution or connect public routes to Platform tools. Plans can be proposed only from a server-constructed target and tenant-scoped evidence; the public route stays disabled until durable intent/reconciliation, Platform registration, approved tenant credentials, and independent postcondition verification are available.

## Safety contract

- The planner performs no I/O, network probes, filesystem operations, shell/subprocess calls, service restarts, Certbot calls, process inspection, or Platform calls.
- Caller-supplied request JSON is not a trusted target. The application must first verify tenant, active device enrollment, actor, and evidence ownership and then construct `TrustedRemediationTarget`.
- Evidence is freshness-bounded to five minutes with a one-minute future-skew tolerance. Stale, future-dated, malformed, or below-threshold evidence blocks a proposal.
- Inputs are validated with strict type/range checks. Boolean values are not accepted as numeric metrics.
- Playbook and service names are code-owned allowlists. Unknown names fail closed.
- The plan includes only allowlisted parameters; arbitrary request fields, commands, secrets, and free-form shell instructions are not forwarded.
- Disk cleanup is destructive and always requires approval; the only proposal is review of app-owned cleanup candidates.
- Service restart is disruptive, restricted to a small allowlist, and always requires approval.
- Certificate renewal requires a syntactically valid public FQDN and a reference to domain-ownership evidence. The planner does not probe the domain and does not assert that a reference itself proves ownership; the calling service must resolve and validate it from the tenant's durable asset inventory.
- High-CPU handling is read-only diagnostic collection; no process killing, reprioritization, or arbitrary command execution is proposed.
- Every plan explicitly marks execution, Platform submission, enforcement, and business outcome verification as false. Plan IDs are deterministic for identical tenant/device/evidence/action inputs to support later idempotent orchestration; Phase 11 must persist plans and reconcile retries.
- A plan is not an approval or authorization grant. Platform policy, approvals, budgets, sandbox, secrets, tool registration and evidence remain authoritative.

## Exit criteria

1. Unit tests cover strict validation, thresholds, freshness, allowlists, deterministic plan IDs, untrusted fields, approval requirements, and no-execution semantics.
2. Existing playbook and full backend tests remain green.
3. Public automation remains disabled and the Platform adapter remains disabled by default.
4. Phase-specific forensic audit documents exactly what is implemented and what still requires external registration/deployment.
