# Phase 16 — Platform-Governed Threat Containment State Machine

**Status:** Complete at repository/CI level; production containment remains disabled.
**Migration:** Alembic revision `0010_threat_containment`
**Boundary:** No local shell, firewall, endpoint, or network side effect is performed by Aurontra.

## Objective

Implement the safe orchestration boundary for threat containment: bind a finding to a trusted tenant-owned endpoint and fresh endpoint-agent telemetry; create a durable idempotent attempt before external side effects; submit only a code-owned action through the Tinlance Agent Platform SDK; and set the finding to contained only after independent, fresh, target-bound postcondition evidence.

## Implementation

### Trusted source and target binding

- `ThreatFinding` now carries optional `device_id` and `telemetry_record_id` foreign keys scoped to the same tenant.
- The public `POST /threats/analyse` endpoint only creates `network_signal` findings and does not accept a telemetry-record ID or a source label. A caller-submitted score cannot authorize endpoint isolation, even if it names a real device.
- The containment service requires a finding sourced from `endpoint_agent`, a matching tenant/device telemetry record with `score_status=ok`, unexpired retention, fresh observation time, an active/enrolled/non-revoked device, and fresh device telemetry.
- Only high/critical findings scoring at least 70 and carrying an explicit `containment_recommended=true` assessment are eligible.

### Durable attempt and idempotency

`threat_containment_attempts` records the finding, device, deterministic action ID, idempotency key, Platform run/execution IDs, Platform evidence/audit references, independent verification references, version, status, reason code and timestamps.

- Unique constraints allow only one containment attempt per tenant/finding and one use of an idempotency key per tenant.
- The attempt is committed before crossing the external side-effect boundary.
- Ambiguous submission outcomes are recorded as `unknown_outcome`; retries reuse the same deterministic action ID and Platform request key rather than creating a second action.
- PostgreSQL forced RLS protects the attempt ledger; tenant context is restored after transaction commits because `set_config(..., true)` is transaction-local.

### Platform-governed action

The only registered action definition in this phase is `threat.containment.isolate_endpoint`. It is code-owned, critical risk, reversible, confidential, single-target, sandbox-required, and evidence-required. The executor uses the existing `PlatformGovernedActionExecutor` and official SDK; it does not run local commands or bypass Platform identity, authorization, policy, approval, sandbox, audit, or execution controls.

A Platform state alone is not proof of isolation. Approval-pending or non-terminal states remain pending and never trigger a local claim of containment.

### Independent postcondition verifier contract

`ThreatContainmentVerifier` is a required dependency, not an optional best-effort enhancement. The verification record must match the trusted tenant, device, finding and Platform execution; identify a supported independent source; carry non-empty evidence references; be fresh; and affirm that isolation is currently active. Platform execution evidence and audit IDs must also be present.

Only then does the service set attempt status to `contained`, set `ThreatFinding.containment_verified=true`, and update the assessment's containment fields. Missing, stale, mismatched, malformed or negative evidence results in `verification_failed`, with no verified-containment claim.

### Fail-closed deployment

- `THREAT_CONTAINMENT_ENABLED=false` by default.
- `AGENT_PLATFORM_ENABLED=false` by default.
- The default FastAPI dependency deliberately provides no verifier, so even if a flag is accidentally enabled, the service rejects the operation before Platform submission.
- The public containment route requires a security-administrator/organization-administrator role and trusted server-side tenant/subject plus configured Platform agent/task UUIDs.
- The legacy `POST /threats/block` endpoint remains HTTP 503.

## Verification

- [CI run 38118632295](https://github.com/LloydCoder/AURONTRA/actions/runs/38118632295): **465 passed, 1 skipped, 85.19% coverage**. Clean SQLite migration, compile, PostgreSQL migration, non-owner/non-BYPASSRLS isolation, and backup/restore checks passed.
- [Secret/history/archive scan 38118632275](https://github.com/LloydCoder/AURONTRA/actions/runs/38118632275): passed.
- Unit/integration tests cover disabled-by-default behavior, missing verifier, untrusted caller-submitted signal rejection, stale telemetry, Platform approval-pending state, wrong target, stale/negative verification, success only with valid independent evidence, and idempotent replay.
- Production deployment was skipped. No real Platform tool registration, customer endpoint isolation, concrete verifier, or production enforcement is claimed.

## Residual gates

1. Phase 17 must implement a trusted telemetry-to-finding correlation path and concrete independent endpoint/network control-plane verifier; the default verifier is intentionally absent.
2. A Tinlance Agent Platform operator must register the exact action/tool and enforce approval policy for this critical-risk capability. Local code cannot certify remote policy configuration.
3. Production must supply tenant-scoped credentials, canonical HTTPS Platform URL, approved agent/task identity, and the exact registered action contract.
4. Add signed verifier evidence and source identity, replay protection, and independent policy attestation before enabling the feature flag.
5. Run a controlled end-to-end exercise against a disposable endpoint and verify isolation, recovery/unisolation, audit evidence, timeouts, and failure/retry behavior.
6. Keep both feature flags disabled until all above gates are evidenced and the production data plane itself is approved.

## Research basis

- [Tinlance Agent System](https://github.com/LloydCoder/tinlance-agent-developer): Aurontra is a consumer of the Agent System, not an alternate authority plane. The Agent Platform remains authoritative for identity, policy, approvals, tools and execution.
- [OWASP ASVS](https://owasp.org/projects/asvs) and [OWASP API Security Top 10](https://owasp.org/API-Security/): support default-deny access, tenant-bound resource authorization, input validation and abuse-resistant APIs.
- [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final): supports gated, tested security changes and explicit verification evidence.
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final): incident response must connect detection, response, recovery and lessons learned; an action request alone is not a response outcome.
- [MITRE ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/): technique mapping remains a hypothesis until supported by corroborating telemetry.

## Acceptance decision

**Phase 16 is complete at repository/CI level only.** The durable state machine, Platform-governed action contract, trusted-source gate and verifier interface are implemented and tested. Real containment is still disabled because no concrete verifier or remote Platform action/policy registration has been wired and validated.
