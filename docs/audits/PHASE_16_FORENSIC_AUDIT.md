# Phase 16 Forensic Audit — Platform-Governed Threat Containment

**Phase:** 16 of 24
**Implementation commit:** `cdafe5f3eb840418f90437c1e0201bf0fe2746c9`
**Decision:** Passed repository/CI gates; production containment remains disabled.

## Executive result

Phase 16 adds a durable tenant-scoped containment-attempt ledger and a fail-closed state machine. It binds a finding to a trusted endpoint-agent telemetry record, submits only a code-owned action through the Tinlance Agent Platform SDK, and marks containment verified only after independent, fresh, identity-matched evidence confirms isolation. The default verifier is deliberately absent and both feature flags remain false.

- [CI run 38118632295](https://github.com/LloydCoder/AURONTRA/actions/runs/38118632295): **465 passed, 1 skipped, 85.19% coverage**.
- [Secret/history/archive scan 38118632275](https://github.com/LloydCoder/AURONTRA/actions/runs/38118632275): passed.
- Clean SQLite Alembic upgrade and Python compilation: passed.
- PostgreSQL migration, non-owner/non-BYPASSRLS RLS tests, and backup/restore: passed.
- Production deployment and live enforcement: not performed.

## Scope inspected

- `backend/core/threat_containment.py`
- `backend/api/routes/threats.py`
- `backend/models/threat_finding.py`
- `backend/models/threat_containment_attempt.py`
- `backend/models/telemetry_record.py`
- `backend/alembic/versions/0010_threat_containment.py`
- `backend/core/config.py`, `.env.example`, `backend/models/__init__.py`
- `backend/tests/integration/test_threat_containment.py`
- `backend/tests/integration/test_threats_api.py`
- `backend/tests/integration/test_tenant_resource_isolation.py`
- `backend/tests/integration/test_tenant_rls.py`
- `.github/workflows/ci.yml`, `.github/workflows/security.yml`
- README, architecture, roadmap, Phase 15/16 docs and threat model.

## Findings and dispositions

### F16-01 — Caller-controlled signals must not authorize isolation

**Risk:** A user could submit a high heuristic score and cause an enrolled device to be isolated.
**Disposition:** Mitigated. The public analysis route creates only `network_signal` findings and cannot set a trusted source or telemetry-record ID. Containment requires a finding sourced from `endpoint_agent` linked to same-tenant telemetry with good quality, fresh observation, and unexpired retention. The public request alone cannot satisfy this gate.

### F16-02 — Target ownership and endpoint freshness

**Risk:** A finding could refer to another tenant's device, an inactive/revoked device, or stale endpoint state.
**Disposition:** Fixed in service and tested. Composite foreign keys bind tenant/device and tenant/finding/telemetry. The service checks active enrollment, revocation state, device last-seen freshness, telemetry source, telemetry quality, freshness and retention.

### F16-03 — Local execution bypassing the Agent Platform

**Risk:** Aurontra might execute local commands or treat an internal decision as execution authority.
**Disposition:** Fixed by architecture. The service calls only `PlatformGovernedActionExecutor` with the code-owned critical-risk isolation action. No local shell, firewall, endpoint or network-control call exists in the service. The Platform remains the authority boundary.

### F16-04 — Lost responses and duplicate containment actions

**Risk:** A timeout after a successful Platform submission could lead to duplicate isolation attempts or false success.
**Disposition:** Mitigated. The attempt is persisted before submission, the action ID is deterministic per tenant/finding, idempotency is enforced in the database, and ambiguous outcomes use `unknown_outcome` with the same action identity. A completed Platform execution is still not treated as proof of the business postcondition.

### F16-05 — False containment claims

**Risk:** A tool's success response or an upstream event might be treated as proof the endpoint is isolated.
**Disposition:** Fixed at the service state machine. Containment requires completed/succeeded Platform state, execution ID, Platform evidence and audit IDs, plus independent evidence matching tenant/device/finding/execution, a supported independent source, freshness, evidence IDs, and active isolation. Failure or mismatch yields `verification_failed`.

### F16-06 — Transaction-local PostgreSQL RLS context lost on commit

**Risk:** The service must commit its attempt before the external action; PostgreSQL `set_config(..., true)` is transaction-local and is cleared on commit.
**Disposition:** Fixed. A commit helper restores tenant context for subsequent queries. PostgreSQL RLS and backup/restore tests passed with the new table.

### F16-07 — Remote approval policy cannot be inferred from local code

**Risk:** A local action definition cannot prove that the remote Platform has registered the tool or requires approval for a critical-risk operation.
**Disposition:** Explicitly left as a release gate. The action is critical-risk, reversible, sandbox-required and evidence-required; Platform registration and approval policy must be independently verified by the Platform operator. Feature flags remain false, and the default verifier dependency is absent, preventing accidental execution.

## Verification matrix

| Gate | Result |
|---|---|
| Clean SQLite migration to head 0010 | Pass |
| Python compilation | Pass |
| Backend test suite | 465 passed, 1 skipped |
| Coverage | 85.19% |
| PostgreSQL migration | Pass |
| Non-owner/non-BYPASSRLS RLS for attempts and findings | Pass |
| Backup/restore table and RLS verification | Pass |
| Secret/history/nested-archive scan | Pass |
| Concrete production verifier | Not configured |
| Remote Platform tool and approval policy | Not independently verified |
| Production containment / endpoint exercise | Not run |
| Feature flags | Disabled by default |

## Residual risks

1. No concrete `ThreatContainmentVerifier` is wired into the default FastAPI dependency; this is intentional and blocks all actual submissions.
2. The Platform action definition is code-owned but must be registered and policy-gated in the authoritative Platform environment.
3. The trusted telemetry-to-finding pipeline is not yet wired. Phase 17 must produce findings linked to verified endpoint-agent telemetry and supply the independent verifier.
4. Verification evidence is currently represented by structured IDs and metadata; signature verification and source-key rotation are not implemented.
5. No controlled endpoint isolation/unisolation, disaster recovery, or production latency/failure exercise has been run.
6. `THREAT_CONTAINMENT_ENABLED`, `AGENT_PLATFORM_ENABLED`, and the business data plane remain disabled in production by default.

## Research basis

- [Tinlance Agent Developer](https://github.com/LloydCoder/tinlance-agent-developer)
- [OWASP ASVS](https://owasp.org/projects/asvs)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [MITRE ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/)

## Final determination

**Phase 16 is accepted at code/CI level, not production-containment level.** Do not enable the feature flags until Phase 17 supplies the trusted finding pipeline and concrete verifier, and a Platform operator validates the exact registered tool and approval policy.
