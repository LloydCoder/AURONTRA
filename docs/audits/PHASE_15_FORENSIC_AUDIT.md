# Phase 15 Forensic Audit — Threat Detection Evidence Pipeline

**Phase:** 15 of 24
**Product:** Aurontra (formerly ResilientAI)
**Owner:** Tinlance Limited
**Implementation commit under review:** `3613996363ba2af4ad3e6681c7c638b0b1a9098f`
**Status:** Passed at code/CI level; production detection efficacy and production release are not certified.

## Executive result

The phase replaces ephemeral threat-event handling with durable tenant-scoped findings, validates untrusted signal inputs, creates deterministic content digests, supports repeatable evaluation on explicitly labelled datasets, and preserves the distinction between assessment and containment.

- [CI run 38118019557](https://github.com/LloydCoder/AURONTRA/actions/runs/38118019557): **451 passed, 1 skipped, 85.49% coverage**.
- [Secret/history/archive scan 38118019534](https://github.com/LloydCoder/AURONTRA/actions/runs/38118019534): passed.
- Clean SQLite migration and Python compilation: passed.
- PostgreSQL migration, non-owner/non-BYPASSRLS tenant isolation, and backup/restore policy verification: passed.
- Production deployment: skipped; no live production traffic or enforcement is claimed.

## Scope inspected

- `backend/core/threat_evidence.py`
- `backend/models/threat_finding.py`
- `backend/alembic/versions/0009_threat_findings.py`
- `backend/api/routes/threats.py`
- `backend/models/__init__.py`
- `backend/core/config.py`
- `.env.example`
- `backend/tests/unit/test_threat_evidence.py`
- `backend/tests/integration/test_threats_api.py`
- `backend/tests/integration/test_tenant_resource_isolation.py`
- `backend/tests/integration/test_tenant_rls.py`
- `.github/workflows/ci.yml`
- `.github/workflows/security.yml`
- `.gitleaks.toml`
- `README.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, Phase 15 design and this audit.

## Findings and dispositions

### F15-01 — Unbounded and malformed signal input

**Finding:** Raw request fields could reach scoring logic with malformed, non-finite, out-of-range, or unexpected values.
**Disposition:** Fixed at the service boundary. Signal fields are allowlisted; IP/protocol values are normalized; numeric fields reject booleans, NaN/Infinity and invalid bounds. Unit tests cover invalid values.

### F15-02 — Ephemeral threat events and weak tenant evidence

**Finding:** Process-local event storage is lost on restart and is unsuitable as a durable multi-tenant record.
**Disposition:** Fixed for threat assessment records. Findings are persisted in `threat_findings`, queries are explicitly tenant-scoped, `(org_id, event_id)` is unique, and PostgreSQL forced RLS is covered by a non-owner role test.

### F15-03 — Duplicate and conflicting event submissions

**Finding:** Retries could create duplicate findings, while reusing an event ID with altered content could silently change the meaning of evidence.
**Disposition:** Fixed for sequential replay and tested. A matching event ID and signal digest returns the existing finding; a different digest returns HTTP 409. The unique database constraint protects concurrent duplicate inserts; a racing insert fails closed with conflict.

### F15-04 — Evidence identity and timestamps

**Finding:** A finding needs stable input identity, detector identity, and clear time semantics to be reproducible and inspectable.
**Disposition:** Fixed at the application/schema level. Canonical JSON is hashed with SHA-256; detector version and observed/received timestamps are stored; API timestamps are normalized to UTC. A digest identifies the input bytes/structure, not the correctness of the signal.

### F15-05 — Score and ATT&CK overclaim risk

**Finding:** A heuristic score or protocol-to-technique mapping could be mistaken for a calibrated probability, confirmed attacker behavior, or containment proof.
**Disposition:** Mitigated. Assessment semantics explicitly state that the score is an uncalibrated deterministic heuristic and ATT&CK mapping is a hypothesis. Responses set `blocked=false` and `containment_verified=false`; the containment route remains disabled.

### F15-06 — Missing reproducible evaluation methodology

**Finding:** Detection performance cannot be supported by anecdotal score examples or unlabelled traffic.
**Disposition:** Partially addressed with a reusable evaluator. It validates unique example IDs, boolean ground-truth labels, score bounds and threshold; computes a confusion matrix, observed metrics, Wilson intervals and a canonical dataset digest. No real-world metric is claimed because no representative labelled dataset is supplied or independently reviewed.

### F15-07 — Upstream bridge claims treated as authoritative

**Finding:** An upstream event could claim a block without Aurontra possessing independently verifiable enforcement evidence.
**Disposition:** Fixed for the event-list API. The endpoint returns Aurontra's durable tenant-scoped findings; it no longer relies on upstream event claims as the authoritative event store. SIEM export continues to sanitize caller-supplied containment claims.

### F15-08 — Migration, RLS and recovery

**Finding:** A new evidence table must be included in schema migration, forced tenant RLS, backup/restore verification, and configured production schema revision.
**Disposition:** Fixed at CI level. Alembic revision `0009_threat_findings` creates the table, indexes, constraints and PostgreSQL RLS policy. CI migrates a clean SQLite database and PostgreSQL; RLS and backup/restore tests include the new table and policy. Production migration remains unperformed.

### F15-09 — Secret-scanner false positive

**Finding:** Gitleaks' generic API-key rule matched the literal historical enum token `api_signal` in test/migration code.
**Disposition:** Renamed the active source label to `network_signal` and added a narrowly scoped allowlist for the historical false positive, restricted to the generic-api-key rule, exact token, and four affected source paths. Current files, reachable Git history and nested archives scan green. The exception does not disable generic API-key scanning globally.

## Verification matrix

| Gate | Result |
|---|---|
| Clean SQLite Alembic upgrade to head | Pass |
| Python compilation | Pass |
| Backend test suite | 451 passed, 1 skipped |
| Coverage | 85.49% |
| PostgreSQL migration | Pass |
| Non-owner/non-BYPASSRLS tenant isolation | Pass |
| Backup/restore preserves tenant data and RLS | Pass |
| Working-tree/history/nested-archive secret scan | Pass |
| Production deployment | Skipped — not claimed |
| Real labelled detection benchmark | Not run — dataset not supplied |
| Real enforcement and postcondition verification | Not implemented in this phase |

## Residual risks

1. The score remains a deterministic heuristic, not a calibrated probability.
2. Dataset metrics only describe the exact dataset hash and threshold supplied to the evaluator. Dataset quality, selection bias, temporal leakage, and generalization remain external validation obligations.
3. ATT&CK labels are heuristic hypotheses, not confirmation that a technique occurred. MITRE ATT&CK's current detection strategy model should be used for future mapping validation.
4. There is no public evaluation-upload API, signed benchmark manifest, model registry, or trusted ground-truth governance in this phase.
5. Threat finding retention, durable append-only audit anchoring, alerting/SLOs and incident response are later-phase work.
6. Containment remains disabled; no network/firewall/endpoint enforcement is invoked or verified.
7. The data plane and deployment remain gated. Green CI is not production deployment evidence.

## Research basis

- [OWASP ASVS](https://owasp.org/projects/asvs)
- [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST TEVV-Athlon evaluation framework draft](https://www.nist.gov/artificial-intelligence/ai-research/tevv-athlon-framework-evaluating-ai-systems)
- [MITRE ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/)
- [MITRE ATT&CK data-model detection documentation](https://mitre-attack.github.io/attack-data-model/docs/principles/attack-detections/)
- [SLSA v1.2 specification](https://slsa.dev/spec/v1.2/)

## Final determination

**Phase 15 is accepted at repository/CI level only.** The evidence pipeline is implemented and its CI/security gates are green. No claim is made about production detection efficacy, customer deployment, calibrated confidence, confirmed malicious behavior, or successful containment. Phase 16 can begin after documentation reconciliation passes its own CI and security scan.
