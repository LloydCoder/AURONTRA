# Phase 15 — Threat Detection Evidence Pipeline

**Status:** Complete at code/CI level. This is not a production detection certification.
**Owner:** Tinlance Limited / Aurontra
**Migration:** Alembic revision `0009_threat_findings`
**Boundary:** Threat assessment and evidence only; containment remains disabled.

## Objective

Make threat analysis reproducible, bounded, tenant-scoped, and auditable enough to support a later verified-containment phase without confusing a heuristic decision with confirmed malicious activity or successful enforcement.

## Implementation

### Signal validation

`backend/core/threat_evidence.py` normalizes IP addresses and protocol labels and rejects unknown fields, non-finite numeric values, booleans in numeric fields, out-of-range entropy, unbounded Z-scores, invalid periodicity, and invalid byte counts. Canonical JSON serialization is deterministic and rejects NaN/Infinity before SHA-256 hashing.

### Durable finding evidence

The `threat_findings` table stores tenant, caller event ID, source label, detector version, observation and receipt timestamps, normalized signal, signal digest, assessment, score, threat level, ATT&CK hypothesis, and explicit non-containment state.

- Unique constraint on `(org_id, event_id)` makes repeated requests idempotent within a tenant. Reuse of an event ID with different signal content returns conflict.
- The assessment includes the detector version, signal digest, score semantics, and `mitre_mapping_semantics=heuristic_hypothesis_not_confirmed_behavior`.
- PostgreSQL RLS is enabled and forced. Reads and writes use explicit tenant predicates in addition to the RLS boundary.
- API responses normalize stored timestamps to UTC and never expose `blocked=true` or `containment_verified=true` from analysis.
- `GET /threats/events` returns persisted tenant-scoped findings rather than treating a third-party bridge response as authoritative evidence.
- `POST /threats/block` remains HTTP 503 until Phase 16 supplies a real enforcement adapter and independent postcondition verification.

### Reproducible offline evaluation

`evaluate_labeled_dataset()` accepts a caller-supplied labelled dataset with unique record IDs, boolean ground-truth labels, integer scores in [0,100], and an explicit threshold. It emits a canonical dataset SHA-256, dataset size, detector version, confusion matrix, precision, recall, false-positive rate, false-negative rate, accuracy, and Wilson 95% intervals for observed proportions.

This is a reproducibility and measurement primitive, not a model calibration routine. There is no bundled production-labelled dataset, no independently validated holdout set, and no evidence that synthetic fixtures represent customer traffic. The evaluator must not be used to advertise real-world detection rates until the dataset's provenance, label quality, representativeness, split strategy, and review process are independently documented.

## Verification

- CI: [run 38118019557](https://github.com/LloydCoder/AURONTRA/actions/runs/38118019557) — **451 passed, 1 skipped, 85.49% coverage**; clean SQLite migration, backend compile, PostgreSQL migration, tenant RLS tests and backup/restore smoke test passed.
- Secret/history/archive scan: [run 38118019534](https://github.com/LloydCoder/AURONTRA/actions/runs/38118019534) — passed.
- PostgreSQL RLS test uses a non-owner, non-BYPASSRLS role and checks cross-tenant read/write denial for threat findings.
- Backup/restore smoke test verifies that the threat findings table and its RLS policy survive restoration.
- Deployment was skipped. No production database migration, live traffic, customer-labelled dataset, or enforcement action is claimed.

## Research basis and design decisions

- [OWASP ASVS](https://owasp.org/projects/asvs) provides a testable application-security requirements framework; this phase adds input bounds, tenant controls, and negative tests rather than claiming conformance certification.
- [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) supports integrating verification and risk reduction into the software lifecycle.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) frames measurement as context-dependent, continuously reviewed risk work; the score is explicitly uncalibrated.
- [NIST TEVV-Athlon draft](https://www.nist.gov/artificial-intelligence/ai-research/tevv-athlon-framework-evaluating-ai-systems) emphasizes documented testing, evaluation, verification, and validation; Phase 15 records the dataset digest and metric semantics but does not claim a complete TEVV program.
- [MITRE ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/) and the [ATT&CK data-model documentation](https://mitre-attack.github.io/attack-data-model/docs/principles/attack-detections/) guide the distinction between a technique hypothesis and a confirmed observed behavior. Legacy ATT&CK data sources were deprecated in ATT&CK v18; the current model emphasizes detection strategies and analytics.
- [SLSA v1.2](https://slsa.dev/spec/v1.2/) informs the later supply-chain/provenance release phase; this phase records input identity and detector version but does not claim a SLSA build level.

## Residual gates

1. Collect a legally authorized, representative, labelled dataset with documented ground truth, time-aware train/validation/holdout separation, and independent review.
2. Evaluate per-protocol and per-traffic-class precision/recall/FPR/FNR with confidence intervals, drift monitoring, and threshold governance.
3. Validate ATT&CK mapping against current technique/detection strategy data; labels remain hypotheses until supported by corroborating telemetry.
4. Add production retention, access review, immutable audit anchoring, alerting, and incident-response workflows in their later phases.
5. Keep containment disabled until Phase 16 independently verifies enforcement and postconditions.

## Acceptance decision

**Phase 15 is complete at code/CI level.** It is not evidence that Aurontra has achieved a particular detection accuracy, that a real-world attack was confirmed, or that traffic was blocked. Phase 16 may begin after this design, forensic audit, roadmap, and README reconciliation commit also passes CI and the secret/history/archive scan.
