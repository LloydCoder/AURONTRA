# Phase 21 — Evidence-Backed Reporting and ROI Integrity

**Status:** Implementation candidate; acceptance pending exact-SHA backend, PostgreSQL RLS/restore, dependency, and secret/archive validation.

## Implemented

- Removed caller control over `org_id`, device counts, ticket counts, threat counts, SIEM state, and MFA state from report request bodies.
- Derive tenant identity exclusively from the verified request context and use tenant-scoped database sessions.
- Calculate report inputs from active tenant devices, tenant tickets created/resolved within the reporting window, completed verified containment attempts, and tenant resilience snapshots.
- Treat SIEM as unverified until tenant-bound integration evidence exists; infer MFA only from verified identity-token claims with explicit MFA indicators.
- Mark ROI as illustrative rather than measured savings and disclose hourly-rate and breach-cost assumptions.
- Qualify compliance outputs as observed control-evidence summaries, not legal compliance scores or certifications; downgrade unsupported control claims to partial/unverified.
- Persist reports as tenant-scoped immutable artifacts containing input provenance, reporting window, creator, payload, and SHA-256 digest.
- Add PostgreSQL row-level security and database triggers rejecting report artifact updates/deletes; SQLite migration has equivalent triggers.
- Add tests for caller-supplied metric rejection, tenant provenance, artifact digest persistence, and append-only behavior; extend PostgreSQL RLS and restore checks.

## Acceptance gates

- [ ] Exact-SHA CI, migration, PostgreSQL tenant RLS, backup/restore, dependency audit, and secret/history/archive scans pass.
- [ ] Verify the artifact digest from canonical stored JSON and ensure the report payload and provenance remain consistent.
- [ ] Test concurrent report generation and tenant isolation under PostgreSQL.
- [ ] Review legal/compliance control mappings with qualified domain counsel before customer-facing use.
- [ ] Confirm all missing/unverified evidence is represented as partial/unknown rather than a positive control assertion.

## Non-claims

Reports are not NIS2/DORA certification, independent assurance, legal advice, or a guarantee of financial savings or avoided breaches. No tenant-specific SIEM configuration or MFA enrollment state is inferred without explicit verified evidence. Hash digests and database triggers provide integrity controls, not proof of external immutable storage.