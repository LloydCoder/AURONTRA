# Phase 23 — Security Assurance and Release Integrity

**Status:** Accepted at repository/CI level for commit `90428644155ce36eeae729f3b8ee578c178bbd19`; frontend lockfile reproducibility and exact-SHA security/CI evidence are recorded in [`release/evidence/phase23-frontend-reproducible-dependencies.json`](../release/evidence/phase23-frontend-reproducible-dependencies.json). This does not accept production deployment or other release gates.

## Implemented

- Added pinned CodeQL SAST workflows for Python and JavaScript/TypeScript using security-extended and security-and-quality queries.
- Added workflow syntax linting with pinned actionlint.
- Added a main-branch release-evidence workflow that creates a deterministic source archive, SPDX JSON SBOM, SHA-256 checksum manifest, and build-provenance attestations for the source archive and SBOM.
- Added frontend dependency auditing and pinned the npm package-manager and Node engine versions.
- Added lightweight concurrent-load tests for the metrics registry and negative role-policy tests.
- Reused the existing exact-SHA backend CI, PostgreSQL RLS/restore, pip-audit, and Gitleaks current-tree/history/archive gates.

## Acceptance gates

- [x] CodeQL completes on the reviewed main candidate SHA; Python and JavaScript/TypeScript analysis jobs succeeded. Findings still require normal triage if surfaced.
- [x] actionlint and GitHub Actions workflow syntax validation succeeded on the reviewed main candidate.
- [x] Frontend dependency audit, lint, TypeScript typecheck, and production build succeeded.
- [x] `frontend/package-lock.json` is committed and the frontend workflow uses `npm ci`.
- [x] Main-branch SPDX SBOM/source provenance workflow completed successfully and uploaded source, SBOM, and checksums. Independent release-operator verification remains part of Phase 24.
- [x] Python dependency audit, secret/history/archive scan, PostgreSQL tenant isolation/RLS/restore, and backend CI passed on the reviewed candidate.
- [ ] Review workflow permissions, action pins, fork PR behavior, artifact retention, and release access controls.

## Non-claims

Adding a workflow does not itself prove a clean SAST result or successful provenance. SBOM/provenance runs are triggered on main, not untrusted pull requests. No container image is built because this repository currently has no Dockerfile. The frontend dependency graph is now lockfile-backed and installed with `npm ci`. This is repository/CI acceptance only; production deployment was skipped and Phases 17, 18, 19, 20, 21, 22, and 24 remain independently gated.