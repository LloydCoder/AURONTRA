# Phase 23 — Security Assurance and Release Integrity

**Status:** Implementation candidate; acceptance requires CodeQL results, exact-SHA CI, dependency/secret scans, and a successful main-branch SBOM/provenance run.

## Implemented

- Added pinned CodeQL SAST workflows for Python and JavaScript/TypeScript using security-extended and security-and-quality queries.
- Added workflow syntax linting with pinned actionlint.
- Added a main-branch release-evidence workflow that creates a deterministic source archive, SPDX JSON SBOM, SHA-256 checksum manifest, and build-provenance attestations for the source archive and SBOM.
- Added frontend dependency auditing and pinned the npm package-manager and Node engine versions.
- Added lightweight concurrent-load tests for the metrics registry and negative role-policy tests.
- Reused the existing exact-SHA backend CI, PostgreSQL RLS/restore, pip-audit, and Gitleaks current-tree/history/archive gates.

## Acceptance gates

- [ ] CodeQL completes on the exact candidate SHA; all high/critical findings are triaged and resolved or explicitly risk-accepted.
- [ ] actionlint validates every workflow, including release-integrity and provenance workflows.
- [ ] Frontend `npm audit --audit-level=high` passes and the production build/typecheck/lint remain green.
- [ ] Commit a reviewed frontend lockfile and switch the frontend build to `npm ci`; direct dependency pins alone do not lock the transitive dependency graph.
- [ ] Main-branch SBOM and provenance workflow succeeds; verify both attestations and checksums independently before release.
- [ ] Dependency, secret/history/archive, PostgreSQL RLS/restore, and fault/load tests pass on the exact final candidate.
- [ ] Review workflow permissions, action pins, fork PR behavior, artifact retention, and release access controls.

## Non-claims

Adding a workflow does not itself prove a clean SAST result or successful provenance. SBOM/provenance runs are triggered on main, not untrusted pull requests. No container image is built because this repository currently has no Dockerfile. The frontend remains less reproducible until a reviewed package-lock file is committed and `npm ci` is used.