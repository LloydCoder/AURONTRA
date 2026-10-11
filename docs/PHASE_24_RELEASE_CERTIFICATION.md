# Phase 24 — Production Release Certification Gate

**Status:** Gate implementation candidate; production release is explicitly **not ready** until all external acceptance evidence is reviewed and verified.

## Implemented

- Added a versioned release acceptance manifest with explicit blocked gates for Platform integration, authenticated console, billing, runtime API-key authentication, compliance review, production SLO/DR, frontend dependency reproducibility, and production deployment/rollback.
- Added `scripts/release_readiness.py` to validate manifest shape, gate uniqueness, evidence paths confined to `release/evidence/`, SHA-256 digests, fail-closed feature defaults, and configured-vs-checked-in migration revision consistency.
- Added a CI-safe report mode that prints blockers without pretending production is ready, and a strict mode that exits non-zero unless every gate is accepted with digest-verified evidence.
- Added a manual production certification workflow with an explicit strict go/no-go input.
- Added tests for accepted evidence, digest tampering, path traversal, current external blockers, and schema consistency.

## Release procedure

1. Keep `release_status` as `not_ready` while any required gate is blocked.
2. For each gate, place reviewed evidence under `release/evidence/`, calculate its SHA-256, and update the manifest only after the accountable owner approves it.
3. Do not mark a gate accepted without evidence path and matching digest. The validator rejects paths outside the evidence directory.
4. Run the standard CI/security workflows on the exact release candidate SHA.
5. Verify source archive checksum, SPDX SBOM, and build-provenance attestations independently.
6. Run the production release workflow with `strict=true` only after all required gates have been accepted and the evidence is present.
7. Require explicit go/no-go approval, rollback readiness, tenant-scoped smoke tests, and measured recovery evidence before enabling production data-plane flags.

## Current blockers

- Phase 17 live Platform/verifier/worker acceptance.
- Phase 18 authenticated console end-to-end acceptance.
- Phase 19 provider sandbox checkout, subscription reconciliation, and server-side entitlements.
- Phase 20 API-key runtime authentication and negative JWT role-policy tests.
- Phase 21 qualified legal/control-owner review of NIS2/DORA mappings.
- Phase 22 durable telemetry, alert delivery, and measured production RTO/RPO.
- Phase 23 committed frontend lockfile and `npm ci` reproducibility.
- Phase 24 production deployment, rollback, and go/no-go evidence.

## Non-claims

This gate does not itself deploy the service, enable disabled features, verify an external Platform, or certify legal compliance. CI success and a green release-readiness report mode are not production acceptance. Strict mode must remain red while required evidence is missing.