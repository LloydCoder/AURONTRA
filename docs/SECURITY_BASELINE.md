# Aurontra Security Baseline

**Status:** Hardening in progress. This is not a production certification.

## Verified baseline findings

The 2026-10-09 repository audit and workflow logs identified:
- Backend tests passed in workflow run 37914230634, but deployment failed because the SSH action reported that no private SSH key or password was available. The deployment credential blocker was not a code-test failure.
- Public automation and threat routes lacked visible authentication and tenant authorization.
- Automation dispatched local playbooks while accepting a caller-provided `device_id`; that did not establish remote execution.
- Threat response returned a block-oriented result without enforcement acknowledgement.
- Billing webhook verification accepted requests when the signing secret was missing.
- Business data and histories were held in process memory.
- The tracked frontend did not establish a reproducible, backend-connected Next.js application.
- The legacy `resilientai-DEPLOY-READY.tar.gz` deployment archive has been removed from the current branch because it was not suitable to trust as a release artifact. Its historical Git object remains in repository history and is covered by the archive-aware Gitleaks history scan. Gitleaks 8.30.1, pinned and checksum-verified, reported no matching secrets on commit `acfb67a4aaf8559be864bb8235613c30162d40cc`; that is not a guarantee that every sensitive artifact or secret type is detectable. Deployment should be built from reviewed source, not that archived bundle.

## Immediate safety controls now in code

1. Public playbook execution returns 503; individual playbooks are recommendation-only and no longer run local cleanup, service commands, Certbot, or process reprioritization.
2. Public threat containment returns 503 until enforcement acknowledgement and post-action verification exist.
3. Unverified upstream containment claims are normalized as unverified; SIEM export does not trust caller-supplied `blocked`, `status`, or `action_taken` values.
4. Lemon Squeezy webhook signature verification fails closed when secret/signature is missing and verifies HMAC-SHA256 over the exact raw body.
5. Public organization registration and checkout return 503 pending durable tenant lifecycle and provider-backed billing.
6. ROI output labels caller-supplied calculations as illustrative models, not measured savings.
7. User-facing business APIs require configured JWT/JWKS verification, a tenant claim, and a recognized organization role; only `/health/live` is public. The Lemon Squeezy webhook uses raw-body HMAC as its authentication mechanism, but remains disabled behind the data-plane gate until durable event idempotency is implemented.
8. The production business data plane remains closed until durable tenant isolation is implemented. `DATA_PLANE_ENABLED=true` alone cannot bypass the code-level gate.
9. `ENVIRONMENT=production` rejects `AUTH_MODE=disabled` and `TEST_MODE=true`.
10. Declared request bodies larger than `MAX_REQUEST_BODY_BYTES` (1 MiB default) are rejected. Production ingress must also cap chunked bodies and apply rate/concurrency limits.
11. Production startup no longer calls SQLAlchemy `create_all`; when the data plane is requested, the database must have exactly the configured Alembic revision.

## CI archive-handling incident and remediation

During development of the archive inventory workflow, an unsafe shell command substitution attempted to execute some file paths discovered inside the legacy archive on an ephemeral GitHub-hosted runner. The workflow revision was replaced, the archive was removed from the current branch, and the current security workflow does not extract or execute archives; it rejects tracked `.tar.gz` files and scans the current tree and reachable history as data. The affected job had `contents: read` permissions and no application/deployment secrets were configured; no production deployment was run. The job was isolated to a GitHub-hosted runner. Because an independent outbound-network audit of that runner was not available, this is recorded as a workflow security incident rather than asserting that no external communication occurred.

## Release gates

Production release remains blocked until all of the following have evidence:
- Resource-level RBAC and negative cross-tenant tests pass.
- Every business route uses durable tenant-scoped repositories and transactional writes.
- API-key issuance, hashing, rotation, revocation, expiry, and scope enforcement are complete.
- Webhook event IDs are durably deduplicated and provider state is reconciled.
- Endpoint actions run only through the Tinlance Agent Platform-governed path and produce verified postconditions.
- Frontend build, lint, type-check, and authenticated end-to-end tests run in CI.
- Dependency audit, SAST, DAST, integration/load/fault tests and release provenance are automated.
- Deployment is actually performed and independently verified; a skipped deployment is not a production pass.
- Existing database schema is reviewed against the bootstrap migration before migration adoption.
- Backup/restore, rollback, SLOs, alerting, incident response and recovery drills have evidence.

## Known limitations

- The Alembic bootstrap creates missing tables but does not alter pre-existing tables. Migration 0002 adds tenant foreign keys and PostgreSQL RLS policies. Both migrations are intentionally irreversible; use a reviewed backup-and-restore process for rollback.
- Tenant/API-key/audit/webhook models and tenant foreign keys are schema foundations; PostgreSQL RLS is now covered by a dedicated CI job, but route repositories still need tenant-scoped queries and the data plane remains closed.
- JWT middleware and role policy are perimeter controls, not object-level authorization or a completed cross-tenant isolation implementation.
- Content-Length checking does not by itself stop oversized chunked requests.
- The old deployment archive is removed from the working tree. Its historical blob remains in Git history; the workflow scans history for matching secrets but does not execute historical artifacts.
- This document is not a substitute for independent penetration testing, production environment verification, or external compliance assessment.
