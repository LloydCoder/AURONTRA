# Aurontra Security Baseline

**Status:** Hardening in progress; not a production certification.

## Verified baseline findings

The 2026-10-09 repository audit and workflow logs identified:
- Backend tests passed in workflow run 37914230634, but deployment failed because the SSH action reported: `can't connect without a private SSH key or password`. The `EC2_SSH_KEY` secret was unavailable to the job. This is an infrastructure credential blocker, not a code-test failure.
- Public automation and threat routes lacked visible authentication/tenant authorization in inspected handlers.
- Automation dispatched local playbooks while accepting a caller-provided `device_id`; this did not establish remote execution.
- Threat response returned a block-oriented result without evidence of enforcement acknowledgement.
- Billing webhook verification accepted requests when the webhook secret was missing.
- Domain records and histories were held in process memory.
- The tracked frontend did not establish a reproducible, backend-connected Next.js application.
- The public repository contains a deployment archive. Gitleaks 8.30.1 was pinned by SHA-256 and scanned the working tree, nested archives (depth 3), and reachable Git history successfully on commit acfb67a4aaf8559be864bb8235613c30162d40cc. This is evidence that the configured scanner found no matching secrets, not a guarantee that every sensitive artifact or secret type is detectable. The archive contents still require a functional/deployment-artifact review.

## Immediate safe defaults

1. Public playbook execution is disabled until authenticated endpoint execution, tenant authorization, policy checks, approval handling and postcondition verification are delivered.
2. Public threat containment is disabled until a real enforcement adapter acknowledges the action and the resulting state is independently verified.
3. Billing webhook signature verification fails closed when the secret or signature is missing.
4. Threat analysis is decision support only; it is not proof of blocking, containment or attacker attribution.
5. Caller-supplied compliance and ROI metrics are not sufficient evidence of certification or realized savings.
6. Internal bridge exceptions are not returned verbatim to clients.
7. Public organization registration and checkout are disabled until tenant authorization, durable credential lifecycle, provider-backed checkout, and webhook idempotency are implemented.
8. Public plan descriptions distinguish implemented/experimental capabilities from disabled or unverified features.
7. Public organization registration and checkout are disabled until tenant authorization, durable credential lifecycle, provider-backed checkout, and webhook idempotency are implemented.
8. Public plan descriptions distinguish implemented/experimental capabilities from disabled or unverified features.

## Release gates

A production release must not be approved until all of the following are demonstrated:
- Tenant/resource authorization and negative cross-tenant tests pass.
- No privileged route is reachable without required identity and authorization.
- Endpoint actions execute only on authenticated, authorized targets and produce verifiable outcomes.
- Billing webhooks use raw-body HMAC verification, durable idempotency and provider-state reconciliation.
- Persistent data, migrations, backup and restore have been tested.
- Frontend build, lint, type-check and API integration tests are part of CI.
- Dependency, secret, static-analysis and relevant dynamic security scans are automated.
- Deployment is green and verified independently of unit tests.
- Release archives and Git history have been scanned; findings are triaged and remediated.
- Operational SLOs, incident response, rollback and recovery runbooks exist.

## Limitations

This document is not a substitute for an independent penetration test, external compliance assessment, production environment verification or review of every commit and binary artifact. Phase completion requires implementation and test evidence, not documentation alone.


## Authentication and tenant data-plane gate

- Production defaults are `AUTH_MODE=required` and `DATA_PLANE_ENABLED=false`.
- Configure `JWT_JWKS_URL`, `JWT_ISSUER`, and `JWT_AUDIENCE` for the selected identity provider before business APIs can authenticate.
- Bearer JWTs must pass asymmetric signature, issuer, audience, and expiry validation. A verified token must contain a subject and organization/tenant claim.
- This middleware is a perimeter control, not a substitute for resource-level authorization. Current handlers still contain process-local collections and therefore do not yet have durable tenant isolation.
- The business data plane remains closed by default even when a token is valid. It must not be enabled in production until durable tenant-scoped repositories, migrations, object-level authorization, and cross-tenant isolation tests are complete.
- CI explicitly opts into the legacy in-process test mode. That setting is test-only and must not be copied to production.
- Only `/health/live` is unauthenticated. Readiness, bridge inventory, docs, reports, telemetry, and all business endpoints remain behind the auth/data-plane gate.


- `ENVIRONMENT=production` cannot be combined with `AUTH_MODE=disabled`; the request gate returns a fail-closed 503.
- JWT verification distinguishes invalid credentials (401) from JWKS provider unavailability (503).
- The tenant-isolation implementation gate is a code-level release switch, not an environment variable. Setting `DATA_PLANE_ENABLED=true` alone cannot open the production business API.


## Request resource limits

The API perimeter rejects request bodies whose declared `Content-Length` exceeds `MAX_REQUEST_BODY_BYTES` (default 1 MiB). Production ingress must enforce the same or stricter body-size limit for chunked/streamed requests and apply rate/concurrency limits at the gateway. The application-level content-length check alone is not a complete DoS defense.

- `TEST_MODE=true` is permitted only in non-production environments and is explicitly set by CI to exercise legacy route behavior. Production requests are rejected if test mode is enabled.


## Schema migration gate

- Alembic bootstrap migration: `0001_tenant_security_foundation`.
- CI must run `alembic upgrade head` against a clean disposable database.
- Existing databases are not automatically altered by this bootstrap; back up and reconcile schema drift before applying it.
- The current startup still calls SQLAlchemy `create_all` for compatibility. Removing production schema mutation and enforcing migrations is a remaining release blocker.
