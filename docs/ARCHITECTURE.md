# Aurontra Architecture and Tinlance Agent System Boundary

## Product position

Aurontra is a Tinlance product for IT service operations, infrastructure resilience, risk assessment, governed remediation workflows, and operational evidence. It is a **consumer of the Tinlance Agent System**, not a fifth authority component inside that system.

## Canonical four-repository system

The reviewed Tinlance Agent System baseline is **tsic-19-agent-system-2026-10-08**. Its ecosystem lock records these reviewed commits; these are immutable reviewed baselines, not live branch pointers:

| Repository | Reviewed commit | Responsibility |
|---|---|---|
| [Tinlance Agent Developer (TADL)](https://github.com/LloydCoder/tinlance-agent-developer) | `4fac75ba9f14d438d045b877685b2695b4da2c5b` | Developer intent, agent artifact validation, and developer-plane conformance; never grants execution authority |
| [Tinlance Agent OS](https://github.com/LloydCoder/tinlance-agent-os) | `8da4aceca56ff58792b81545f3992c5e4493bda4` | Workspace, session, task, workflow, lifecycle and presentation |
| [Tinlance Agent Platform SDK](https://github.com/LloydCoder/tinlance-agent-platform-sdk) | `615eef529831fdfbe37e050e45d9a1a8c4472291` | Typed client for the Platform contract; no duplicated authority kernel |
| [Tinlance Agent Platform](https://github.com/LloydCoder/tinlance-agent-platform) | `4f524c51f24ace3fa96b5f2fbd716d0270c16aae` | Sole authority for identity, tenant binding, authorization, policy, approvals, budgets, sandbox/tool authority, secrets, execution, and authoritative evidence |

**Canonical integration authority:** [Tinlance System Integration (TSIC)](https://github.com/LloydCoder/tinlance-system-integration), reviewed adapter commit `bdb5b7f9f2295562ad8681c591a8a927500b4d8c`. Aurontra must consume the published contracts and must not redefine TSIC certification semantics.

## Required execution path

1. Aurontra collects an authorized operational signal and creates a domain-level intent with provenance.
2. Aurontra submits a typed request through the official Platform SDK, using the reviewed SDK revision and Platform API **1.1** contract.
3. The request crosses `POST /v1/agent-platform` with a bearer credential, `X-Tinlance-API-Version: 1.1`, `X-Request-ID`, and an idempotency key for consequential operations; W3C `traceparent` is propagated where available.
4. The Platform authenticates the principal, binds tenant and subject, and evaluates capability, policy, risk, required approval, budget, sandbox, secret scope, and execution context.
5. The Platform returns authoritative run state and evidence references. Aurontra may present these records but cannot mint or rewrite them.
6. Aurontra verifies business postconditions separately. Platform execution acceptance is not itself proof that the business outcome succeeded.

## Non-negotiable boundaries

- Never use local `subprocess`, `systemctl`, Certbot, process reprioritization, or API-host filesystem cleanup as a substitute for an authenticated endpoint agent and Platform-governed execution.
- Never treat TADL artifacts, Agent OS state, SDK requests, model output, retrieved content, memory, tool output, or external responses as authority.
- Never duplicate Platform identity, authorization, policy, approval, secrets, sandbox, budget, execution, or audit authority inside Aurontra.
- Never claim a threat was blocked without enforcement acknowledgement and post-action verification.
- Never treat a run being accepted as proof that the IT outcome was achieved.
- Pin the SDK and other cross-repository consumers to reviewed full commit SHAs; do not depend on mutable branch heads in release builds.

## Current implementation status

The current Aurontra repository has not yet completed the SDK integration. The public automation execution and threat containment routes are intentionally disabled until the governed execution path and verification contracts are implemented. This document defines the target boundary; it does not claim integration is already live.

## Conformance and release

The Tinlance Agent Developer conformance suite is a release gate for the four-repository system, and TSIC is the canonical ecosystem certification authority. Aurontra should add product-specific contract tests against the reviewed SDK/Platform wire contract and must keep those tests green alongside its own CI/security workflows. Passing repository conformance does not prove production database, secrets, sandbox, TLS, telemetry, backups, or incident response are deployed.


## Authentication rollout gate

Aurontra's production default requires a configured JWT verifier and keeps the business data plane closed. Ticket and device routes now use durable tenant-scoped repositories, require an active organization, and have cross-tenant regression tests; PostgreSQL RLS covers tenant-owned tables and is exercised with a non-owner role. Several other modules (including threat history, SLA/reporting, knowledge-base and billing state) still have legacy in-memory or caller-supplied behavior. The data plane must remain disabled until those subsystems are migrated or explicitly disabled, resource-level authorization is complete across every route, and end-to-end isolation is independently verified. CI's explicit test-mode override exists only to keep tests deterministic.


## Resource consumption

The application rejects oversized declared request bodies before routing. The production reverse proxy/API gateway must also enforce maximum streamed body size, per-tenant rate limits, concurrency budgets, and upstream timeouts; these controls are not yet certified as deployed.


## Database migration status

The repository has Alembic migrations for the base schema and tenant foreign keys/RLS. Ticket and device route persistence is exercised in SQLite tests with foreign-key enforcement enabled; PostgreSQL CI validates tenant isolation for organizations, devices and tickets using a non-owner/non-bypass role, then performs a custom-format dump/restore smoke test that verifies restored tenant data and RLS policies. These are CI proofs, not evidence of a production database migration or managed-backup configuration. The migrations are intentionally non-destructive for pre-existing tables; before production adoption, back up the actual database, compare schema to models, and run a reviewed forward migration. Production startup must not use `create_all` as a substitute for migrations.


## Durable jobs and event delivery (Phase 06)

Aurontra now has tenant-scoped `durable_jobs` and `outbox_events` tables, introduced by Alembic revision `0003_durable_jobs_and_outbox`. Both tables have tenant foreign keys, idempotency uniqueness, queue-oriented indexes, and PostgreSQL forced row-level security. Revision `0004_device_lifecycle` extends the expected production migration head.

- Jobs are claimed in bounded batches with row locks and PostgreSQL `SKIP LOCKED`; leases expire and can be recovered. Attempt counts, bounded exponential backoff, cooperative cancellation, lease-owner checks and terminal dead-letter states are persisted.
- A transactional outbox avoids a dual-write gap: ticket creation writes the ticket and a `ticket.created` event in the same database transaction. Event payloads contain the ticket identifier and source only; consumers must refetch data through tenant-scoped access.
- Worker execution is explicit allowlist dispatch. An unregistered job type is dead-lettered; handlers receive an idempotency key and bounded JSON payloads/results. No handler is implicitly authorized to perform privileged infrastructure actions.
- Outbox publication is at-least-once. A publisher may deliver an event and crash before recording its acknowledgement, so downstream consumers must deduplicate by event/idempotency identifier.
- The code provides reusable worker loops, but no production scheduler, broker, publisher destination, or service deployment is configured. This phase is implementation and CI evidence, not proof of live production processing.
- These workers do not replace the Tinlance Agent Platform. Any consequential remediation must still go through the official Platform SDK and its policy, approval, sandbox, budget, secret, execution and evidence controls.


## Organization and device lifecycle (Phase 07)

Alembic revision `0004_device_lifecycle` adds `enrolled_at`, `revoked_at`, and `agent_version` metadata to devices and an organization/activity index. Legacy devices are not silently declared enrolled: their enrollment timestamp remains NULL pending an explicit authenticated agent handshake, and migration `0004` disables records lacking that proof so old `is_active` flags cannot grant telemetry trust.

- `POST /devices/provision` is an organization-admin operation that creates a tenant-owned, inactive device record. Provisioning is not enrollment and cannot authorize telemetry or execution. Telemetry ingestion also requires `is_active=true` and non-null `enrolled_at`; Phase 08 must be the only supported path that establishes authenticated enrollment.
- `POST /devices/{device_id}/revoke` is organization-admin-only, tenant-scoped, and idempotent. A cross-tenant identifier is indistinguishable from a missing device.
- `POST /organizations/offboard` is organization-admin-only. It transitions the organization to `offboarded`, deactivates its devices, stamps revocation time, and retains records for audit/retention policy rather than cascading deletion.
- `GET /organizations/me` exposes only the authenticated tenant's own lifecycle state. A narrowly scoped lifecycle database dependency permits status inspection and repeated offboarding for an existing inactive organization; normal tenant data dependencies continue to reject non-active organizations.
- The endpoint-agent cryptographic handshake, enrollment proof, key rotation, heartbeat authentication, and telemetry replay defense are Phase 08 requirements. No device is activated merely by provisioning, and these routes do not claim those Phase 08 controls are complete.
