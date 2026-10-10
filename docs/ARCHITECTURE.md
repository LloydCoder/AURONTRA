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

Aurontra's production default requires a configured JWT verifier and keeps the business data plane closed. A valid bearer token alone is insufficient to enable the API: current handlers use in-memory state and cannot yet guarantee organization-level data separation. The data plane must remain disabled until durable tenant-scoped repositories, migrations, object-level authorization, and cross-tenant isolation tests are complete. CI's explicit test-mode override exists only to keep unit tests deterministic.


## Resource consumption

The application rejects oversized declared request bodies before routing. The production reverse proxy/API gateway must also enforce maximum streamed body size, per-tenant rate limits, concurrency budgets, and upstream timeouts; these controls are not yet certified as deployed.


## Database migration status

The repository now has an Alembic environment and a versioned bootstrap migration for the current schema plus tenant/API-key/audit/webhook foundations. The migration is intentionally non-destructive for tables that already exist; it does not claim to reconcile an existing production database automatically. Before production adoption, back up the database, compare actual schema to the migration/model definitions, and run a reviewed forward migration. Production startup must not use `create_all` as a substitute for migrations.
