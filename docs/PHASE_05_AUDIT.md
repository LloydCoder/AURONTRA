# Phase 05 Forensic Audit — Tenant Persistence and Resource Authorization

**Audited implementation baseline:** `0ddf2fd96fde49ca9466b6861a562b2b44402f3c`  
**Workflow:** [Aurontra CI and Deployment run 38097323960](https://github.com/LloydCoder/AURONTRA/actions/runs/38097323960)  
**Decision:** Phase 05 foundational acceptance passed. **Production release remains blocked.**

## Scope

Phase 05 establishes durable tenant-scoped storage for the core ticket and device resources, validates tenant context and organization state, enforces relational integrity in SQLite tests, and verifies PostgreSQL RLS behavior using a non-owner/non-bypass role. It does not claim that all Aurontra subsystems are production-ready.

## Implementation reviewed

- `backend/core/database.py`
  - Uses transaction-local `app.current_org_id` for PostgreSQL RLS.
  - Requires a verified tenant context outside explicit test mode.
  - Rejects missing, suspended, or otherwise non-active organizations.
  - Enables SQLite foreign-key enforcement so tests cannot silently pass with orphaned records.
  - Keeps production schema management under Alembic; `create_all` is not the production migration mechanism.
- `backend/api/routes/tickets.py`
  - Persists tickets through SQLAlchemy.
  - Scopes list, detail, and resolution queries by tenant.
  - Verifies referenced devices belong to the same tenant.
  - Commits writes before returning success.
  - Keeps generated AI replies distinct from verified resolution; a model claim alone does not mark a ticket resolved.
- `backend/api/routes/devices.py`
  - Lists and fetches only tenant-owned devices.
  - Accepts telemetry only for an active enrolled device owned by the current tenant.
  - Commits the device state update before reporting persistence.
- `backend/alembic/versions/0002_tenant_foreign_keys_and_rls.py`
  - Adds tenant foreign keys and PostgreSQL RLS policies for the tenant-owned schema.
- `backend/tests/integration/test_tenant_resource_isolation.py`
  - Verifies cross-tenant ticket reads are not disclosed.
  - Verifies tickets cannot reference another tenant's device.
  - Verifies telemetry cannot mutate another tenant's device.
  - Verifies inactive organizations cannot open a tenant database session.
  - Verifies foreign-key rejection and transaction rollback.
- `backend/tests/integration/test_tenant_rls.py`
  - Uses a non-owner, non-`BYPASSRLS` role.
  - Verifies tenant isolation for organizations, devices, and tickets.
  - Verifies cross-tenant writes are denied.
- `.github/workflows/ci.yml`
  - Runs backend tests and static sanity checks.
  - Runs PostgreSQL migration/RLS tests.
  - Performs a PostgreSQL custom-format dump/restore smoke test and verifies restored tenant data and RLS policies.
  - Gates production deployment on explicit `vars.DEPLOY_ENABLED == 'true'`; a skipped deployment is not represented as a deployment success.

## CI evidence

- Backend tests: **273 passed, 1 skipped**, 1 warning.
- Total test coverage: **83.52%** (required threshold 60%).
- Alembic clean SQLite upgrade: passed.
- Python compilation: passed.
- PostgreSQL migration: passed.
- PostgreSQL RLS test: passed.
- PostgreSQL backup/restore smoke test: passed.
- Gitleaks current tree/history and archive scan: passed.
- Overall CI workflow: **success**.
- Deployment job: **skipped**, because production deployment is not explicitly enabled/configured. No production deployment is claimed.

## Residual blockers and explicit non-claims

1. **The production business data plane remains closed.** Other business modules still have legacy in-memory or caller-supplied behavior, including parts of resilience history, threat history, SLA/reporting, knowledge-base, billing/subscription, and audit writes.
2. Device enrollment, API-key issuance/rotation/revocation, authenticated endpoint-agent communication, and offboarding remain future phases.
3. The database restore test is a CI smoke test, not evidence of configured managed backups, production RPO/RTO, or a completed disaster-recovery drill.
4. The PostgreSQL RLS suite currently exercises organizations, devices, and tickets. Each future tenant-owned table and route must be covered before the global data-plane gate can be removed.
5. Production identity-provider configuration, actual production database migration, endpoint agent, Tinlance Agent Platform integration, and real deployment have not been verified.

## Research basis

- OWASP API Security Top 10, API1:2023 — Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- PostgreSQL Row Security Policies: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- PostgreSQL row locking and `SKIP LOCKED` semantics: https://www.postgresql.org/docs/16/sql-select.html
- AWS Prescriptive Guidance — transactional outbox: https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/transactional-outbox.html
- NIST SP 800-218 — Secure Software Development Framework: https://csrc.nist.gov/pubs/sp/800/218/final

## Phase decision

**Phase 05: Complete for the foundational tenant persistence and resource-isolation scope.**

**Phase 06 starts next:** durable jobs, transactional outbox, idempotency, lease-based workers, retry/backoff, cancellation, and dead-letter/reconciliation behavior. Existing legacy subsystems remain disabled from production until their own phases and verification gates pass.
