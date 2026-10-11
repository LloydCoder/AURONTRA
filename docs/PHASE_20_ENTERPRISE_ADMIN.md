# Phase 20 — Enterprise Administration Foundation

**Status:** Implementation candidate; acceptance pending exact-SHA CI, security review, and API-key authorization tests.

## Implemented

- Added tenant-scoped administrator endpoints to list, create, and revoke API keys.
- Generated API key secrets with a cryptographically secure random generator; only SHA-256 hashes and short prefixes are persisted.
- Returned the raw key exactly once from creation and excluded hashes/secrets from list and audit responses.
- Restricted scopes to a fixed allowlist and rejected unknown or duplicate scopes.
- Required an administrator/owner role in the verified request context; the central JWT policy also classifies `/admin/*` as administrator-only.
- Added idempotent revocation and tenant-scoped lookup to prevent cross-organization access.
- Appended API-key lifecycle events to the existing hash-linked audit chain in the same database transaction as the mutation.
- Added an administrator-only audit listing endpoint and tests for key secrecy, tenant isolation, scope validation, revocation replay, and audit-chain linkage.

## Acceptance gates

- [ ] Exact-SHA backend CI and PostgreSQL RLS/restore tests pass.
- [ ] Dependency audit and working-tree/history/archive secret scan pass.
- [ ] Verify administrator-vs-member/viewer negative authorization tests with signed JWT claims.
- [ ] Verify audit sequence allocation under concurrent administrator mutations on PostgreSQL.
- [ ] Review whether API keys are accepted by any runtime authentication path before advertising them as usable API credentials; this phase only manages credentials.
- [ ] Integration configuration and secret references are added only through a reviewed tenant-bound secret-management design.

## Non-claims

This phase does not create or modify identity-provider roles, does not store integration secrets, and does not claim API keys can authenticate requests. Authentication remains governed by the existing JWT perimeter. The audit chain is tamper-evident at the application layer, not a claim of immutable external storage.