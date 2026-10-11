# Phase 08 — Platform-Bound Endpoint Agent Identity

**Status:** implementation on branch `phase-08-agent-identity`; acceptance requires backend CI, PostgreSQL RLS/backup-restore, and secret/history scan to be green before merge.

## Authority boundary

Aurontra is a resource server and product-specific telemetry consumer. It does not mint endpoint-agent tokens, store agent private keys, issue generic capabilities, or replace the Tinlance Agent Platform.

The Platform-approved identity provider must issue short-lived, DPoP-bound access tokens for a device principal. Required token claims:

- `iss`, `aud`, `sub`, `iat`, `exp`, and `jti`
- `tenant_id` (or `org_id`) matching the device's owning organization
- `scope` containing only the authorized operation
- `cnf.jkt` binding the access token to the DPoP public-key thumbprint

The token subject must equal the pre-provisioned Aurontra device ID. Aurontra verifies the issuer, JWKS signature, audience, tenant claim, scope, token lifetime, DPoP proof, and local device lifecycle state. Production configuration requires HTTPS for the issuer, JWKS, and canonical public origin. Agent auth is disabled by default and the production data plane remains closed until the full product-wide release gate is passed.

## Request proof

Agent requests use `Authorization: DPoP <access-token>` plus a `DPoP` JWT header. The proof requires:

- `typ=dpop+jwt` and an allowed asymmetric algorithm (ES256, RS256 with at least 2048-bit key, or EdDSA/Ed25519)
- Public-only JWK whose RFC 7638 thumbprint matches token `cnf.jkt`
- `htm`, canonical `htu`, fresh `iat`, unique `jti`, and `ath` (access-token hash)
- `bht`, an explicit Aurontra extension binding the proof to the exact request-body bytes

The server persists proof identifiers under a tenant RLS policy with a unique key. Reuse is rejected; expired entries are pruned within the tenant transaction. Body hashing supplements DPoP's standard method/URI/token binding. HTTPS remains mandatory in production.

## Lifecycle endpoints

- `POST /agent/v1/enroll`: requires `aurontra:agent:enroll`; only a provisioned, unrevoked device can enroll. The server binds `cnf.jkt`, records agent version and enrollment time, and only then activates the device.
- `POST /agent/v1/telemetry`: requires `aurontra:telemetry:write`; identity subject, tenant, active state, enrollment timestamp, revocation state, and enrolled key thumbprint must all match.
- `POST /agent/v1/rotate-key`: requires `aurontra:agent:key:rotate`; the new DPoP-bound token must be issued by the Platform-approved identity provider for the same device and new key. The server records rotation time and rejects subsequent requests bound to the previous thumbprint.

Revocation through the tenant-admin device lifecycle API remains authoritative and disables telemetry immediately. Re-enrollment of an already enrolled or revoked device is rejected; reactivation requires a reviewed lifecycle operation.

## Data and replay protection

Alembic revision `0005_agent_dpop_identity` adds the enrolled key thumbprint and rotation timestamp to devices, plus `agent_request_replays` with a unique proof identifier, tenant/device foreign key, request hash, expiry index, and forced PostgreSQL RLS. Backup/restore validation and non-owner RLS tests cover the replay table.

## Operational prerequisites before enabling in production

1. Configure the Platform-approved OAuth issuer to issue DPoP-bound device tokens with the required audience, tenant, subject, scope, and `cnf.jkt` claims.
2. Provision a workload principal for each device ID; do not mint or persist credentials inside Aurontra.
3. Set `AGENT_AUTH_ENABLED=true`, `AGENT_JWKS_URL`, `AGENT_JWT_ISSUER`, `AGENT_JWT_AUDIENCE`, and `AGENT_PUBLIC_ORIGIN` only after the issuer contract and TLS deployment have been validated.
4. Keep `DATA_PLANE_ENABLED=false` until all product APIs have durable tenant-scoped persistence and the complete release checklist is green.

## Standards basis

- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP): sender-constrained access tokens, per-request proof, access-token hash, and replay detection.
- RFC 7638 — JSON Web Key (JWK) Thumbprint: stable key binding.
- RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens: alternative sender-constraint mechanism if the approved identity provider does not support DPoP.
- NIST SP 800-207 — Zero Trust Architecture: authenticate and authorize each subject/device; never infer trust from network location.
