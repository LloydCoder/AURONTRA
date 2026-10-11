# Phase 18 — Authenticated Customer Console

**Status:** Implementation in progress. The old unbuildable dashboard containing fabricated operational records has been removed. The replacement is a dependency-free static console with a deterministic build and a browser E2E gate.

## Scope and trust boundaries

- The browser UI is a read-only presentation layer. The backend remains the authority for authentication, tenant isolation, role authorization, and durable evidence.
- The console consumes only authenticated API responses for organizations, devices, tickets, threat summaries, and threat events. Failed or disabled endpoints produce explicit unavailable states; they are never replaced with seeded records or zero-valued claims.
- “Verified containment” is computed only from records whose server response explicitly reports `containment_verified: true`. Detection, assessment, monitoring, or a containment request is not reported as a successful block.
- The SPA uses OIDC Authorization Code + PKCE with S256. It validates state, nonce, issuer, audience, expiration, issued-at time, and RS256 ID-token signatures using the issuer's JWKS. OIDC issuer and its authorization/token/JWKS endpoints must share an HTTPS origin.
- Access tokens remain in memory only. The PKCE verifier, state, and nonce are temporary session values and are removed after callback processing. API calls use a bearer header, no cookies, no cache, no redirects, and a bounded request timeout.
- The generated static output includes a deterministic SHA-256 manifest, a restrictive CSP allowlist, anti-framing and content-type headers, a no-referrer policy, and no-store caching.
- No production API credentials, OIDC secrets, customer records, or test-only authentication bypasses are embedded in the build.

## Implementation

- `frontend/index.html`, `frontend/app.js`, and `frontend/styles.css` form the static application.
- `frontend/build.py` validates public configuration, generates `config.js`, `_headers`, and `nginx.conf`, and verifies the deterministic manifest without third-party runtime dependencies.
- `frontend/e2e/console.spec.ts` covers sign-in, PKCE parameters, signed ID-token validation, tenant API bearer headers, sign-out, explicit data-plane-disabled behavior, and rejection of mismatched state/forged tokens.
- `frontend/tests/test_build.py` checks production HTTPS requirements, security headers, reproducible manifests, and tamper detection.
- `.github/workflows/ci.yml` runs frontend source/build checks and authenticated browser tests; deployment depends on the frontend gate.

## Acceptance gates

- [ ] Frontend build and manifest verification pass on the exact candidate SHA.
- [ ] All Playwright E2E tests pass on the exact candidate SHA.
- [ ] Backend CI, PostgreSQL tenant-isolation/RLS and restore checks, dependency audit, and secret/archive scan remain green.
- [ ] For a production rollout, the operator must configure the public OIDC issuer/client/redirect URI and API origin, register the exact redirect URI and CORS origins with the identity provider, and verify API JWT issuer/audience/JWKS configuration.
- [ ] A live authenticated test with a non-production tenant must prove that cross-tenant reads are denied and that the backend data plane is enabled only after the Phase 17 tenant-isolation gate is accepted.

## External release limitations

The console deliberately does not enable the backend business data plane. If the API reports `TENANT_DATA_PLANE_NOT_READY`, the UI shows that status and no data. CI fixtures are synthetic test records used only by the Playwright route intercepts; they are not included in production assets. A green build is not evidence that an OIDC provider, tenant, API origin, or production authorization policy has been configured.
