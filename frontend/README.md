# AURONTRA customer console

The console is a dependency-free static application. `python3 build.py` copies the reviewed HTML, JavaScript, and CSS, writes public OIDC/API configuration from environment variables, emits deployment security headers, and creates a deterministic SHA-256 manifest. `python3 build.py --verify` verifies that manifest. The application build itself does not install or execute third-party JavaScript packages.

## Build configuration

Public, non-secret build variables:

- `AURONTRA_API_BASE_URL`: canonical HTTPS API origin, without a path.
- `AURONTRA_OIDC_ISSUER`: exact OIDC issuer URL used for discovery.
- `AURONTRA_OIDC_CLIENT_ID`: public SPA client identifier.
- `AURONTRA_OIDC_REDIRECT_URI`: exact registered redirect URI, normally the console root.
- `AURONTRA_OIDC_AUDIENCE`: optional provider-specific API audience.
- `AURONTRA_ENVIRONMENT`: set to `test` only for the E2E harness; insecure HTTP is accepted only for `.test` API hosts in that mode.

No client secret is accepted or embedded. The browser performs Authorization Code + PKCE, validates state and the ID-token issuer/audience/nonce, and keeps access tokens in memory only. The PKCE verifier, state, and nonce are temporary session values and are cleared after callback handling. The backend remains the authorization authority and verifies bearer tokens independently.

The OIDC discovery issuer, authorization endpoint, and token endpoint must use HTTPS and the same origin. The API is called with `credentials: omit`, redirects disabled, `cache: no-store`, and a bounded timeout. Access tokens are never written to localStorage, sessionStorage, URLs, logs, or HTML. A reload requires re-authentication rather than persisting a bearer token.

## E2E tests

`npm install --no-save --package-lock=false @playwright/test@1.64.0`, then `npx playwright install --with-deps chromium`, then `npm run test:e2e`. The test harness intercepts OIDC and API traffic; its fixtures are test-only and are never shipped in the application build. It covers authenticated API calls, evidence-backed containment labels, disabled-data-plane behavior, and invalid OIDC state.

## Deployment

Serve `dist/` as static files and apply the generated `_headers` file or the supplied `nginx.conf`. A successful static build is not evidence that a production OIDC provider, API origin, tenant, or authorization policy has been configured. The business API intentionally returns 503 until the backend's tenant-isolation release gate is enabled; the console displays that condition without fabricating records.
