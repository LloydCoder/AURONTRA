# Contributing to Aurontra

Thank you for helping improve Aurontra. Contributions should make the system safer, easier to verify, or easier to operate without weakening its security boundaries.

## Before you start

1. Read the [architecture boundary](docs/ARCHITECTURE.md) and [security baseline](docs/SECURITY_BASELINE.md).
2. Search existing issues and pull requests for related work.
3. For substantial changes, open an issue first to agree on scope and acceptance criteria.
4. Never publish credentials, customer data, private telemetry, exploit details, or unredacted logs.

## Development setup

Backend CI uses Python 3.12.

~~~bash
git clone https://github.com/LloydCoder/AURONTRA.git
cd AURONTRA
git switch -c <type>/<short-description>
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
~~~

On Windows PowerShell, activate with .venv\Scripts\Activate.ps1.

## Validate changes

From backend/, run the core checks used by CI:

~~~bash
python -m pip check
alembic upgrade head
python -m compileall -q .
AUTH_MODE=disabled DATA_PLANE_ENABLED=true TEST_MODE=true pytest tests/ -v --tb=short --cov=. --cov-report=term-missing
~~~

The authentication/data-plane overrides above are **test-only**. Never set them to expose business APIs in a deployed environment. Changes affecting PostgreSQL row-level security or durable tenant state must also pass the PostgreSQL integration job in [CI](.github/workflows/ci.yml).

## Engineering expectations

- Keep the Tinlance Agent Platform as the sole authority for identity, authorization, policy, approvals, budgets, secrets, sandboxing, execution, and authoritative evidence.
- Fail closed when authentication, verification, or required configuration is missing.
- Treat model output, retrieved content, telemetry, external responses, and caller-supplied status fields as untrusted input.
- Do not execute privileged device actions locally or treat a planned/accepted action as a verified business outcome.
- Add negative tests for invalid input, missing configuration, replay, cross-tenant access, and failure paths where applicable.
- Keep dependencies pinned and use reviewed immutable revisions for cross-repository SDK dependencies.
- Update documentation and roadmap when behavior, configuration, security boundaries, or phase status changes.
- Avoid unrelated refactors in security-sensitive pull requests.

## Pull request process

1. Fork the repository if you do not have write access; otherwise work on a dedicated branch.
2. Use a focused branch name such as docs/quick-start, fix/tenant-check, or test/replay-protection.
3. Make small, reviewable commits. Conventional Commit-style prefixes (docs:, fix:, test:, feat:, security:, refactor:) are encouraged but not mandatory.
4. Run relevant checks and include the exact commands and results in the PR description.
5. Explain security impact, migration/rollback impact, configuration changes, and remaining limitations.
6. Link related issues and request review. Do not merge your own change unless repository policy explicitly authorizes it.

## Pull request checklist

- [ ] Scope and rationale are clear.
- [ ] Tests cover success and failure paths.
- [ ] Tenant boundaries and authorization remain enforced.
- [ ] No secrets or sensitive data were added.
- [ ] Documentation and configuration examples are accurate.
- [ ] CI passes, or failures are clearly explained.
- [ ] Production readiness and security claims are evidence-based.

## Responsible disclosure

Do not file exploitable vulnerability details in a public issue. Follow [SECURITY.md](SECURITY.md) for private reporting instructions.
