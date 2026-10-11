<div align="center">

# Aurontra

**Governed IT resilience for operations and security teams: turn operational signals into auditable, human-governed response workflows.**

[![CI](https://github.com/LloydCoder/AURONTRA/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/LloydCoder/AURONTRA/actions/workflows/ci.yml)
[![Security scan](https://github.com/LloydCoder/AURONTRA/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/LloydCoder/AURONTRA/actions/workflows/security.yml)

</div>

> [!WARNING]
> **Aurontra is not certified production-ready.** The production business data plane, endpoint-agent authentication, governed remediation submission, and threat containment remain disabled by default or blocked on external integration and release gates. Passing CI is not proof of production deployment, successful containment, calibrated prediction, or regulatory compliance.

## Why Aurontra

Aurontra is a Tinlance ecosystem product for IT service operations, infrastructure resilience, risk assessment, and governed remediation. It consumes the Tinlance Agent System; it does not replace or duplicate the Agent Platform's authority over identity, authorization, policy, approvals, secrets, sandboxing, execution, or authoritative evidence.

| Need | Aurontra approach | Important boundary |
|---|---|---|
| Operational visibility | Tenant-scoped tickets, device telemetry, and evidence records | Production ingestion remains gated on approved identity and release acceptance |
| Risk assessment | Threat signals and predictive evaluations with provenance | Scores are heuristics unless calibrated against representative labelled data |
| Remediation planning | Deterministic, freshness-bounded plans and durable intents | No local privileged execution; submission is disabled until Platform contracts and independent verification are configured |
| Governed action | Reviewed Tinlance Agent Platform SDK and code-owned action allowlists | Platform remains the sole execution authority |
| Auditability | Durable records, idempotency, and explicit verification states | An accepted action is not proof that the business outcome succeeded |

## Quick Start

Requirements: Python 3.12, Git, and a supported OS. These commands set up the backend and run tests; they do not enable production business APIs.

~~~bash
git clone https://github.com/LloydCoder/AURONTRA.git
cd AURONTRA/backend && python3.12 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
AUTH_MODE=disabled DATA_PLANE_ENABLED=true TEST_MODE=true pytest tests/ -q
~~~

The test-only environment overrides are scoped to the test command. Do not use them to run a production service.

## Installation

Requirements: Python 3.12, Git, network access for Python dependencies and the pinned Tinlance Agent Platform SDK revision. PostgreSQL 16 is used by the CI tenant-isolation and backup/restore integration checks.

From the repository root:

~~~bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
~~~

On Windows PowerShell, activate with .venv\Scripts\Activate.ps1.

### Run the API locally

From backend/, start the FastAPI application:

~~~bash
uvicorn main:app --host 127.0.0.1 --port 8003
~~~

Check liveness at http://127.0.0.1:8003/health/live. Liveness confirms that the process responds; it does not certify dependencies, tenant isolation, or production readiness. Business APIs remain closed unless authentication and release gates are configured.

## Usage

### Run tests

From backend/ with the virtual environment activated:

~~~bash
AUTH_MODE=disabled DATA_PLANE_ENABLED=true TEST_MODE=true pytest tests/ -v --tb=short --cov=. --cov-report=term-missing
~~~

These environment overrides are for isolated automated tests only. CI also runs dependency checks, a clean SQLite migration, compilation, PostgreSQL tenant-row-level-security tests, and a backup/restore smoke test. See the [CI workflow](.github/workflows/ci.yml) for enforced commands.

### Check liveness

~~~bash
curl --fail --silent --show-error http://127.0.0.1:8003/health/live
~~~

Expected response:

~~~json
{"alive":true}
~~~

### Configuration

Settings are environment-driven and may also be loaded from backend/.env. Never commit real secrets or copy production credentials into a local development environment.

| Setting | Default | Purpose |
|---|---|---|
| ENVIRONMENT | development | Runtime environment; production enforces stricter configuration checks |
| AUTH_MODE | required | Keeps business API authentication enabled by default |
| DATA_PLANE_ENABLED | false | Keeps the business data plane closed by default |
| TEST_MODE | false | Enables deterministic test-only behavior when explicitly set |
| DATABASE_URL | sqlite+aiosqlite:///./aurontra_dev.db | Local database URL; production requires reviewed durable database configuration |
| MAX_REQUEST_BODY_BYTES | 1048576 | Maximum declared request body size checked by application middleware |
| AGENT_AUTH_ENABLED | false | Endpoint-agent authentication feature gate |
| AGENT_PLATFORM_ENABLED | false | Governed Platform adapter feature gate |
| REMEDIATION_SUBMISSION_ENABLED | false | Internal remediation submission feature gate |
| THREAT_CONTAINMENT_ENABLED | false | Threat containment feature gate |
| REDIS_URL | redis://localhost:6379 | Redis URL for integrations that require it |

The full configuration is defined in [backend/core/config.py](backend/core/config.py). This table lists selected safety-relevant settings, not every supported environment variable. Production requires HTTPS identity-provider endpoints, tenant-scoped credentials, verified Platform tool/approval configuration, independent postcondition verification, durable subsystem coverage, and operational release evidence.

## Features and current maturity

| Capability | Repository evidence | Current limitation |
|---|---|---|
| Ticket and device APIs | Tenant-scoped persistence and cross-tenant regression tests | Overall production data plane remains gated |
| Endpoint-agent identity | DPoP-bound token verification and replay protection code | Disabled until approved issuer/JWKS and release gates are configured |
| Telemetry evidence | Freshness, provenance, idempotency, and tenant-scoped persistence | Production ingestion and retention scheduling are not certified as deployed |
| Predictive evaluation | Offline evaluation reports and input validation | Anomaly confidence is uncalibrated; forecasts are heuristics |
| Threat findings | Durable tenant-scoped findings and offline evaluation | Risk score is heuristic; ATT&CK mappings are hypotheses |
| Governed remediation | Deterministic plans, durable intents, Platform adapter contracts | Submission/worker/scheduler are not production-wired |
| Threat containment | Durable attempt state and independent-verification contract | Disabled pending verified Platform tool, approval policy, telemetry, and verifier integration |
| AI service desk | Draft-only resolution, redaction, approved knowledge retrieval, provenance | Production data plane remains closed |
| CI and security hygiene | Python tests, dependency audit, PostgreSQL RLS/restore checks, Gitleaks scan | CI does not replace production verification or independent security assessment |

## Documentation

- [Documentation index](docs/README.md)
- [Architecture and Tinlance Agent System boundary](docs/ARCHITECTURE.md)
- [Enterprise hardening roadmap](docs/ROADMAP.md)
- [Security baseline and release gates](docs/SECURITY_BASELINE.md)
- [Phase 08 — endpoint-agent identity](docs/PHASE_08_AGENT_IDENTITY.md)
- [Phase 09 — governed action engine](docs/PHASE_09_GOVERNED_ACTION_ENGINE.md)
- [Phase 10 — safe remediation playbooks](docs/PHASE_10_SAFE_REMEDIATION.md)
- [Phase 11 — durable orchestration and recovery](docs/PHASE_11_ORCHESTRATION_RECOVERY.md)
- [Phase 12 — telemetry evidence](docs/PHASE_12_TELEMETRY_EVIDENCE.md)
- [Phase 13 — predictive evaluation](docs/PHASE_13_PREDICTIVE_EVALUATION.md)
- [Phase 14 — AI service desk](docs/PHASE_14_AI_SERVICE_DESK.md)
- [Phase 15 — threat evidence](docs/PHASE_15_THREAT_EVIDENCE.md)
- [Phase 16 — verified containment](docs/PHASE_16_VERIFIED_CONTAINMENT.md)
- [Phase forensic audits](docs/audits/)
- [LLM documentation index](llms.txt)

## Contributing

Contributions should include focused tests, documentation updates, and evidence for security-sensitive behavior. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Never submit secrets, customer data, unverified claims, or changes that bypass Platform authorization and approval controls.

## License and acknowledgements

**No license file is currently present.** Until the maintainers choose and add a license, do not assume permission to reuse, modify, or redistribute this repository. See the [license decision note](docs/LICENSING.md).

Aurontra integrates with the Tinlance Agent System through the reviewed [Tinlance Agent Platform SDK](https://github.com/LloydCoder/tinlance-agent-platform-sdk). The Platform remains the authority for governed execution and evidence.

<details>
<summary>Roadmap and production acceptance</summary>

The roadmap contains 24 sequential hardening phases. The repository records historical acceptance for Phases 01–16, with Phase 17 in progress at the latest recorded checkpoint. Verify the current [roadmap](docs/ROADMAP.md) and CI before relying on phase status.

Production acceptance requires complete resource-level authorization and tenant isolation, durable state across enabled business subsystems, provider-backed webhook idempotency, reviewed Platform tool and approval registrations, independently verified outcomes, worker/scheduler deployment, backups and recovery drills, monitoring, and a real deployment followed by independent verification.

</details>

<details>
<summary>Troubleshooting</summary>

- **Business APIs return 503:** expected when identity configuration, the data-plane gate, or tenant-isolation release requirements are not satisfied.
- **Endpoint-agent routes return 503:** check the feature gate and approved issuer/JWKS/audience configuration; do not disable authentication to bypass the gate.
- **Platform actions are unavailable:** the adapter is disabled by default and needs tenant-scoped credentials, registered tools, and policy/approval configuration.
- **Dependency installation fails:** use Python 3.12 and ensure Git access is available for the pinned SDK dependency.
- **A test requires PostgreSQL:** use the PostgreSQL integration workflow or a disposable PostgreSQL 16 test database. Do not point tests at production.

</details>

<details>
<summary>Support</summary>

Use the repository issue tracker for reproducible bugs and feature requests. Do not disclose vulnerabilities or credentials in public issues; follow [SECURITY.md](SECURITY.md).

</details>
