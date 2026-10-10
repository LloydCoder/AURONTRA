# Aurontra

**Aurontra — Autonomous IT Resilience Platform.** Detect operational risk, assist IT service workflows, coordinate governed remediation, and produce auditable operational evidence.

Aurontra is a Tinlance ecosystem product. It integrates with the authoritative Tinlance Agent System through documented, versioned interfaces; it must not duplicate the Agent Platform's identity, authorization, policy, approval, sandbox, secrets, execution, or audit authority.

## Product scope

- IT service-desk assistance with risk-based escalation.
- Device and infrastructure health telemetry and evaluated predictive signals.
- Governed remediation through authenticated endpoint agents.
- Threat analysis and containment with independently verified enforcement outcomes.
- Enterprise integrations, operational reporting, and evidence provenance.

## Current release status

**Not certified production-ready.** The repository is undergoing security-first hardening. Existing test success is not equivalent to production readiness, and a decision score is not proof that a threat was blocked.

Until secure endpoint execution and authorization are implemented and tested:
- Public self-healing execution is disabled.
- The threat-containment endpoint is disabled; analysis must not be represented as containment.
- Billing webhooks are rejected when signature verification cannot be performed.
- Public organization registration and checkout are disabled until secure tenant lifecycle and provider-backed billing are implemented.
- The production business data plane is disabled by default until JWT verification and durable tenant isolation are configured.
- ROI outputs are illustrative models, not measured savings; control mappings are not compliance certification.
- Deployment status is reported separately from test status.

## Development and verification

Backend CI uses Python 3.12 and pytest. The CI workflow is the source of truth for currently enforced checks. Security, persistence, frontend, integration, and deployment gates will be expanded as hardening proceeds. New tenant, API-key, audit, and webhook idempotency models are schema foundations only; no production migration or tenant-isolated data-plane release is claimed.

## Architecture and security principles

1. Default-deny for privileged actions.
2. Authenticate and authorize every non-public operation at tenant and resource level.
3. Never execute a requested device action on the API host as a substitute for an endpoint agent.
4. Distinguish observed, detected, decided, requested, enforced, and verified states.
5. Persist operational records and audit evidence durably.
6. Keep secrets out of source control, logs, API responses, and artifacts.
7. Report modeled ROI separately from measured outcomes.
8. Do not claim NIS2/DORA compliance or certification based only on caller-supplied metrics.

## Roadmap

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the canonical Tinlance Agent System boundary, [docs/ROADMAP.md](docs/ROADMAP.md) for the phase plan, and [docs/SECURITY_BASELINE.md](docs/SECURITY_BASELINE.md) for safety constraints and release gates.
