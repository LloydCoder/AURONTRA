# Aurontra documentation

This index groups project documentation by the kind of question it answers.

## Start here

- [Repository README](../README.md) — product scope, setup, tests, selected configuration, and maturity limitations.
- [Architecture](ARCHITECTURE.md) — component boundaries, Platform integration, and current implementation constraints.
- [Roadmap](ROADMAP.md) — sequential hardening phases and recorded acceptance status.
- [Security baseline](SECURITY_BASELINE.md) — known risks, safety controls, and release gates.
- [Licensing decision](LICENSING.md) — unresolved license selection and required maintainer decision.

## Tutorials

The repository does not yet provide a fully verified end-to-end product tutorial because the production data plane and external integrations remain gated. Begin with the backend Quick Start in the [root README](../README.md) to install dependencies and run tests.

## How-to guides

- [Run CI-equivalent backend tests](../CONTRIBUTING.md#validate-changes)
- [Report a vulnerability privately](../SECURITY.md)
- [Ask for support](../SUPPORT.md)
- [Contribute a change](../CONTRIBUTING.md)

## Explanation

- [Architecture and system boundary](ARCHITECTURE.md)
- [Security baseline and release gates](SECURITY_BASELINE.md)
- [Roadmap and phase acceptance](ROADMAP.md)
- [Phase forensic audits](audits/)

## Reference

- [Backend configuration](../backend/core/config.py)
- [Backend dependency manifest](../backend/requirements.txt)
- [CI workflow](../.github/workflows/ci.yml)
- [Security scan workflow](../.github/workflows/security.yml)
- [LLM documentation index](../llms.txt)

## Phase design documents

- [Phase 08 — endpoint-agent identity](PHASE_08_AGENT_IDENTITY.md)
- [Phase 09 — governed action engine](PHASE_09_GOVERNED_ACTION_ENGINE.md)
- [Phase 10 — safe remediation playbooks](PHASE_10_SAFE_REMEDIATION.md)
- [Phase 11 — orchestration and recovery](PHASE_11_ORCHESTRATION_RECOVERY.md)
- [Phase 12 — telemetry evidence](PHASE_12_TELEMETRY_EVIDENCE.md)
- [Phase 13 — predictive evaluation](PHASE_13_PREDICTIVE_EVALUATION.md)
- [Phase 14 — AI service desk](PHASE_14_AI_SERVICE_DESK.md)
- [Phase 15 — threat evidence](PHASE_15_THREAT_EVIDENCE.md)
- [Phase 16 — verified containment](PHASE_16_VERIFIED_CONTAINMENT.md)

- [Repository metadata and release maintenance checklist](MAINTENANCE.md)
