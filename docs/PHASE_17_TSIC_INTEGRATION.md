# Phase 17 — Tinlance Ecosystem Integration

**Status:** In progress; TSIC registration and trace-context version correction are merged. Contract hardening is implemented and CI-validated on the candidate branch; live cross-system verification and operational acceptance remain open.  
**Aurontra baseline:** `c804dc7d72da163c0fe3db928b753d5cc826544c`  
**TSIC registration PR:** [LloydCoder/tinlance-system-integration#53](https://github.com/LloydCoder/tinlance-system-integration/pull/53)  
**TSIC candidate commit:** `ae961f1cf6ea26ac0d468283b03159f016613caf`  
**Authority:** TSIC owns ecosystem contracts and registry; Tinlance Agent Platform owns generic consequential execution.

## Objective

Register Aurontra in the canonical TSIC ecosystem and prove versioned, tenant-safe, replay-safe contracts across Aurontra and the Tinlance Agent Platform. Registry registration alone is not end-to-end integration or production certification.

## Work completed

- [x] Inspected TSIC's live ecosystem manifest schema, capability authority registry, canonical architecture map, dependency graph, service registry, and adapter registry.
- [x] Merged TSIC PR #53 as `f12105f5a64fc365eae1bd151d01eed509f3108d` after the TSIC CI and associated certification workflows passed on candidate `ae961f1cf6ea26ac0d468283b03159f016613caf`.
- [x] Merged TSIC PR #54 as `619db9e264cdc71369de621c981bfc2ba1615a1d` to align the trace-context registry version to the authoritative `1.1.0` contract and pin Aurontra's per-contract adapter versions; all 32 associated workflows passed on the reviewed candidate.
- [x] Registered Aurontra as a domain product, added its reference adapter, declared the Agent Platform dependency, and bound identity-context, event-envelope, delivery-semantics, trace-context, and agent-registration contracts.
- [x] Kept Aurontra's authority narrowly scoped to `it_resilience_product`; no execution authority was added.
- [x] Preserved the rule that reference registration does not enable production flags or certify runtime integration.
- [x] Added a pinned TSIC contract snapshot (`identity-context` 1.0.0, `event-envelope` 1.0.0, `trace-context` 1.1.0) tied to TSIC registry revision `619db9e264cdc71369de621c981bfc2ba1615a1d`.
- [x] The shared client now accepts only typed `TSICIdentityContext` objects for tenant-scoped operations and binds tenant, organization, workspace, actor, execution, trace, and correlation headers.
- [x] Integration destinations are bound to explicit service-to-configuration allowlists; arbitrary service names and spoofed origins fail closed (OWASP SSRF guidance).
- [x] Successful response bodies are streamed with a strict 1 MiB cap before JSON parsing; redirects remain disabled.
- [x] W3C `traceparent` is validated and propagated; event envelopes are validated against the pinned TSIC contract snapshot; unsafe correlation/idempotency values are rejected.
- [x] ThreatFade and FusionOps data operations now require typed tenant context; health probes remain non-tenant-scoped.
- [x] Regression tests cover unknown services, spoofed origins, untyped identity context, oversized responses, cross-tenant envelope mismatches, and header injection.
- [x] Earlier candidate `161a0fa988a02ddd7ffe134bddcacff8d8d2f540` passed CI with 503 tests passed, 1 skipped, and 85.08% coverage; PostgreSQL RLS/restore checks, dependency audit, and secret/archive scan passed.
- [ ] Validate the subsequent SSRF, bounded-response, typed-context, and bridge-propagation changes on one exact SHA; record the resulting test count and coverage below.
- [ ] Complete controlled sandbox contracts, independent-verifier integration, and operational release gates.

## Required implementation gates

### 17.1 Registry and authority integrity
- Verify manifest/schema validity, unique system IDs, graph/manifest parity, canonical architecture parity, capability-owner parity, and service registry consistency.
- Verify Aurontra's only generic consequential execution path remains the Agent Platform.
- Do not mark Aurontra or the production system-of-systems gate complete solely because structural registry checks pass.

### 17.2 Versioned contracts and identity propagation
- Add automated contract tests for tenant/subject identity, schema version negotiation, event envelope validation, trace/correlation propagation, idempotency keys, and sanitized failures.
- Tenant identity must originate from verified server-side authentication context, never caller-supplied payload fields.
- Unsupported versions and missing or mismatched identity must fail closed.

### 17.3 Trusted telemetry and threat findings
- Prove that only authenticated, enrolled, active devices can submit telemetry.
- Bind findings to tenant, device, telemetry source, freshness window, provenance, and detector version.
- Public caller-controlled network signals must not satisfy endpoint-trust requirements for containment.

### 17.4 Governed remediation and containment
- Keep Platform tool names and arguments code-owned and bounded.
- Verify that approvals, policy, authorization, and execution state come from the Platform.
- Preserve unknown-outcome reconciliation and stable idempotency for retries.
- Do not treat Platform acknowledgement as proof of a business postcondition.
- Accept containment only after fresh, signed, target-bound independent verification evidence.

### 17.5 Durable delivery and recovery
- Test outbox atomicity, duplicate delivery, consumer idempotency, expired leases, retry/backoff, dead-letter handling, cancellation, and crash recovery.
- Deploy and monitor a real worker/scheduler only after runtime configuration is reviewed; CI queue primitives do not prove production processing.

### 17.6 Live integration and release
- Run mocked contract tests first.
- Run controlled sandbox tests only when a safe test tenant, tenant-scoped Platform principal, registered tools, approval policy, and independent verifier credentials are explicitly provisioned.
- Keep `DATA_PLANE_ENABLED`, `AGENT_PLATFORM_ENABLED`, `REMEDIATION_SUBMISSION_ENABLED`, and `THREAT_CONTAINMENT_ENABLED` disabled until their respective acceptance evidence is complete.
- Reconcile docs, phase audit, and exact-SHA CI/security evidence after every implementation change.

## Acceptance criteria

Phase 17 is complete only when:
1. TSIC registration and authority/graph/capability conformance are green and merged.
2. Aurontra contract tests cover identity, versioning, event provenance, trace propagation, idempotency, and failure semantics.
3. Trusted telemetry-to-finding and finding-to-remediation paths pass positive and negative tenant-isolation tests.
4. The concrete independent containment verifier is integrated and adversarially tested for stale, replayed, mismatched, invalid-signature, and cross-tenant evidence.
5. Platform approval/policy/tool configuration is verified in a controlled environment without local execution bypass.
6. Worker/scheduler processing and recovery are demonstrated, with observability and operational runbooks.
7. Main-branch CI, PostgreSQL migration/RLS/restore checks, dependency checks, secret/history/archive scan, and forensic audit are green on the exact candidate.
8. Release documentation distinguishes repository validation, sandbox integration, production deployment, and customer readiness.

## Current non-claims

- TSIC PR #53 is merged; registry inclusion is not proof of runtime integration.
- Structural TSIC CI is not proof of Aurontra runtime integration.
- No live production Platform, verifier, identity provider, customer database, worker/scheduler, or containment action has been exercised by this phase's current evidence.
- Domain allowlisting reduces SSRF exposure but does not alone prevent DNS rebinding; deployment networking must enforce approved egress and prevent private/link-local metadata destinations as defense in depth.
- Production readiness, predictive accuracy, threat-detection efficacy, and compliance certification are not claimed.
