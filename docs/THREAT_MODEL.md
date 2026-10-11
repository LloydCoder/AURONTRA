# Aurontra Threat Model

**Version:** 1.0  
**Review status:** Initial engineering threat model; open risks remain.  
**Product owner:** Tinlance Limited  
**System:** Aurontra, formerly ResilientAI

**Decision: Not production-ready.** The production business data plane remains closed until tenant isolation, durable persistence, and resource-level authorization are implemented and independently tested. This is a living engineering model, not a penetration-test report, compliance assessment, or certification.

## 1. Security objectives

1. Keep each customer organization isolated from every other organization.
2. Authenticate people, services, and endpoints; authorize every operation with least privilege.
3. Ensure Aurontra cannot independently grant agent execution authority or bypass Tinlance Agent Platform policy and approvals.
4. Distinguish observed signals, model assessments, decisions, requested actions, enforced actions, and verified outcomes.
5. Preserve provenance, integrity, and access controls for operational evidence.
6. Minimize exposure of ticket PII, device telemetry, credentials, threat indicators, and model context.
7. Make billing state and webhook processing authentic, replay-safe, durable, and reconcilable.
8. Make release artifacts reproducible and prevent untrusted repository content from becoming executable deployment input.

## 2. System context and trust boundaries

### Components

- **User console/API:** receives user requests, tickets, telemetry, reports, and administration actions.
- **Identity provider:** configured JWT/JWKS issuer. Aurontra verifies asymmetric signature, issuer, audience, expiry, subject, organization, and role.
- **Aurontra database:** intended durable tenant records, device/ticket state, webhook idempotency, and audit evidence. Current schema includes foundation models; route-level repositories are not yet wired.
- **Tinlance Agent Platform and SDK:** authoritative identity, authorization, policy, approval, budget, sandbox, secret access, execution, and authoritative evidence for agent actions.
- **Tinlance Agent Developer (TADL):** developer-plane artifact validation and conformance; it does not grant execution authority.
- **Tinlance Agent OS:** workspace, lifecycle, task/workflow, and operator experience above the Platform.
- **Endpoint agent:** future authenticated endpoint identity and telemetry/action channel. It is not yet a verified production component in Aurontra.
- **Tinlance ecosystem bridges:** ThreatFade, FusionOps, ReconOS, BugFlow, FDSE, HezCast, TwinGuard, FadeForge, AI Shield, KalevioAI, Olvrix, and FadeReach. A bridge module is not proof that a remote integration is deployed or authenticated.
- **External services:** LLM providers, Lemon Squeezy, email delivery, database/cache infrastructure, CI/CD, and production hosts.
- **Release pipeline:** GitHub Actions builds/tests/scans source and may deploy only with explicitly configured production credentials.

### Trust boundaries

| Boundary | Untrusted input | Required control |
|---|---|---|
| Browser/user to API | Query/body/headers, IDs, ticket text, claimed organization/role | JWT verification, role policy, schema limits, tenant binding, rate limits, object-level authorization |
| API to database | Tenant IDs, resource IDs, model output, bridge payloads | Parameterized queries, tenant predicates, transactions, PostgreSQL RLS, least-privilege DB role |
| Aurontra to Agent Platform | Requested action, device/resource identifiers, model-generated intent | Versioned SDK contract, service identity, request IDs/idempotency, Platform policy/approval/budget/sandbox |
| Endpoint agent to API | Telemetry, result claims, agent identity | Device-bound credentials, signed requests, replay protection, schema/version checks, result verification |
| API to external bridge | User-influenced identifiers and remote responses | HTTPS, scoped credentials, allowlisted endpoints, timeouts, bounded responses, schema validation, circuit breakers |
| Provider to webhook | Raw body, signature, event metadata | Raw-body HMAC, constant-time comparison, event deduplication, durable inbox, provider reconciliation |
| Ticket/context to LLM | PII, malicious instructions, retrieved documents | Data minimization, prompt-injection handling, structured output, tool allowlists, no authority from model output |
| Repository/artifact to CI/deploy | Source, archives, scripts, dependencies, workflow definitions | Full-SHA action pinning, read-only token, secret/archive scan, no execution of untrusted archives, reviewed release artifacts |

## 3. Assets and security impact

- **Customer data:** ticket descriptions, reporter email, device inventory, telemetry, reports, integrations and account metadata.
- **Tenant boundary:** organization IDs, role claims, device/ticket ownership, query predicates, RLS session context.
- **Execution authority:** Agent Platform identity, approval, budget, sandbox, scoped secrets, endpoint-agent credentials.
- **Security evidence:** detections, threat events, containment acknowledgements, audit chain, compliance-control evidence.
- **Commercial state:** subscription IDs, payment events, plan/entitlement state, webhook secrets.
- **Confidential credentials:** JWT/JWKS configuration, API keys, bridge credentials, LLM keys, deployment SSH credentials, GitHub token.
- **Availability/integrity:** database records, job state, queue state, model outputs, deployment configuration, backups, recovery procedures.
- **Reputation and regulatory posture:** false claims of containment, compliance, uptime, or financial savings can cause direct customer and legal harm.

## 4. Threat register

Ratings are qualitative and reflect the current repository and default-closed production data plane, not a hypothetical fully enabled deployment.

| ID | Threat / STRIDE | Risk | Current mitigation/evidence | Residual blocker |
|---|---|---:|---|---|
| T-01 | Cross-tenant disclosure or mutation: information disclosure, tampering, elevation | Critical | Production data plane returns 503 until a code-level tenant-isolation gate is removed after review; JWT organization/role checks exist | Ticket/device handlers now use tenant-scoped SQLAlchemy repositories; PostgreSQL RLS covers organizations/devices/tickets and negative tests pass. Remaining business handlers still use legacy in-memory/caller-supplied state, so the data plane stays closed |
| T-02 | Forged, expired, wrong-issuer, or wrong-audience JWT: spoofing | High | PyJWT verifies RS256/ES256 signature, issuer, audience, expiry, iat and subject; tests cover valid and invalid signatures; production identity endpoints must use HTTPS | No deployed identity-provider configuration, key-rotation drill, token revocation/session policy, or production integration test |
| T-03 | Low-privilege user invokes privileged operation: elevation | High | Conservative role policy distinguishes viewer/member/admin; privileged automation, threat block, checkout, onboarding and deletes require admin | No fine-grained scopes or resource ownership checks |
| T-04 | API-host filesystem/service/process mutation: tampering/elevation | Critical | Public playbook trigger returns 503; playbooks are recommendation-only; no local cleanup, Certbot, systemctl, or process reprioritization | Authenticated endpoint agent and Platform-governed action adapter are not implemented |
| T-05 | Detection result represented as successful containment: spoofing/repudiation | Critical | Public containment disabled; upstream block claims normalized as unverified; SIEM export does not trust caller-supplied status/action fields | No enforcement acknowledgement, independently verified postcondition, or tested enforcement adapter |
| T-06 | Webhook forgery or replay changes entitlement: spoofing/tampering | High | Lemon Squeezy raw-body HMAC-SHA256 verification fails closed when secret/signature is absent; checkout is disabled | Inbound webhook idempotency, replay tests, and provider-state reconciliation remain open; the outbound transactional outbox does not process payment-provider webhooks |
| T-07 | Arbitrary domain input triggers internal-network probes: SSRF | High | Certificate playbook no longer performs outbound probes or invokes Certbot | Future certificate inventory needs owned-domain allowlists, DNS/IP validation, redirect policy, and egress controls |
| T-08 | Prompt injection leaks ticket PII or causes unsafe action: tampering/disclosure/elevation | High | Autonomous remediation disabled at public boundary | PII minimization, tenant-scoped retrieval, prompt-injection suite, structured output validation, model-provider retention policy, and tool allowlists remain open |
| T-09 | Malicious bridge response trusted or hangs API: spoofing/DoS | High | Integration endpoints default unset; bridge timeout configuration exists | Per-bridge TLS/service identity, response schemas, bounded bodies, retries/circuit breakers, error isolation, and contract tests |
| T-10 | Oversized/high-rate requests exhaust resources: DoS | High | Declared request body limit defaults to 1 MiB; selected list limits are bounded | Content-Length check does not constrain chunked bodies; gateway rate/concurrency limits and per-tenant budgets are not verified |
| T-11 | Unreviewed deployment archive enters CI/deploy: tampering/elevation | High | Legacy archive removed from current branch; workflow rejects tracked tarballs and scans current tree/history as data | Historical blob remains in Git history and is scanned; incident below requires continued scrutiny |
| T-12 | Secret leaks through code, Git history, or archive: disclosure | High | Checksum-pinned Gitleaks scans working tree, nested archives and reachable history; no matching findings reported | Scanner coverage is not proof that every secret is detectable; external credentials still require least privilege and rotation policy |
| T-13 | Fake checkout or duplicate webhook activates entitlement: tampering | High | Checkout returns 503; signature verification is strict | No provider-created checkout session, durable subscription table, webhook dedupe, entitlement reconciliation, or duplicate-event tests |
| T-14 | Caller-supplied metrics imply compliance or realized savings: repudiation/tampering | High | ROI output is labelled illustrative; control mapping is not called certification | Evidence-backed collection, provenance/freshness, exceptions, and audited calculation methodology remain incomplete |
| T-15 | Audit record rewritten, omitted, or reordered: repudiation/tampering | High | Hash-chain utility exists; audit schema has ORM-level update/delete guards and sequence uniqueness | No complete transactional write path, DB-level append-only permissions, concurrent sequence allocation, external checkpoint, or tamper suite |
| T-16 | Vulnerable dependency or compromised GitHub Action enters release: tampering/elevation | High | Third-party Actions pinned to full commit SHAs; CI checks dependency consistency | Automated dependency audit, SAST, SBOM, provenance attestation, and action allowlist remain open |
| T-17 | Deployment marked green without deployment: repudiation/misconfiguration | High | CI and deployment are separate; preflight reports missing configuration and fails on a main-branch deployment attempt if required values are absent | Production SSH key/fingerprint/host/path/service variables are not confirmed; deployment has not been independently verified |
| T-18 | Data loss or prolonged outage: availability/tampering | High | Production startup checks configured Alembic revision when data plane is requested; data plane defaults closed | Backups, restore drills, RPO/RTO, queue recovery, rollback, alerting and SLO evidence are absent |

## 5. Attack scenarios and required controls

### A. Cross-tenant data access

**Attack path:** authenticate as a member of organization A, submit an organization B resource ID or alter an organization field in a body/query, then exploit a handler that looks up a shared in-memory record without a tenant predicate.

**Current outcome:** production business API remains closed. JWT role policy alone does not prove resource isolation. Ticket/device APIs now filter by verified tenant context and active organization; negative API tests and non-owner PostgreSQL RLS tests pass for organizations, devices and tickets.

**Required before opening the data plane:** derive tenant identity from verified request context, never a caller-controlled body field; scope every query/update/delete by tenant; enable and force PostgreSQL RLS for every tenant-owned table; set transaction-local tenant context; test API predicates and database isolation with two organizations and adversarial IDs. Phase 05 evidence covers organizations, devices and tickets; the remaining subsystems must be brought under the same controls.

### B. Unauthorized or incorrectly targeted remediation

**Attack path:** attacker submits a valid-looking device ID and playbook; API executes a local subprocess or host action; target differs from the claimed endpoint or causes service disruption.

**Current outcome:** public trigger disabled and playbooks recommendation-only.

**Required before enabling:** submit typed intent through the official Platform SDK; Platform evaluates identity, tenant, policy, approvals, budget and sandbox; endpoint agent authenticates device identity; action has allowlisted arguments, timeout/cancellation and idempotency; independently verify postconditions. Model output is never authority.

### C. False threat-block result

**Attack path:** malicious/erroneous signal or upstream response says a threat was blocked; report/SIEM exports false containment; operators believe traffic is stopped.

**Current outcome:** public containment disabled and unverified upstream claims downgraded.

**Required before enabling:** distinguish detected, decision made, containment requested, enforcement acknowledged, contained, and verification failed. Only an authenticated enforcement acknowledgement plus independent post-action check may set verified containment.

### D. Webhook replay and entitlement drift

**Attack path:** replay a valid signed event, race duplicate deliveries, or submit out-of-order events; duplicate activation or stale entitlements result.

**Current outcome:** raw-body HMAC authenticity is checked; checkout and business data plane disabled.

**Required before enabling:** durable unique provider/event ID; persist payload hash and received/processed state transactionally; acknowledge only after durable capture; process asynchronously with retries/dead-letter handling; reconcile provider state; test duplicate, replay, reordering, invalid signature, missing secret, and provider outage. Lemon Squeezy retries failed deliveries, so processing must be idempotent.

### E. Prompt injection and PII exfiltration

**Attack path:** attacker embeds instructions in ticket text or retrieved knowledge; LLM follows them, reveals cross-tenant context, or attempts a privileged tool call.

**Required before enabling autonomous resolution:** redact/minimize PII; enforce tenant-filtered retrieval; treat ticket text, retrieved content, bridge output and model output as untrusted; validate strict typed output; use allowlisted tools with policy checks; do not let the model choose tenant/resource authority; escalate security, infrastructure and ambiguous cases; record model/provider/version and evidence.

### F. Release artifact compromise

**Attack path:** stale deployment archive contains old code/config or executable installer; CI/deploy consumes it without source review.

**Current outcome:** old archive removed from current branch; workflow rejects tracked tarballs and scans historical Git objects without executing them.

**Incident record:** an intermediate archive-inventory workflow revision used unsafe shell command substitution while formatting matched paths and attempted to execute some paths inside the archive on an ephemeral GitHub-hosted runner. That workflow was replaced. The affected security job had read-only contents permission and no application/deployment secrets configured; no production deployment was run. No independent outbound-network audit of that runner was available, so this is recorded as a workflow security incident rather than asserting that no external communication occurred.

**Required before release:** build from reviewed commit in a clean job; never execute repository archives as an inspection technique; pin actions to verified full SHAs; use read-only tokens; produce checksum/SBOM/provenance; require reviewed production environment approvals; test rollback.

## 6. Security design decisions

- **Default deny:** production business data plane disabled in code until tenant-scoped repositories, migration verification, object-level authorization and cross-tenant tests are complete.
- **One execution authority:** Tinlance Agent Platform remains the only authority for agent policy, approval, sandbox, secrets, budgets, execution and authoritative agent evidence. Aurontra is a product client, not a parallel authority kernel.
- **Evidence state separation:** a detection score is not a finding; a decision is not enforcement; an action request is not acknowledgement; acknowledgement is not independently verified business outcome.
- **Fail closed:** missing identity configuration, invalid token, absent webhook secret/signature, unavailable durable tenant store, and missing deployment configuration must not silently enable functionality.
- **No secrets in source/artifacts:** credentials come from managed environment/secret stores; raw API keys shown once and only hashes stored; public artifacts are not deployment sources.
- **Tenant identity is not user input:** derive organization context from verified identity and enforce it again in every repository query and database policy.
- **Compliance/ROI claims require provenance:** caller-supplied values are estimates, not audit evidence, certification, or measured savings.

## 7. Required verification matrix

| Control | Required test/evidence | Status |
|---|---|---|
| JWT signature, issuer, audience, expiry | Valid, wrong-key, expired, wrong-issuer/audience tests | Partial: valid/wrong-signature and perimeter tests exist |
| Role policy | Viewer/member/admin positive and negative tests | Partial: basic role policy tests exist |
| Tenant isolation | Two-tenant CRUD, guessed IDs, altered org claims, raw SQL/RLS bypass tests | Partial: ticket/device API negatives and PostgreSQL RLS tests pass for organizations/devices/tickets; remaining business routes are gated |
| Database migrations | Clean upgrade, existing-schema reconciliation, wrong-revision startup test | Partial: clean SQLite upgrade; existing DB reconciliation open |
| Webhook authenticity/idempotency | Raw-body HMAC, duplicate event, replay, out-of-order and provider outage | Partial: HMAC tests; durable idempotency open |
| Remediation safety | Target identity, policy/approval, bounded execution, timeout, cancellation, postcondition | Open; public execution disabled |
| Threat containment | Enforcement acknowledgement, independent verification, failed containment | Open; public containment disabled |
| LLM safety | Prompt injection, cross-tenant retrieval, PII redaction, output schema and timeout | Open |
| Bridge safety | TLS, service auth, schema/size limits, timeout, circuit breaker, failure injection | Open |
| Supply chain | Full-SHA action pins, dependency/SAST scan, SBOM, provenance, archive rejection | Partial: full-SHA pins and Gitleaks; dependency/SAST/SBOM open |
| Recovery | Backup restore, RPO/RTO, job recovery, rollback | Partial: PostgreSQL custom-format dump/restore smoke test passes and verifies data/RLS; RPO/RTO, queue recovery and production restore drill remain open |
| Production deployment | Configured SSH trust, actual deployment, health and end-to-end checks | Open; deployment credentials/environment not verified |

## 8. External references

- NIST SP 800-207, Zero Trust Architecture: https://csrc.nist.gov/pubs/sp/800/207/final
- OWASP API Security Top 10 (2023): https://owasp.org/www-project-api-security/
- PostgreSQL Row Security Policies: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- OWASP API1:2023 Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- PostgreSQL `SELECT ... FOR UPDATE ... SKIP LOCKED` queue-claiming semantics: https://www.postgresql.org/docs/16/sql-select.html
- AWS Prescriptive Guidance, transactional outbox pattern: https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/transactional-outbox.html
- GitHub Actions secure use and full-SHA pinning: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- Alembic migration cookbook: https://alembic.sqlalchemy.org/en/latest/cookbook.html
- Lemon Squeezy webhook signing and raw-body HMAC: https://docs.lemonsqueezy.com/help/webhooks/signing-requests
- Lemon Squeezy webhook retry behavior: https://docs.lemonsqueezy.com/help/webhooks/webhook-requests

## 9. Release decision

**Not production-ready.** Default-closed posture and security regression tests reduce immediate exposure, but tenant persistence/resource authorization, production identity configuration, governed endpoint execution, durable webhook processing, reproducible frontend, dependency/SAST coverage, backup/recovery evidence, and actual deployment verification remain release blockers.
