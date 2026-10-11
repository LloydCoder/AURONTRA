# Phase 14 — AI Service Desk and Tenant-Scoped Knowledge Retrieval

**Status:** Complete at code/CI level after forensic audit. This phase is not a production certification.
**Owner:** Tinlance Limited / Aurontra
**System boundary:** Aurontra consumes the Tinlance Agent System; it does not duplicate Platform identity, authorization, approval, execution, secrets, or audit authority.

## Objective

Turn the legacy ticket resolver into a risk-based drafting assistant backed by approved, tenant-scoped knowledge. The system may propose a response, but only a human or a separately verified workflow can mark the underlying ticket resolved.

## Security and behavior requirements

1. **Draft-only semantics.** The resolver always reports `resolved=false` and `outcome_verified=false`. A draft cannot change a ticket to resolved or closed.
2. **Conservative triage.** Security incidents, infrastructure/data-loss signals, empty input, and unknown categories escalate. Known low-risk categories may receive a suggestion; heuristic confidence is explicitly not a calibrated probability.
3. **Prompt-injection containment.** Ticket fields and article excerpts are serialized as untrusted JSON data. System instructions explicitly forbid treating those fields as instructions. This is defense-in-depth, not a claim that prompt injection can be eliminated by prompting alone.
4. **Data minimization.** Reporter email is not sent to the model. Common email addresses, phone numbers, bearer tokens and credential assignments are redacted before model submission and again in generated output. Ticket and article inputs are bounded.
5. **Bounded inference.** Provider calls have a configurable timeout; timeouts, provider failures, offline fallback, malformed output and empty output produce a human-review state. Provider exception contents are not written to logs.
6. **Output constraints.** Model output is type-checked, bounded, stripped of markup/control characters and never treated as executable HTML, code or an instruction to an action runner.
7. **Approved retrieval only.** Retrieval returns only published articles with approval metadata, restricted to the authenticated tenant or explicitly global content. Candidate count, result count and excerpt length are bounded. Content SHA-256 is verified before use; a mismatch fails closed.
8. **Knowledge publication boundary.** Tenant RLS permits tenant users to insert/update/delete drafts only. Published content is read-only to the tenant role; self-publication and spoofed approval metadata are denied. Global article publication belongs to a separately controlled administrative process.
9. **Provenance.** Persist prompt version/digest, response digest, generation time, retrieved article IDs/versions/digests, triage category/tier/confidence semantics, and explicit escalation reason on the ticket. A timeout or triage escalation must not be misreported as a model invocation. Hashes provide integrity references, not proof that model content is correct.
10. **Tenant isolation.** Retrieval always requires a verified tenant ID and uses explicit organization predicates in addition to PostgreSQL RLS. No cross-tenant article content may enter a prompt.

## Implementation

- `backend/agents/ticket_resolver.py`: deterministic risk triage, bounded/redacted prompt construction, safe response validation, timeout/fallback handling and draft-only result contract.
- `backend/knowledge/retrieval.py`: tenant/global published-article retrieval, deterministic lexical ranking, content-digest validation and safe source URL filtering.
- `backend/models/knowledge_article.py`: versioned knowledge article record with approval metadata, status, tenant scope and content digest.
- `backend/models/ticket.py` and Alembic revision `0008_ticket_ai_knowledge`: durable suggestion, triage, escalation and knowledge-reference provenance.
- `backend/api/routes/tickets.py`: retrieves approved references, refuses model invocation on knowledge-integrity failure, and persists suggestion provenance without resolving the ticket.
- CI adds tenant-RLS assertions for published knowledge visibility, cross-tenant denial, tenant self-publication denial and backup/restore preservation of the table's RLS policies.

## Verification results

- Unit tests for triage, unknown-case escalation, prompt-injection boundaries, PII/secret redaction, timeout, invalid/empty provider responses, output bounds, offline fallback and draft-only semantics.
- Retrieval tests for tenant scoping, global published content, draft exclusion, integrity failure, invalid tenant/limit and source URL safety.
- Route tests for persisted prompt/response/reference provenance and fail-closed behavior when a stored article digest is invalid.
- SQLite Alembic upgrade, Python compilation, full backend suite with coverage, PostgreSQL non-owner RLS tests, backup/restore policy checks, and current-tree/history/archive secret scan.
- Forensic review recorded in [Phase 14 audit](audits/PHASE_14_FORENSIC_AUDIT.md). CI and secret/history/archive scan passed on the reviewed commit.

## Research basis

- OWASP API Security Top 10 (2023), particularly broken object-level authorization, broken authentication, security misconfiguration, SSRF and unsafe API consumption: https://api-security.owasp.org/editions/2023/en/0x11-t10/
- NIST Secure Software Development Framework (SP 800-218) for integrating security practices throughout design, implementation, verification and release: https://csrc.nist.gov/pubs/sp/800/218/final
- NIST AI Risk Management Framework for documenting model limitations, measurement and risk treatment: https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf
- Scikit-learn model evaluation guidance for separating measured test behavior from production-quality claims: https://scikit-learn.org/stable/modules/model_evaluation.html

## Explicit non-claims

This phase does not provide semantic/vector retrieval, a curated production knowledge corpus, a calibrated triage model, autonomous remediation, guaranteed prompt-injection immunity, or evidence that generated suggestions fix customer issues. Knowledge retrieval is deterministic lexical ranking over approved records. Production LLM provider configuration and production data-plane release remain separate gates.
