# Phase 14 Forensic Audit — AI Service Desk and Tenant-Scoped Knowledge

**Phase:** 14 of 24  
**Product:** Aurontra (historical name: ResilientAI)  
**Owner:** Tinlance Limited  
**Implementation review SHA:** `a790acc92066da25b01b22fdb70ba03f0c1eb7e7`  
**Status:** Implementation audit passed at code/CI level. Production certification is explicitly not claimed.

## Executive result

Phase 14 replaces the unsafe “AI resolved the ticket” behavior with a reviewable suggestion workflow, and adds tenant-scoped, approval-aware, integrity-checked knowledge retrieval. The implementation passes the backend suite, PostgreSQL tenant RLS and backup/restore checks, SQLite migration validation, compilation and the secret/history/archive scan.

- [Implementation CI run 38116534766](https://github.com/LloydCoder/AURONTRA/actions/runs/38116534766): **433 passed, 1 skipped, 85.56% coverage**.
- [Secret/history/archive scan 38116534756](https://github.com/LloydCoder/AURONTRA/actions/runs/38116534756): passed for working tree, reachable Git history and nested archives.
- PostgreSQL migration, non-owner RLS tests and backup/restore smoke test: passed in the CI workflow.
- Deployment: **skipped** by release gating. No production deployment or live LLM provider was exercised.

## Scope inspected

- `backend/agents/ticket_resolver.py`
- `backend/knowledge/retrieval.py`
- `backend/models/knowledge_article.py`
- `backend/models/ticket.py`
- `backend/alembic/versions/0008_ticket_ai_provenance_knowledge.py` (Alembic revision ID: `0008_ticket_ai_knowledge`)
- `backend/api/routes/tickets.py`
- `backend/core/config.py`, `backend/core/llm_gateway.py`, `.env.example`
- `backend/models/__init__.py`
- `backend/tests/unit/test_ticket_resolver.py`
- `backend/tests/unit/test_knowledge_retrieval.py`
- `backend/tests/integration/test_ticket_ai_provenance.py`
- `backend/tests/integration/test_tenant_rls.py`
- `.github/workflows/ci.yml`
- `README.md`, `docs/ROADMAP.md`, `docs/PHASE_14_AI_SERVICE_DESK.md`

## Findings and dispositions

### F14-01 — False resolution claims

**Finding:** Model-generated text is not proof that an IT issue was fixed.  
**Disposition:** Fixed. The resolver always returns `resolved=false` and `outcome_verified=false`; the API does not close a ticket on the strength of a generated answer. Low-risk suggestions leave the ticket open. High-impact or unknown cases are escalated.

### F14-02 — Unsafe triage default

**Finding:** Unknown tickets were previously treated as low-risk and eligible for automatic resolution.  
**Disposition:** Fixed. Security, infrastructure/data-loss and unrecognized cases fail closed to human review. Low-risk categories are eligible only for a draft. Confidence is labelled as a heuristic, not a calibrated probability.

### F14-03 — PII and credential exposure to model providers

**Finding:** Reporter email and sensitive values in ticket text could be unnecessarily passed to an external provider or repeated in its response.  
**Disposition:** Mitigated. Reporter email is omitted from the prompt; common email, phone, bearer-token and credential-assignment patterns are redacted on input and output; inputs and outputs are bounded. Regex-based redaction is not exhaustive and must not be described as complete PII removal.

### F14-04 — Prompt injection and untrusted knowledge

**Finding:** Ticket content and knowledge excerpts can contain adversarial instructions.  
**Disposition:** Mitigated through a fixed system prompt, canonical JSON serialization into explicitly untrusted fields, model-boundary content-digest validation, and human-review-only semantics. This is defense-in-depth; it does not guarantee prompt-injection immunity.

### F14-05 — Unbounded inference and malformed output

**Finding:** Provider latency, provider errors, empty output and malformed responses could cause unsafe or unbounded behavior.  
**Disposition:** Fixed at the application boundary. Calls are deadline-bounded, provider exception contents are not logged, responses are type-checked and length-bounded, markup/control characters are stripped, common secrets are redacted, and failures produce a human-review result. The combined prompt digest covers both system and user prompts.

### F14-06 — Cross-tenant knowledge leakage and unapproved content

**Finding:** A published-status flag alone is not sufficient evidence of approval or tenant scope.  
**Disposition:** Fixed at multiple layers. Retrieval explicitly filters for the current tenant or global content, published status and non-null approval metadata; content digests are verified with constant-time comparison; PostgreSQL RLS restricts tenant visibility; the database requires non-empty approval metadata for published rows. Tenant users can access their own drafts but cannot self-publish, spoof approval metadata, or modify published rows. Global content is only visible with a verified tenant context.

### F14-07 — Unbounded knowledge payloads

**Finding:** Large article bodies and candidate sets could inflate request memory and model payloads.  
**Disposition:** Mitigated. Article content is database-bounded, retrieval candidates are capped, result count is bounded, excerpts are bounded, and the serialized prompt is reduced while preserving valid JSON under the configured character budget.

### F14-08 — Incomplete AI provenance

**Finding:** A returned answer without durable provenance cannot reliably show what instructions, knowledge version or triage decision produced it; a timeout reason must not be misrepresented as a model name.  
**Disposition:** Fixed. Tickets persist prompt version and combined system/user prompt digest, response digest, generation time, article IDs/versions/content digests, triage category/tier/confidence semantics, actual model metadata when available, and explicit escalation reason. Hashes establish a content reference, not correctness or outcome verification.

### F14-09 — Migration revision incompatibility

**Finding:** The initial Alembic revision identifier exceeded PostgreSQL's `alembic_version.version_num` column limit.  
**Disposition:** Fixed before acceptance. Revision identifier shortened to `0008_ticket_ai_knowledge`; clean SQLite migration and PostgreSQL migration passed.

### F14-10 — Test isolation and database-policy gaps

**Finding:** Initial regression tests exposed an incorrect async mock context manager, missing parent-organization fixture commit, and missing assertions for draft/global knowledge policy.  
**Disposition:** Fixed. Tests use synchronous `patch` context managers, persist fixture organizations before article insertion, validate global and same-tenant visibility, reject cross-tenant rows, deny self-publication, and verify backup/restore preserves RLS.

## Verification evidence

| Gate | Result |
|---|---|
| Clean SQLite Alembic upgrade | Pass |
| Python backend compilation | Pass |
| Backend suite | 433 passed, 1 skipped |
| Coverage | 85.56% |
| PostgreSQL migration | Pass |
| Non-owner PostgreSQL RLS tests | Pass |
| PostgreSQL backup/restore policy check | Pass |
| Working-tree/history/nested-archive scan | Pass |
| Production deployment | Skipped — not claimed |

The one skipped test is the PostgreSQL RLS test when running inside the SQLite-oriented full suite; it is separately exercised by the PostgreSQL workflow and passed there.

## Residual risks and release gates

1. The production data plane remains disabled. A passing PR workflow does not establish a deployed, healthy runtime.
2. No live LLM provider call, production credentials, customer tenant or curated production knowledge corpus was exercised.
3. Retrieval is deterministic lexical ranking, not semantic/vector search. Relevance quality has not been measured on a representative corpus.
4. No production knowledge-authoring or approval UI/API is implemented. The schema and RLS define the safety boundary; global publication still requires a separately controlled administrative process.
5. Regex redaction cannot guarantee removal of every secret or personal identifier. Human review remains mandatory.
6. A suggestion never proves remediation. Ticket closure must be tied to a separate, authorized and independently verified outcome.
7. Broader compliance evidence, retention/DSAR policy, SLOs, live integration contracts and production release evidence remain in later phases.

## Research and architecture basis

- [OWASP API Security Top 10 (2023)](https://api-security.owasp.org/editions/2023/en/0x11-t10/) — object-level authorization, authentication, security misconfiguration, SSRF and unsafe API consumption.
- [NIST Secure Software Development Framework, SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) — security integrated into design, implementation, verification and release.
- [NIST AI Risk Management Framework](https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf) — explicit model limitations, measurement and risk treatment.
- [Scikit-learn model evaluation guidance](https://scikit-learn.org/stable/modules/model_evaluation.html) — separate measured test behavior from unsupported quality claims.

## Final determination

**Phase 14 is accepted at code/CI level.** No claim is made that Aurontra is production-certified or that generated AI drafts resolve customer issues. Phase 15 may begin only after this phase's documentation reconciliation commit also passes CI and the secret/history/archive scan.
