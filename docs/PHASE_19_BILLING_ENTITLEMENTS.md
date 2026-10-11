# Phase 19 — Billing Webhook Durability and Entitlement Safety

**Status:** Implementation candidate; acceptance requires exact-SHA CI/security validation and provider contract review.
**Scope:** Replace process-local webhook state with durable, idempotent inbox processing while preserving fail-closed entitlement semantics.

## Implemented

- Removed the in-memory subscription list and fake subscription activation response.
- Persisted authenticated Lemon Squeezy deliveries through the existing unique provider/event ID webhook ledger.
- Derived a stable event key from the SHA-256 digest of the exact raw payload because the provider envelope does not expose a universal delivery ID.
- Enforced payload size limits, strict envelope validation, HMAC verification before parsing/processing, bounded event/object identifiers, and sanitized logs.
- Added duplicate-delivery, invalid-signature, and unknown-event regression tests.
- Marked price estimates as quotes only. The endpoint does not create checkout sessions.
- Kept checkout and entitlement grants disabled: a provider-signed payload alone is not proof of an authorized tenant's purchase.

## Security and correctness properties

1. Invalid signatures do not write an event.
2. Exact retries produce one durable ledger row and a replay response.
3. Unknown signed events are recorded as ignored, not dispatched.
4. The event ledger stores only event name, provider object ID, and a digest; it does not persist raw provider payloads, emails, or payment data.
5. No entitlement is granted from caller-controlled organization IDs or provider metadata alone.
6. Checkout continues to return 503 until a verified tenant-bound checkout intent, provider session creation, and reconciliation are implemented and tested.

## Acceptance and remaining gates

- [ ] Frontend and backend workflows pass on the exact candidate SHA.
- [ ] PostgreSQL migration/RLS/restore and secret/archive/history scans pass.
- [ ] Provider sandbox checkout and signed event delivery are exercised using non-production credentials.
- [ ] Server-created checkout intents are bound to the authenticated tenant and provider checkout/session IDs.
- [ ] Subscription state transitions are reconciled idempotently, including out-of-order events, cancellation, expiry, refunds, and replay.
- [ ] Entitlements are derived from durable reconciled state and enforced server-side; frontend state is never authoritative.
- [ ] Operational replay/reconciliation runbook and alerting are reviewed.

## Non-claims

This candidate does not activate paid subscriptions, create provider checkout sessions, or grant entitlements. No live provider credentials or sandbox account were exercised. The durable inbox is a safe foundation, not end-to-end billing certification.