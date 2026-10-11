"""Integration test for PostgreSQL tenant RLS using a non-owner, non-bypass role."""
import os
import uuid

import asyncpg
import pytest


@pytest.mark.asyncio
async def test_rls_scopes_organization_and_device_rows_and_rejects_cross_tenant_write():
    dsn = os.getenv("TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("TEST_POSTGRES_DSN is not configured")

    suffix = uuid.uuid4().hex[:8]
    org_a = f"rls-a-{suffix}"
    org_b = f"rls-b-{suffix}"
    device_a = f"device-a-{suffix}"
    device_b = f"device-b-{suffix}"
    ticket_a = f"ticket-a-{suffix}"
    ticket_b = f"ticket-b-{suffix}"
    replay_a = f"replay-a-{suffix}"
    kb_a = f"kb-a-{suffix}"
    kb_b = f"kb-b-{suffix}"
    kb_draft_a = f"kb-draft-a-{suffix}"
    kb_draft_b = f"kb-draft-b-{suffix}"
    replay_b = f"replay-b-{suffix}"
    role = f"aurontra_rls_{suffix}"
    password = f"test-{suffix}-only"
    admin = await asyncpg.connect(dsn)
    app = None
    try:
        await admin.execute(f'CREATE ROLE "{role}" LOGIN PASSWORD \'{password}\' NOSUPERUSER NOBYPASSRLS')
        await admin.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')
        await admin.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON organizations, devices, tickets, durable_jobs, outbox_events, agent_request_replays, remediation_intents, telemetry_records, knowledge_articles TO "{role}"')
        await admin.execute(
            "INSERT INTO organizations (id, name, status) VALUES ($1, $1, 'active'), ($2, $2, 'active')",
            org_a, org_b,
        )
        await admin.execute(
            "INSERT INTO knowledge_articles (id, org_id, article_key, slug, title, category, content, content_sha256, status, version, approved_by, approved_at) "
            "VALUES ($1, $2, $3, $4, 'A approved', 'connectivity', 'a', repeat('a', 64), 'published', 1, 'admin', now()), "
            "($5, $6, $7, $8, 'B approved', 'connectivity', 'b', repeat('b', 64), 'published', 1, 'admin', now())",
            kb_a, org_a, kb_a, kb_a, kb_b, org_b, kb_b, kb_b,
        )
        await admin.execute(
            "INSERT INTO knowledge_articles (id, org_id, article_key, slug, title, category, content, content_sha256, status, version) "
            "VALUES ($1, $2, $3, $4, 'A draft', 'connectivity', 'draft-a', repeat('d', 64), 'draft', 1), "
            "($5, $6, $7, $8, 'B draft', 'connectivity', 'draft-b', repeat('e', 64), 'draft', 1)",
            kb_draft_a, org_a, kb_draft_a, kb_draft_a, kb_draft_b, org_b, kb_draft_b, kb_draft_b,
        )
        await admin.execute(
            "INSERT INTO devices (id, org_id, name) VALUES ($1, $2, $1), ($3, $4, $3)",
            device_a, org_a, device_b, org_b,
        )
        await admin.execute(
            "INSERT INTO tickets (id, org_id, title, description, reporter_email, status, priority, source) "
            "VALUES ($1, $2, 'A tenant ticket', 'private', 'a@example.invalid', 'OPEN', 'MEDIUM', 'MANUAL'), "
            "($3, $4, 'B tenant ticket', 'private', 'b@example.invalid', 'OPEN', 'MEDIUM', 'MANUAL')",
            ticket_a, org_a, ticket_b, org_b,
        )
        await admin.execute(
            "INSERT INTO durable_jobs (id, org_id, job_type, schema_version, idempotency_key, payload, status, attempts, max_attempts, result_metadata) "
            "VALUES ($1, $2, 'test.job', '1', $3, '{}'::jsonb, 'pending', 0, 3, '{}'::jsonb), "
            "($4, $5, 'test.job', '1', $6, '{}'::jsonb, 'pending', 0, 3, '{}'::jsonb)",
            f"job-a-{suffix}", org_a, f"job-a-{suffix}", f"job-b-{suffix}", org_b, f"job-b-{suffix}",
        )
        await admin.execute(
            "INSERT INTO outbox_events (id, org_id, aggregate_type, aggregate_id, event_type, schema_version, idempotency_key, payload, status, attempts) "
            "VALUES ($1, $2, 'ticket', $1, 'ticket.created', '1', $3, '{}'::jsonb, 'pending', 0), "
            "($4, $5, 'ticket', $4, 'ticket.created', '1', $6, '{}'::jsonb, 'pending', 0)",
            f"event-a-{suffix}", org_a, f"event-a-{suffix}", f"event-b-{suffix}", org_b, f"event-b-{suffix}",
        )
        await admin.execute(
            "INSERT INTO agent_request_replays (jti, org_id, device_id, request_hash, expires_at) "
            "VALUES ($1, $2, $3, $4, now() + interval '5 minutes'), "
            "($5, $6, $7, $8, now() + interval '5 minutes')",
            replay_a, org_a, device_a, "a" * 64, replay_b, org_b, device_b, "b" * 64,
        )
        await admin.execute(
            "INSERT INTO telemetry_records (id, org_id, device_id, event_id, schema_version, source, key_thumbprint, proof_jti, request_id, request_hash, payload_hash, observed_at, received_at, metrics, missing_metrics, quality_flags, computed_score, score_components, score_status, retention_expires_at) "
            "VALUES ($1, $2, $3, $1, '1', 'endpoint_agent', 'thumb-a', $4, 'req-a', $5, $5, now(), now(), '{}'::jsonb, '[]'::jsonb, '[]'::jsonb, 90, '{}'::jsonb, 'ok', now() + interval '90 days'), "
            "($6, $7, $8, $6, '1', 'endpoint_agent', 'thumb-b', $9, 'req-b', $10, $10, now(), now(), '{}'::jsonb, '[]'::jsonb, '[]'::jsonb, 80, '{}'::jsonb, 'ok', now() + interval '90 days')",
            f"telemetry-a-{suffix}", org_a, device_a, f"proof-a-{suffix}", "a" * 64,
            f"telemetry-b-{suffix}", org_b, device_b, f"proof-b-{suffix}", "b" * 64,
        )
        await admin.execute(
            "INSERT INTO remediation_intents (id, org_id, device_id, plan_id, idempotency_key, playbook, source_evidence_id, plan_payload, status, version, platform_evidence_ids, audit_event_ids, postcondition_evidence_ids, result_metadata) "
            "VALUES ($1, $2, $3, $1, $4, 'high_cpu', 'evidence-a', '{}'::jsonb, 'proposed', 0, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '{}'::jsonb), "
            "($5, $6, $7, $5, $8, 'high_cpu', 'evidence-b', '{}'::jsonb, 'proposed', 0, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '{}'::jsonb)",
            f"intent-a-{suffix}", org_a, device_a, f"remediation:intent-a-{suffix}",
            f"intent-b-{suffix}", org_b, device_b, f"remediation:intent-b-{suffix}",
        )

        app_dsn = dsn.replace("postgresql://postgres:postgres@", f"postgresql://{role}:{password}@")
        app = await asyncpg.connect(app_dsn)
        await app.execute("SELECT set_config('app.current_org_id', $1, false)", org_a)

        visible_devices = await app.fetch("SELECT id FROM devices ORDER BY id")
        assert [row["id"] for row in visible_devices] == [device_a]
        visible_orgs = await app.fetch("SELECT id FROM organizations")
        assert [row["id"] for row in visible_orgs] == [org_a]
        visible_tickets = await app.fetch("SELECT id FROM tickets ORDER BY id")
        assert [row["id"] for row in visible_tickets] == [ticket_a]
        visible_jobs = await app.fetch("SELECT id FROM durable_jobs")
        assert [row["id"] for row in visible_jobs] == [f"job-a-{suffix}"]
        visible_outbox = await app.fetch("SELECT id FROM outbox_events")
        assert [row["id"] for row in visible_outbox] == [f"event-a-{suffix}"]
        visible_replays = await app.fetch("SELECT jti FROM agent_request_replays")
        assert [row["jti"] for row in visible_replays] == [replay_a]
        visible_intents = await app.fetch("SELECT id FROM remediation_intents")
        assert [row["id"] for row in visible_intents] == [f"intent-a-{suffix}"]
        visible_telemetry = await app.fetch("SELECT id FROM telemetry_records")
        assert [row["id"] for row in visible_telemetry] == [f"telemetry-a-{suffix}"]
        visible_knowledge = await app.fetch("SELECT id FROM knowledge_articles ORDER BY id")
        assert [row["id"] for row in visible_knowledge] == [kb_a, kb_draft_a]

        await app.execute("SELECT set_config('app.current_org_id', '', false)")
        assert await app.fetch("SELECT id FROM devices") == []
        assert await app.fetch("SELECT id FROM tickets") == []
        assert await app.fetch("SELECT id FROM durable_jobs") == []
        assert await app.fetch("SELECT id FROM outbox_events") == []
        assert await app.fetch("SELECT jti FROM agent_request_replays") == []
        assert await app.fetch("SELECT id FROM remediation_intents") == []
        assert await app.fetch("SELECT id FROM telemetry_records") == []
        assert await app.fetch("SELECT id FROM knowledge_articles") == []

        await app.execute("SELECT set_config('app.current_org_id', $1, false)", org_a)
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app.execute(
                "INSERT INTO devices (id, org_id, name) VALUES ($1, $2, $3)",
                f"forbidden-{suffix}", org_b, "cross-tenant-write",
            )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app.execute(
                "INSERT INTO knowledge_articles (id, org_id, article_key, slug, title, category, content, content_sha256, status, version, approved_by, approved_at) "
                "VALUES ($1, $2, $3, $4, 'self-approved', 'connectivity', 'unsafe', repeat('c', 64), 'published', 1, 'tenant-user', now())",
                f"forbidden-kb-{suffix}", org_a, f"forbidden-kb-{suffix}", f"forbidden-kb-{suffix}",
            )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app.execute(
                "UPDATE knowledge_articles SET status='published', approved_by='tenant-user', approved_at=now() WHERE id=$1",
                kb_draft_a,
            )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app.execute(
                "INSERT INTO tickets (id, org_id, title, description, reporter_email, status, priority, source) "
                "VALUES ($1, $2, 'forbidden', 'cross-tenant', 'x@example.invalid', 'OPEN', 'MEDIUM', 'MANUAL')",
                f"forbidden-ticket-{suffix}", org_b,
            )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app.execute(
                "INSERT INTO durable_jobs (id, org_id, job_type, schema_version, idempotency_key, payload, status, attempts, max_attempts, result_metadata) "
                "VALUES ($1, $2, 'forbidden', '1', $1, '{}'::jsonb, 'pending', 0, 3, '{}'::jsonb)",
                f"forbidden-job-{suffix}", org_b,
            )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app.execute(
                "INSERT INTO outbox_events (id, org_id, aggregate_type, aggregate_id, event_type, schema_version, idempotency_key, payload, status, attempts) "
                "VALUES ($1, $2, 'ticket', $1, 'ticket.created', '1', $1, '{}'::jsonb, 'pending', 0)",
                f"forbidden-event-{suffix}", org_b,
            )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app.execute(
                "INSERT INTO agent_request_replays (jti, org_id, device_id, request_hash, expires_at) "
                "VALUES ($1, $2, $3, $4, now() + interval '5 minutes')",
                f"forbidden-replay-{suffix}", org_b, device_b, "c" * 64,
            )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app.execute(
                "INSERT INTO telemetry_records (id, org_id, device_id, event_id, schema_version, source, key_thumbprint, proof_jti, request_id, request_hash, payload_hash, observed_at, received_at, metrics, missing_metrics, quality_flags, computed_score, score_components, score_status, retention_expires_at) "
                "VALUES ($1, $2, $3, $1, '1', 'endpoint_agent', 'thumb', $4, 'req', $5, $5, now(), now(), '{}'::jsonb, '[]'::jsonb, '[]'::jsonb, 90, '{}'::jsonb, 'ok', now() + interval '90 days')",
                f"forbidden-telemetry-{suffix}", org_b, device_b, f"proof-forbidden-{suffix}", "c" * 64,
            )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app.execute(
                "INSERT INTO remediation_intents (id, org_id, device_id, plan_id, idempotency_key, playbook, source_evidence_id, plan_payload, status, version, platform_evidence_ids, audit_event_ids, postcondition_evidence_ids, result_metadata) "
                "VALUES ($1, $2, $3, $1, $1, 'high_cpu', 'evidence', '{}'::jsonb, 'proposed', 0, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '{}'::jsonb)",
                f"forbidden-intent-{suffix}", org_b, device_b,
            )
    finally:
        if app is not None:
            await app.close()
        await admin.execute(f'DROP OWNED BY "{role}"') if role else None
        await admin.execute(f'DROP ROLE IF EXISTS "{role}"')
        await admin.close()
