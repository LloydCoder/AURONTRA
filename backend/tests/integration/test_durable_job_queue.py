"""Durable queue and transactional outbox regression tests."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from core.database import AsyncSessionLocal
from core.job_queue import (
    IdempotencyConflict,
    JobLeaseLost,
    cancel_job,
    claim_jobs,
    claim_outbox_events,
    complete_job,
    enqueue_job,
    enqueue_outbox_event,
    fail_job,
    fail_outbox_event,
    mark_outbox_published,
)
from models.durable_job import DurableJob, OutboxEvent


@pytest.mark.asyncio
async def test_enqueue_is_idempotent_per_tenant_and_rejects_key_reuse():
    async with AsyncSessionLocal() as session:
        first, created = await enqueue_job(
            session, org_id="test-tenant", job_type="ticket.classify",
            idempotency_key="ticket-123:classify", payload={"ticket_id": "ticket-123"},
        )
        duplicate, created_again = await enqueue_job(
            session, org_id="test-tenant", job_type="ticket.classify",
            idempotency_key="ticket-123:classify", payload={"ticket_id": "ticket-123"},
        )
        assert created is True
        assert created_again is False
        assert duplicate.id == first.id
        with pytest.raises(IdempotencyConflict):
            await enqueue_job(
                session, org_id="test-tenant", job_type="ticket.classify",
                idempotency_key="ticket-123:classify", payload={"ticket_id": "other-ticket"},
            )
        rows = list((await session.scalars(select(DurableJob))).all())
        assert len(rows) == 1


@pytest.mark.asyncio
async def test_job_claim_retry_and_success_lifecycle():
    async with AsyncSessionLocal() as session:
        job, created = await enqueue_job(
            session, org_id="test-tenant", job_type="report.generate",
            idempotency_key="report-1", payload={"report_id": "report-1"}, max_attempts=3,
        )
        assert created
        claimed = await claim_jobs(session, worker_id="worker-a", limit=5, lease_seconds=30)
        assert [item.id for item in claimed] == [job.id]
        assert claimed[0].status == "running"
        assert claimed[0].attempts == 1

        retry = await fail_job(
            session, job_id=job.id, org_id="test-tenant", worker_id="worker-a",
            error_code="TimeoutError: provider key=should_not_be_persisted", retry_after_seconds=1,
        )
        assert retry.status == "retry_wait"
        assert retry.last_error_code == "worker_error"
        retry.available_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.flush()

        claimed_again = await claim_jobs(session, worker_id="worker-b", limit=1, lease_seconds=30)
        assert len(claimed_again) == 1
        assert claimed_again[0].attempts == 2
        with pytest.raises(JobLeaseLost):
            await complete_job(
                session, job_id=job.id, org_id="test-tenant",
                worker_id="worker-a", result_metadata={"ok": True},
            )
        completed = await complete_job(
            session, job_id=job.id, org_id="test-tenant",
            worker_id="worker-b", result_metadata={"outcome": "verified"},
        )
        assert completed.status == "succeeded"
        assert completed.completed_at is not None
        assert completed.result_metadata == {"outcome": "verified"}


@pytest.mark.asyncio
async def test_exhausted_job_attempts_move_to_dead_letter():
    async with AsyncSessionLocal() as session:
        job, _ = await enqueue_job(
            session, org_id="test-tenant", job_type="ticket.process",
            idempotency_key="ticket-dead-letter", payload={}, max_attempts=1,
        )
        await claim_jobs(session, worker_id="worker-a", limit=1, lease_seconds=30)
        failed = await fail_job(
            session, job_id=job.id, org_id="test-tenant", worker_id="worker-a",
            error_code="upstream_unavailable",
        )
        assert failed.status == "dead_letter"
        assert failed.completed_at is not None


@pytest.mark.asyncio
async def test_pending_job_can_be_cancelled_and_is_not_claimed():
    async with AsyncSessionLocal() as session:
        job, _ = await enqueue_job(
            session, org_id="test-tenant", job_type="ticket.process",
            idempotency_key="ticket-cancel", payload={},
        )
        cancelled = await cancel_job(session, job_id=job.id, org_id="test-tenant")
        assert cancelled.status == "cancelled"
        assert await claim_jobs(session, worker_id="worker-a") == []


@pytest.mark.asyncio
async def test_job_cancellation_during_execution_is_cooperative():
    async with AsyncSessionLocal() as session:
        job, _ = await enqueue_job(
            session, org_id="test-tenant", job_type="ticket.process",
            idempotency_key="ticket-running-cancel", payload={},
        )
        await claim_jobs(session, worker_id="worker-a", limit=1, lease_seconds=30)
        requested = await cancel_job(session, job_id=job.id, org_id="test-tenant")
        assert requested.status == "running"
        assert requested.cancellation_requested_at is not None
        completed = await complete_job(
            session, job_id=job.id, org_id="test-tenant", worker_id="worker-a",
        )
        assert completed.status == "cancelled"


@pytest.mark.asyncio
async def test_outbox_is_idempotent_and_delivery_lease_is_enforced():
    async with AsyncSessionLocal() as session:
        event, created = await enqueue_outbox_event(
            session, org_id="test-tenant", aggregate_type="ticket", aggregate_id="tkt-1",
            event_type="ticket.created", idempotency_key="ticket:tkt-1:created",
            payload={"ticket_id": "tkt-1"},
        )
        duplicate, duplicate_created = await enqueue_outbox_event(
            session, org_id="test-tenant", aggregate_type="ticket", aggregate_id="tkt-1",
            event_type="ticket.created", idempotency_key="ticket:tkt-1:created",
            payload={"ticket_id": "tkt-1"},
        )
        assert created and not duplicate_created and duplicate.id == event.id
        claimed = await claim_outbox_events(session, worker_id="publisher-a", limit=5)
        assert [item.id for item in claimed] == [event.id]
        with pytest.raises(JobLeaseLost):
            await mark_outbox_published(
                session, event_id=event.id, org_id="test-tenant", worker_id="publisher-b",
            )
        published = await mark_outbox_published(
            session, event_id=event.id, org_id="test-tenant", worker_id="publisher-a",
        )
        assert published.status == "published"
        assert published.published_at is not None


@pytest.mark.asyncio
async def test_outbox_retries_then_dead_letters_without_leaking_error_text():
    async with AsyncSessionLocal() as session:
        event, _ = await enqueue_outbox_event(
            session, org_id="test-tenant", aggregate_type="ticket", aggregate_id="tkt-2",
            event_type="ticket.updated", idempotency_key="ticket:tkt-2:updated",
            payload={"ticket_id": "tkt-2"},
        )
        await claim_outbox_events(session, worker_id="publisher-a", limit=1)
        retry = await fail_outbox_event(
            session, event_id=event.id, org_id="test-tenant", worker_id="publisher-a",
            error_code="connection_timeout", retry_after_seconds=1, max_attempts=2,
        )
        assert retry.status == "pending"
        retry.available_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.flush()
        await claim_outbox_events(session, worker_id="publisher-b", limit=1)
        dead = await fail_outbox_event(
            session, event_id=event.id, org_id="test-tenant", worker_id="publisher-b",
            error_code="connection_timeout", max_attempts=2,
        )
        assert dead.status == "dead_letter"
        assert dead.last_error_code == "connection_timeout"



@pytest.mark.asyncio
async def test_domain_write_and_outbox_event_share_transaction():
    from models.ticket import Ticket, TicketPriority, TicketSource, TicketStatus

    async with AsyncSessionLocal() as session:
        ticket = Ticket(
            id="outbox-atomic-ticket",
            org_id="test-tenant",
            title="Atomic event",
            description="The outbox event must roll back with the domain write",
            reporter_email="test@example.invalid",
            source=TicketSource.MANUAL,
            priority=TicketPriority.MEDIUM,
            status=TicketStatus.OPEN,
        )
        session.add(ticket)
        await session.flush()
        await enqueue_outbox_event(
            session, org_id="test-tenant", aggregate_type="ticket",
            aggregate_id=ticket.id, event_type="ticket.created",
            idempotency_key=f"ticket:{ticket.id}:created",
            payload={"ticket_id": ticket.id},
        )
        await session.rollback()

    async with AsyncSessionLocal() as session:
        assert await session.get(Ticket, "outbox-atomic-ticket") is None
        assert await session.scalar(
            select(OutboxEvent).where(OutboxEvent.idempotency_key == "ticket:outbox-atomic-ticket:created")
        ) is None



@pytest.mark.asyncio
async def test_worker_processes_only_explicitly_registered_handlers():
    from workers.job_worker import process_job_batch

    async def echo(payload, idempotency_key):
        assert idempotency_key == "worker:echo:1"
        return {"echo": payload["value"]}

    async with AsyncSessionLocal() as session:
        await enqueue_job(
            session, org_id="test-tenant", job_type="test.echo",
            idempotency_key="worker:echo:1", payload={"value": "ok"},
        )
        await enqueue_job(
            session, org_id="test-tenant", job_type="test.not_registered",
            idempotency_key="worker:unknown:1", payload={},
        )
        await session.commit()

    result = await process_job_batch(
        session_factory=AsyncSessionLocal, worker_id="worker-batch",
        handlers={"test.echo": echo}, limit=10,
    )
    assert result == {
        "claimed": 2, "succeeded": 1,
        "retrying_or_dead_letter": 1, "unsupported": 1,
    }
    async with AsyncSessionLocal() as session:
        rows = list((await session.scalars(select(DurableJob).order_by(DurableJob.job_type))).all())
        by_type = {row.job_type: row for row in rows}
        assert by_type["test.echo"].status == "succeeded"
        assert by_type["test.echo"].result_metadata == {"echo": "ok"}
        assert by_type["test.not_registered"].status == "dead_letter"


@pytest.mark.asyncio
async def test_outbox_worker_publishes_and_records_durable_ack():
    from workers.job_worker import publish_outbox_batch

    delivered = []

    async def publisher(payload, idempotency_key):
        delivered.append((payload, idempotency_key))

    async with AsyncSessionLocal() as session:
        await enqueue_outbox_event(
            session, org_id="test-tenant", aggregate_type="ticket", aggregate_id="tkt-worker",
            event_type="ticket.created", idempotency_key="outbox:worker:1",
            payload={"ticket_id": "tkt-worker"},
        )
        await session.commit()

    result = await publish_outbox_batch(
        session_factory=AsyncSessionLocal, worker_id="outbox-worker",
        publisher=publisher, limit=10,
    )
    assert result == {"claimed": 1, "published": 1, "retrying_or_dead_letter": 0}
    assert delivered == [({"ticket_id": "tkt-worker"}, "outbox:worker:1")]
    async with AsyncSessionLocal() as session:
        event = await session.scalar(select(OutboxEvent).where(OutboxEvent.idempotency_key == "outbox:worker:1"))
        assert event.status == "published"
        assert event.published_at is not None


@pytest.mark.asyncio
async def test_expired_job_lease_can_be_reclaimed_but_old_worker_cannot_commit():
    async with AsyncSessionLocal() as session:
        job, _ = await enqueue_job(
            session, org_id="test-tenant", job_type="test.lease",
            idempotency_key="lease-recovery", payload={}, max_attempts=3,
        )
        await claim_jobs(session, worker_id="worker-old", limit=1, lease_seconds=30)
        job.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await session.flush()
        recovered = await claim_jobs(session, worker_id="worker-new", limit=1, lease_seconds=30)
        assert len(recovered) == 1
        assert recovered[0].id == job.id
        assert recovered[0].attempts == 2
        with pytest.raises(JobLeaseLost):
            await complete_job(
                session, job_id=job.id, org_id="test-tenant",
                worker_id="worker-old", result_metadata={},
            )



@pytest.mark.asyncio
async def test_queue_rejects_non_json_numbers_and_oversized_payloads():
    async with AsyncSessionLocal() as session:
        with pytest.raises(ValueError):
            await enqueue_job(
                session, org_id="test-tenant", job_type="test.invalid",
                idempotency_key="nan-payload", payload={"metric": float("nan")},
            )
        with pytest.raises(ValueError, match="64 KiB"):
            await enqueue_job(
                session, org_id="test-tenant", job_type="test.oversized",
                idempotency_key="large-payload", payload={"body": "x" * 70000},
            )
        with pytest.raises(ValueError, match="64 KiB"):
            await enqueue_outbox_event(
                session, org_id="test-tenant", aggregate_type="ticket",
                aggregate_id="tkt-large", event_type="ticket.created",
                idempotency_key="large-outbox-payload", payload={"body": "x" * 70000},
            )

@pytest.mark.asyncio
async def test_tenant_aware_worker_passes_authoritative_org_from_job_row():
    from workers.job_worker import process_job_batch

    observed = []

    async def tenant_handler(payload, idempotency_key, trusted_org_id):
        observed.append((payload.get("org_id"), trusted_org_id, idempotency_key))
        return {"trusted_tenant": trusted_org_id}

    async with AsyncSessionLocal() as session:
        job, _ = await enqueue_job(
            session, org_id="test-tenant", job_type="tenant.echo",
            idempotency_key="tenant-echo-1",
            payload={"org_id": "attacker-controlled-value", "value": "ok"},
        )
        await session.commit()

    result = await process_job_batch(
        session_factory=AsyncSessionLocal,
        worker_id="tenant-aware-worker",
        handlers={"tenant.echo": tenant_handler},
        tenant_aware_handlers=frozenset({"tenant.echo"}),
    )
    assert result["succeeded"] == 1
    assert observed == [("attacker-controlled-value", "test-tenant", "tenant-echo-1")]
