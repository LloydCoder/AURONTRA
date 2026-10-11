"""Transactional durable work queue primitives.

This module does not execute jobs. Consumers must validate the registered job
type, re-check tenant/resource authorization, and submit consequential actions
through the Tinlance Agent Platform. Delivery is at-least-once, never exactly-once.
"""
import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from models.durable_job import DurableJob, OutboxEvent


class IdempotencyConflict(ValueError):
    """An idempotency key was reused for a semantically different operation."""


class JobLeaseLost(RuntimeError):
    """A worker tried to mutate a job it no longer owns."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _safe_error_code(value: str) -> str:
    # Persist stable machine-readable codes, never exception messages, prompts,
    # tokens, ticket text, URLs or other potentially sensitive provider output.
    normalized = re.sub(r"[^a-zA-Z0-9_.-]", "_", value)[:100]
    return normalized or "worker_error"


async def enqueue_job(
    session: AsyncSession,
    *,
    org_id: str,
    job_type: str,
    idempotency_key: str,
    payload: dict,
    max_attempts: int = 5,
    available_at: datetime | None = None,
    schema_version: str = "1",
) -> tuple[DurableJob, bool]:
    """Insert once per tenant/key; return (job, created)."""
    if not org_id or len(org_id) > 64:
        raise ValueError("org_id is required and must be <= 64 characters")
    if not job_type or len(job_type) > 160:
        raise ValueError("job_type is required and must be <= 160 characters")
    if not idempotency_key or len(idempotency_key) > 255:
        raise ValueError("idempotency_key is required and must be <= 255 characters")
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    if not 1 <= max_attempts <= 25:
        raise ValueError("max_attempts must be between 1 and 25")
    # Fail early for non-JSON values and prevent accidental secret fields from
    # being silently stringified by a serializer.
    _canonical_hash(payload)

    stmt = select(DurableJob).where(
        DurableJob.org_id == org_id,
        DurableJob.idempotency_key == idempotency_key,
    )
    existing = await session.scalar(stmt)
    if existing:
        same = (
            existing.job_type == job_type
            and existing.schema_version == schema_version
            and _canonical_hash(existing.payload) == _canonical_hash(payload)
        )
        if not same:
            raise IdempotencyConflict("Idempotency key already belongs to a different job.")
        return existing, False

    job = DurableJob(
        id=f"job-{uuid.uuid4().hex}",
        org_id=org_id,
        job_type=job_type,
        schema_version=schema_version,
        idempotency_key=idempotency_key,
        payload=payload,
        status="pending",
        attempts=0,
        max_attempts=max_attempts,
        available_at=available_at or _now(),
        result_metadata={},
    )
    # Savepoint keeps a duplicate-key race from invalidating the caller's
    # surrounding business transaction.
    try:
        async with session.begin_nested():
            session.add(job)
            await session.flush()
    except IntegrityError:
        existing = await session.scalar(stmt)
        if existing and existing.job_type == job_type and existing.schema_version == schema_version and _canonical_hash(existing.payload) == _canonical_hash(payload):
            return existing, False
        raise IdempotencyConflict("Idempotency key already exists with different job content.")
    return job, True


async def claim_jobs(
    session: AsyncSession,
    *,
    worker_id: str,
    limit: int = 10,
    lease_seconds: int = 60,
) -> list[DurableJob]:
    """Atomically lease ready jobs; PostgreSQL uses SKIP LOCKED for concurrency."""
    if not worker_id or len(worker_id) > 255:
        raise ValueError("worker_id is required and must be <= 255 characters")
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not 5 <= lease_seconds <= 3600:
        raise ValueError("lease_seconds must be between 5 and 3600")
    now = _now()
    # A worker may crash after consuming its final attempt. Reap that expired
    # lease into the dead-letter state rather than leaving it running forever.
    await session.execute(
        update(DurableJob)
        .where(
            DurableJob.status == "running",
            DurableJob.lease_expires_at <= now,
            DurableJob.attempts >= DurableJob.max_attempts,
        )
        .values(
            status="dead_letter",
            lease_owner=None,
            lease_expires_at=None,
            last_error_code="lease_expired_max_attempts",
            completed_at=now,
            updated_at=now,
        )
    )
    ready = or_(
        DurableJob.status.in_(["pending", "retry_wait"]),
        and_(DurableJob.status == "running", DurableJob.lease_expires_at <= now),
    )
    statement = (
        select(DurableJob)
        .where(ready, DurableJob.available_at <= now, DurableJob.attempts < DurableJob.max_attempts)
        .order_by(DurableJob.available_at, DurableJob.created_at, DurableJob.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    jobs = list((await session.scalars(statement)).all())
    for job in jobs:
        job.status = "running"
        job.attempts += 1
        job.lease_owner = worker_id
        job.lease_expires_at = now + timedelta(seconds=lease_seconds)
        job.started_at = job.started_at or now
        job.updated_at = now
    await session.flush()
    return jobs


def _assert_lease(job: DurableJob, worker_id: str, now: datetime) -> None:
    if job.status != "running" or job.lease_owner != worker_id:
        raise JobLeaseLost("Worker does not own the active job lease.")
    if job.lease_expires_at is None or job.lease_expires_at <= now:
        raise JobLeaseLost("Job lease expired; worker must not commit a result.")


async def complete_job(
    session: AsyncSession,
    *,
    job_id: str,
    org_id: str,
    worker_id: str,
    result_metadata: dict | None = None,
) -> DurableJob:
    now = _now()
    job = await session.scalar(
        select(DurableJob).where(DurableJob.id == job_id, DurableJob.org_id == org_id).with_for_update()
    )
    if job is None:
        raise LookupError("Job not found.")
    _assert_lease(job, worker_id, now)
    if job.cancellation_requested_at is not None:
        job.status = "cancelled"
    else:
        job.status = "succeeded"
        job.result_metadata = result_metadata or {}
    job.completed_at = now
    job.lease_owner = None
    job.lease_expires_at = None
    job.updated_at = now
    await session.flush()
    return job


async def fail_job(
    session: AsyncSession,
    *,
    job_id: str,
    org_id: str,
    worker_id: str,
    error_code: str = "worker_error",
    retry_after_seconds: int | None = None,
) -> DurableJob:
    now = _now()
    job = await session.scalar(
        select(DurableJob).where(DurableJob.id == job_id, DurableJob.org_id == org_id).with_for_update()
    )
    if job is None:
        raise LookupError("Job not found.")
    _assert_lease(job, worker_id, now)
    job.last_error_code = _safe_error_code(error_code)
    job.lease_owner = None
    job.lease_expires_at = None
    job.updated_at = now
    if job.cancellation_requested_at is not None:
        job.status = "cancelled"
        job.completed_at = now
    elif job.attempts >= job.max_attempts:
        job.status = "dead_letter"
        job.completed_at = now
    else:
        delay = retry_after_seconds
        if delay is None:
            delay = min(3600, 2 ** min(job.attempts, 10))
        if not 1 <= delay <= 86400:
            raise ValueError("retry_after_seconds must be between 1 and 86400")
        job.status = "retry_wait"
        job.available_at = now + timedelta(seconds=delay)
    await session.flush()
    return job


async def cancel_job(
    session: AsyncSession, *, job_id: str, org_id: str
) -> DurableJob:
    """Tenant-scoped cancellation; running jobs receive a cooperative cancel request."""
    job = await session.scalar(
        select(DurableJob).where(DurableJob.id == job_id, DurableJob.org_id == org_id).with_for_update()
    )
    if job is None:
        raise LookupError("Job not found.")
    if job.status in {"succeeded", "failed", "dead_letter", "cancelled"}:
        return job
    now = _now()
    if job.status == "running":
        job.cancellation_requested_at = now
    else:
        job.status = "cancelled"
        job.completed_at = now
    job.updated_at = now
    await session.flush()
    return job


async def enqueue_outbox_event(
    session: AsyncSession,
    *,
    org_id: str,
    aggregate_type: str,
    aggregate_id: str,
    event_type: str,
    idempotency_key: str,
    payload: dict,
    schema_version: str = "1",
) -> tuple[OutboxEvent, bool]:
    """Persist an event in the same caller-owned transaction as its domain change."""
    if not all((org_id, aggregate_type, aggregate_id, event_type, idempotency_key)):
        raise ValueError("org, aggregate, event type and idempotency key are required")
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    _canonical_hash(payload)
    stmt = select(OutboxEvent).where(
        OutboxEvent.org_id == org_id,
        OutboxEvent.idempotency_key == idempotency_key,
    )
    existing = await session.scalar(stmt)
    if existing:
        same = (
            existing.aggregate_type == aggregate_type
            and existing.aggregate_id == aggregate_id
            and existing.event_type == event_type
            and existing.schema_version == schema_version
            and _canonical_hash(existing.payload) == _canonical_hash(payload)
        )
        if not same:
            raise IdempotencyConflict("Idempotency key already belongs to a different event.")
        return existing, False
    event = OutboxEvent(
        id=f"evt-{uuid.uuid4().hex}",
        org_id=org_id,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        event_type=event_type,
        schema_version=schema_version,
        idempotency_key=idempotency_key,
        payload=payload,
        status="pending",
        attempts=0,
    )
    try:
        async with session.begin_nested():
            session.add(event)
            await session.flush()
    except IntegrityError:
        existing = await session.scalar(stmt)
        if existing and existing.aggregate_type == aggregate_type and existing.aggregate_id == aggregate_id and existing.event_type == event_type and existing.schema_version == schema_version and _canonical_hash(existing.payload) == _canonical_hash(payload):
            return existing, False
        raise IdempotencyConflict("Idempotency key already exists with different event content.")
    return event, True



async def claim_outbox_events(
    session: AsyncSession,
    *,
    worker_id: str,
    limit: int = 50,
    lease_seconds: int = 60,
) -> list[OutboxEvent]:
    """Lease pending events for at-least-once publication."""
    if not worker_id or len(worker_id) > 255:
        raise ValueError("worker_id is required and must be <= 255 characters")
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    if not 5 <= lease_seconds <= 3600:
        raise ValueError("lease_seconds must be between 5 and 3600")
    now = _now()
    statement = (
        select(OutboxEvent)
        .where(
            OutboxEvent.available_at <= now,
            or_(
                OutboxEvent.status == "pending",
                and_(OutboxEvent.status == "publishing", OutboxEvent.lease_expires_at <= now),
            ),
        )
        .order_by(OutboxEvent.available_at, OutboxEvent.created_at, OutboxEvent.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    events = list((await session.scalars(statement)).all())
    for event in events:
        event.status = "publishing"
        event.attempts += 1
        event.lease_owner = worker_id
        event.lease_expires_at = now + timedelta(seconds=lease_seconds)
    await session.flush()
    return events


async def mark_outbox_published(
    session: AsyncSession,
    *,
    event_id: str,
    org_id: str,
    worker_id: str,
) -> OutboxEvent:
    now = _now()
    event = await session.scalar(
        select(OutboxEvent).where(
            OutboxEvent.id == event_id,
            OutboxEvent.org_id == org_id,
        ).with_for_update()
    )
    if event is None:
        raise LookupError("Outbox event not found.")
    if event.status != "publishing" or event.lease_owner != worker_id or not event.lease_expires_at or event.lease_expires_at <= now:
        raise JobLeaseLost("Worker does not own the active outbox lease.")
    event.status = "published"
    event.published_at = now
    event.lease_owner = None
    event.lease_expires_at = None
    event.last_error_code = None
    await session.flush()
    return event


async def fail_outbox_event(
    session: AsyncSession,
    *,
    event_id: str,
    org_id: str,
    worker_id: str,
    error_code: str = "publisher_error",
    retry_after_seconds: int | None = None,
    max_attempts: int = 10,
) -> OutboxEvent:
    now = _now()
    event = await session.scalar(
        select(OutboxEvent).where(
            OutboxEvent.id == event_id,
            OutboxEvent.org_id == org_id,
        ).with_for_update()
    )
    if event is None:
        raise LookupError("Outbox event not found.")
    if event.status != "publishing" or event.lease_owner != worker_id or not event.lease_expires_at or event.lease_expires_at <= now:
        raise JobLeaseLost("Worker does not own the active outbox lease.")
    event.last_error_code = _safe_error_code(error_code)
    event.lease_owner = None
    event.lease_expires_at = None
    if event.attempts >= max_attempts:
        event.status = "dead_letter"
    else:
        delay = retry_after_seconds if retry_after_seconds is not None else min(3600, 2 ** min(event.attempts, 10))
        if not 1 <= delay <= 86400:
            raise ValueError("retry_after_seconds must be between 1 and 86400")
        event.status = "pending"
        event.available_at = now + timedelta(seconds=delay)
    await session.flush()
    return event
