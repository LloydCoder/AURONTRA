"""Bounded worker loops for durable jobs and transactional outbox delivery.

No handler is registered by default. Callers must pass an explicit allowlist.
Handlers may not treat queued payloads or model output as execution authority;
consequential actions must be authorized by the Tinlance Agent Platform.
"""
import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.job_queue import (
    claim_jobs,
    claim_outbox_events,
    complete_job,
    fail_job,
    fail_outbox_event,
    mark_outbox_published,
)

JobHandler = Callable[[dict[str, Any], str], Awaitable[dict[str, Any] | None]]
OutboxPublisher = Callable[[dict[str, Any], str], Awaitable[None]]


def _validate_result(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("Worker result must be a JSON object.")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > 65536:
        raise ValueError("Worker result exceeds 64 KiB.")
    return value


async def process_job_batch(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    worker_id: str,
    handlers: dict[str, JobHandler],
    limit: int = 10,
    lease_seconds: int = 60,
    handler_timeout_seconds: int = 120,
) -> dict[str, int]:
    """Claim and process a bounded batch; cancellation leaves leases for recovery."""
    if not 1 <= handler_timeout_seconds <= 300:
        raise ValueError("handler_timeout_seconds must be between 1 and 300")

    async with session_factory() as session:
        jobs = await claim_jobs(
            session, worker_id=worker_id, limit=limit, lease_seconds=lease_seconds
        )
        claimed = [
            {
                "id": job.id,
                "org_id": job.org_id,
                "job_type": job.job_type,
                "payload": job.payload,
                "idempotency_key": job.idempotency_key,
            }
            for job in jobs
        ]
        await session.commit()

    counts = {"claimed": len(claimed), "succeeded": 0, "retrying_or_dead_letter": 0, "unsupported": 0}
    for item in claimed:
        handler = handlers.get(item["job_type"])
        if handler is None:
            counts["unsupported"] += 1
            async with session_factory() as session:
                await fail_job(
                    session, job_id=item["id"], org_id=item["org_id"],
                    worker_id=worker_id, error_code="unknown_job_type",
                )
                await session.commit()
            counts["retrying_or_dead_letter"] += 1
            continue
        try:
            result = await asyncio.wait_for(
                handler(item["payload"], item["idempotency_key"]),
                timeout=handler_timeout_seconds,
            )
            safe_result = _validate_result(result)
        except asyncio.TimeoutError:
            async with session_factory() as session:
                await fail_job(
                    session, job_id=item["id"], org_id=item["org_id"],
                    worker_id=worker_id, error_code="handler_timeout",
                )
                await session.commit()
            counts["retrying_or_dead_letter"] += 1
        except asyncio.CancelledError:
            # Do not falsely acknowledge a cancelled process. Lease expiry allows
            # another worker to recover it; handler side effects must be idempotent.
            raise
        except Exception:
            # Never persist exception text, which can contain secrets or customer data.
            async with session_factory() as session:
                await fail_job(
                    session, job_id=item["id"], org_id=item["org_id"],
                    worker_id=worker_id, error_code="handler_error",
                )
                await session.commit()
            counts["retrying_or_dead_letter"] += 1
        else:
            async with session_factory() as session:
                await complete_job(
                    session, job_id=item["id"], org_id=item["org_id"],
                    worker_id=worker_id, result_metadata=safe_result,
                )
                await session.commit()
            counts["succeeded"] += 1
    return counts


async def publish_outbox_batch(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    worker_id: str,
    publisher: OutboxPublisher,
    limit: int = 50,
    lease_seconds: int = 60,
    publish_timeout_seconds: int = 30,
) -> dict[str, int]:
    """Publish a bounded outbox batch at-least-once with durable retry state."""
    if not 1 <= publish_timeout_seconds <= 120:
        raise ValueError("publish_timeout_seconds must be between 1 and 120")

    async with session_factory() as session:
        events = await claim_outbox_events(
            session, worker_id=worker_id, limit=limit, lease_seconds=lease_seconds
        )
        claimed = [
            {
                "id": event.id,
                "org_id": event.org_id,
                "payload": event.payload,
                "idempotency_key": event.idempotency_key,
            }
            for event in events
        ]
        await session.commit()

    counts = {"claimed": len(claimed), "published": 0, "retrying_or_dead_letter": 0}
    for item in claimed:
        try:
            await asyncio.wait_for(
                publisher(item["payload"], item["idempotency_key"]),
                timeout=publish_timeout_seconds,
            )
        except asyncio.TimeoutError:
            async with session_factory() as session:
                await fail_outbox_event(
                    session, event_id=item["id"], org_id=item["org_id"],
                    worker_id=worker_id, error_code="publisher_timeout",
                )
                await session.commit()
            counts["retrying_or_dead_letter"] += 1
        except asyncio.CancelledError:
            raise
        except Exception:
            async with session_factory() as session:
                await fail_outbox_event(
                    session, event_id=item["id"], org_id=item["org_id"],
                    worker_id=worker_id, error_code="publisher_error",
                )
                await session.commit()
            counts["retrying_or_dead_letter"] += 1
        else:
            async with session_factory() as session:
                await mark_outbox_published(
                    session, event_id=item["id"], org_id=item["org_id"],
                    worker_id=worker_id,
                )
                await session.commit()
            counts["published"] += 1
    return counts
