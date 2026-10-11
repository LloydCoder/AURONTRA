"""Tenant-scoped bounded telemetry retention maintenance."""
from datetime import datetime, timezone

from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from models.telemetry_record import TelemetryRecord


class TelemetryRetentionError(RuntimeError):
    """Sanitized telemetry retention error."""


async def purge_expired_telemetry(
    session: AsyncSession,
    *,
    org_id: str,
    now: datetime | None = None,
    limit: int = 500,
) -> int:
    """Delete at most limit expired rows for one explicitly bound tenant."""
    if session.info.get("tenant_id") != org_id:
        raise TelemetryRetentionError("tenant_session_mismatch")
    if not 1 <= limit <= 1000:
        raise ValueError("retention purge limit must be between 1 and 1000")
    cutoff = now or datetime.now(timezone.utc)
    if cutoff.tzinfo is None or cutoff.utcoffset() is None:
        raise ValueError("retention cutoff must be timezone-aware")
    if session.get_bind().dialect.name == "postgresql":
        await session.execute(text("SELECT set_config('app.current_org_id', :org_id, true)"), {"org_id": org_id})
    expired_ids = select(TelemetryRecord.id).where(
        TelemetryRecord.org_id == org_id,
        TelemetryRecord.retention_expires_at <= cutoff,
    ).order_by(TelemetryRecord.retention_expires_at, TelemetryRecord.id).limit(limit)
    result = await session.execute(delete(TelemetryRecord).where(
        TelemetryRecord.org_id == org_id,
        TelemetryRecord.id.in_(expired_ids),
    ))
    await session.flush()
    return int(result.rowcount or 0)
