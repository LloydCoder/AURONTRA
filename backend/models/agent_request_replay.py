"""Replay protection records for authenticated endpoint-agent requests."""
from sqlalchemy import Column, DateTime, ForeignKeyConstraint, Index, String, func

from core.database import Base


class AgentRequestReplay(Base):
    """Durable, tenant-scoped one-use DPoP proof identifiers."""

    __tablename__ = "agent_request_replays"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "device_id"],
            ["devices.org_id", "devices.id"],
            name="fk_agent_request_replays_org_device",
            ondelete="RESTRICT",
        ),
        Index("ix_agent_request_replays_expires_at", "expires_at"),
        Index("ix_agent_request_replays_org_device", "org_id", "device_id"),
    )

    jti = Column(String(256), primary_key=True)
    org_id = Column(String(64), nullable=False)
    device_id = Column(String(128), nullable=False)
    request_hash = Column(String(64), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
