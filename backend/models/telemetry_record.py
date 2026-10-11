"""Append-only tenant-scoped endpoint telemetry with provenance and retention."""
from sqlalchemy import (
    CheckConstraint, Column, DateTime, ForeignKey, ForeignKeyConstraint,
    Index, Integer, JSON, String, UniqueConstraint, func,
)
from core.database import Base


class TelemetryRecord(Base):
    __tablename__ = "telemetry_records"
    __table_args__ = (
        UniqueConstraint("org_id", "device_id", "event_id", name="uq_telemetry_org_device_event"),
        ForeignKeyConstraint(
            ["org_id", "device_id"],
            ["devices.org_id", "devices.id"],
            name="fk_telemetry_records_org_device",
            ondelete="RESTRICT",
        ),
        CheckConstraint("schema_version = '1'", name="ck_telemetry_schema_version"),
        CheckConstraint(
            "computed_score IS NULL OR (computed_score >= 0 AND computed_score <= 100)",
            name="ck_telemetry_computed_score_range",
        ),
        Index("ix_telemetry_org_device_observed", "org_id", "device_id", "observed_at"),
        Index("ix_telemetry_org_retention", "org_id", "retention_expires_at"),
    )

    id = Column(String(36), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    device_id = Column(String(128), nullable=False)
    event_id = Column(String(36), nullable=False)
    schema_version = Column(String(16), nullable=False, default="1", server_default="1")
    source = Column(String(32), nullable=False, default="endpoint_agent", server_default="endpoint_agent")
    agent_version = Column(String(64), nullable=True)
    key_thumbprint = Column(String(128), nullable=False)
    proof_jti = Column(String(256), nullable=False, unique=True)
    request_id = Column(String(128), nullable=False)
    request_hash = Column(String(64), nullable=False)
    payload_hash = Column(String(64), nullable=False)
    observed_at = Column(DateTime(timezone=True), nullable=False)
    received_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    metrics = Column(JSON, nullable=False)
    missing_metrics = Column(JSON, nullable=False, default=list)
    quality_flags = Column(JSON, nullable=False, default=list)
    computed_score = Column(Integer, nullable=True)
    score_components = Column(JSON, nullable=False, default=dict)
    score_status = Column(String(32), nullable=True)
    retention_expires_at = Column(DateTime(timezone=True), nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<TelemetryRecord {self.id} org={self.org_id} device={self.device_id} event={self.event_id}>"
