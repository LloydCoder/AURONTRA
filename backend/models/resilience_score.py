"""Tenant-owned resilience score snapshots per device."""
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, ForeignKeyConstraint, func
from core.database import Base


class ResilienceScore(Base):
    __tablename__ = "resilience_scores"
    __table_args__ = (
        ForeignKeyConstraint(
            ["org_id", "device_id"], ["devices.org_id", "devices.id"],
            name="fk_resilience_scores_org_device", ondelete="RESTRICT",
        ),
    )

    id = Column(String, primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    device_id = Column(String, nullable=False, index=True)
    score = Column(Integer, nullable=False, default=100)
    cpu_score = Column(Integer, nullable=True)
    memory_score = Column(Integer, nullable=True)
    disk_score = Column(Integer, nullable=True)
    threat_score = Column(Integer, nullable=True)
    uptime_score = Column(Integer, nullable=True)
    predicted_score_72h = Column(Integer, nullable=True)
    anomaly_detected = Column(Integer, default=0)
    recorded_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"<ResilienceScore device={self.device_id} score={self.score}>"
