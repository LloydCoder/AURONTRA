"""ResilienceScore model — time-series score snapshots per device."""
from sqlalchemy import Column, String, Integer, Float, DateTime, func
from core.database import Base


class ResilienceScore(Base):
    __tablename__ = "resilience_scores"

    id = Column(String, primary_key=True)
    device_id = Column(String, nullable=False, index=True)

    # Composite score 0-100
    score = Column(Integer, nullable=False, default=100)

    # Component breakdown
    cpu_score = Column(Integer, nullable=True)
    memory_score = Column(Integer, nullable=True)
    disk_score = Column(Integer, nullable=True)
    threat_score = Column(Integer, nullable=True)
    uptime_score = Column(Integer, nullable=True)

    # Prediction metadata
    predicted_score_72h = Column(Integer, nullable=True)
    anomaly_detected = Column(Integer, default=0)  # 0 | 1

    recorded_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"<ResilienceScore device={self.device_id} score={self.score}>"
