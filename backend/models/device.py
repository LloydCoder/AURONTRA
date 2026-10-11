"""Device model — monitored endpoint with a tenant-owned identity."""
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, UniqueConstraint, func
from core.database import Base


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("org_id", "id", name="uq_devices_org_id_id"),)

    id = Column(String, primary_key=True)
    org_id = Column(String, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    name = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    os_type = Column(String, nullable=True)
    device_type = Column(String, default="server")
    is_active = Column(Boolean, default=True, nullable=False)
    resilience_score = Column(Integer, default=100, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    enrolled_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    agent_version = Column(String(64), nullable=True)
    agent_key_thumbprint = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __init__(self, **kwargs):
        kwargs.setdefault("is_active", True)
        kwargs.setdefault("resilience_score", 100)
        super().__init__(**kwargs)

    def __repr__(self) -> str:
        return f"<Device {self.name} ({self.id}) score={self.resilience_score}>"
