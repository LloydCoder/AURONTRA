"""Hashed tenant-scoped API credentials; raw secrets are never persisted."""
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, UniqueConstraint, func
from core.database import Base


class APIKey(Base):
    __tablename__ = "api_keys"
    __table_args__ = (
        UniqueConstraint("key_hash", name="uq_api_keys_key_hash"),
    )

    id = Column(String(64), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    key_hash = Column(String(128), nullable=False)
    key_prefix = Column(String(24), nullable=False, index=True)
    scopes = Column(JSON, nullable=False, default=list)
    created_by = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<APIKey {self.id} org={self.org_id} prefix={self.key_prefix}>"
