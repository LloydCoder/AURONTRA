"""Tenant identity and lifecycle record."""
from sqlalchemy import Column, String, DateTime, func
from core.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(64), primary_key=True)
    name = Column(String(200), nullable=False)
    status = Column(String(32), nullable=False, default="pending", index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self) -> str:
        return f"<Organization {self.id} [{self.status}]>"
