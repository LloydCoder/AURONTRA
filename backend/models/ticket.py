"""Ticket model — IT support ticket with AI resolution tracking."""
import enum
from sqlalchemy import Column, String, Boolean, DateTime, Text, Enum, func
from core.database import Base


class TicketStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    ESCALATED = "escalated"


class TicketPriority(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TicketSource(str, enum.Enum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    MANUAL = "manual"
    AGENT = "agent"


class Ticket(Base):
    __tablename__ = "tickets"

    id = Column(String, primary_key=True)
    org_id = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    reporter_email = Column(String, nullable=False)
    device_id = Column(String, nullable=True)
    status = Column(Enum(TicketStatus), default=TicketStatus.OPEN, nullable=False)
    priority = Column(Enum(TicketPriority), default=TicketPriority.MEDIUM, nullable=False)
    source = Column(Enum(TicketSource), default=TicketSource.MANUAL)
    ai_resolved = Column(Boolean, default=False, nullable=False)
    ai_response = Column(Text, nullable=True)
    ai_model_used = Column(String, nullable=True)
    ai_confidence = Column(String, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __init__(self, **kwargs):
        kwargs.setdefault("status", TicketStatus.OPEN)
        kwargs.setdefault("priority", TicketPriority.MEDIUM)
        kwargs.setdefault("source", TicketSource.MANUAL)
        kwargs.setdefault("ai_resolved", False)
        super().__init__(**kwargs)

    def __repr__(self) -> str:
        return f"<Ticket {self.id} [{self.status}] ai={self.ai_resolved}>"
