"""Import all models so SQLAlchemy registers them with Base.metadata."""
from models.device import Device
from models.ticket import Ticket, TicketStatus, TicketPriority, TicketSource
from models.resilience_score import ResilienceScore
from models.automation_rule import AutomationRule

__all__ = [
    "Device", "Ticket", "TicketStatus", "TicketPriority", "TicketSource",
    "ResilienceScore", "AutomationRule",
]
