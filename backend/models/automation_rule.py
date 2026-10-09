"""AutomationRule model — defines self-healing trigger conditions."""
from sqlalchemy import Column, String, Boolean, Float, DateTime, func
from core.database import Base


class AutomationRule(Base):
    __tablename__ = "automation_rules"

    id = Column(String, primary_key=True)
    org_id = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False)
    trigger_metric = Column(String, nullable=False)
    trigger_threshold = Column(Float, nullable=False)
    trigger_operator = Column(String, default="gt")
    playbook = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    execution_count = Column(Float, default=0)
    last_triggered_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __init__(self, **kwargs):
        kwargs.setdefault("is_active", True)
        kwargs.setdefault("execution_count", 0)
        kwargs.setdefault("trigger_operator", "gt")
        super().__init__(**kwargs)

    def __repr__(self) -> str:
        return f"<AutomationRule {self.name} [{self.playbook}]>"
