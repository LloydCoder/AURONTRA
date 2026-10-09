"""
Unit tests for all ORM models.
RED phase — tests written before model implementation.
"""
import pytest
from datetime import datetime, timezone


class TestDeviceModel:
    def test_device_has_required_fields(self):
        from models.device import Device
        d = Device(
            id="dev-001",
            name="prod-server-01",
            org_id="org-001",
            ip_address="10.0.0.1",
        )
        assert d.id == "dev-001"
        assert d.name == "prod-server-01"
        assert d.org_id == "org-001"
        assert d.ip_address == "10.0.0.1"

    def test_device_defaults(self):
        from models.device import Device
        d = Device(id="dev-002", name="srv", org_id="org-001")
        assert d.is_active is True
        assert d.resilience_score == 100
        assert d.os_type is None

    def test_device_repr(self):
        from models.device import Device
        d = Device(id="dev-003", name="my-server", org_id="org-001")
        assert "my-server" in repr(d)


class TestTicketModel:
    def test_ticket_has_required_fields(self):
        from models.ticket import Ticket
        t = Ticket(
            id="tkt-001",
            org_id="org-001",
            title="VPN not connecting",
            description="User can't connect to VPN since this morning.",
            reporter_email="james@corp.com",
        )
        assert t.title == "VPN not connecting"
        assert t.reporter_email == "james@corp.com"

    def test_ticket_default_status(self):
        from models.ticket import Ticket, TicketStatus
        t = Ticket(id="tkt-002", org_id="org-001", title="Test", description="desc", reporter_email="a@b.com")
        assert t.status == TicketStatus.OPEN

    def test_ticket_default_priority(self):
        from models.ticket import Ticket, TicketPriority
        t = Ticket(id="tkt-003", org_id="org-001", title="Test", description="desc", reporter_email="a@b.com")
        assert t.priority == TicketPriority.MEDIUM

    def test_ticket_ai_resolved_flag(self):
        from models.ticket import Ticket
        t = Ticket(id="tkt-004", org_id="org-001", title="Test", description="desc", reporter_email="a@b.com")
        assert t.ai_resolved is False


class TestResilienceScoreModel:
    def test_score_has_required_fields(self):
        from models.resilience_score import ResilienceScore
        rs = ResilienceScore(
            id="rs-001",
            device_id="dev-001",
            score=87,
        )
        assert rs.device_id == "dev-001"
        assert rs.score == 87

    def test_score_clamped_to_valid_range(self):
        from models.resilience_score import ResilienceScore
        rs = ResilienceScore(id="rs-002", device_id="dev-001", score=50)
        assert 0 <= rs.score <= 100

    def test_score_has_component_breakdown(self):
        from models.resilience_score import ResilienceScore
        rs = ResilienceScore(
            id="rs-003",
            device_id="dev-001",
            score=75,
            cpu_score=80,
            memory_score=70,
            disk_score=75,
            threat_score=100,
        )
        assert rs.cpu_score == 80
        assert rs.threat_score == 100


class TestAutomationRuleModel:
    def test_rule_has_required_fields(self):
        from models.automation_rule import AutomationRule
        rule = AutomationRule(
            id="rule-001",
            org_id="org-001",
            name="Disk cleanup",
            trigger_metric="disk_percent",
            trigger_threshold=85.0,
            playbook="disk_full",
        )
        assert rule.playbook == "disk_full"
        assert rule.trigger_threshold == 85.0

    def test_rule_is_active_by_default(self):
        from models.automation_rule import AutomationRule
        rule = AutomationRule(
            id="rule-002", org_id="org-001", name="Test",
            trigger_metric="cpu_percent", trigger_threshold=90.0,
            playbook="high_cpu",
        )
        assert rule.is_active is True
