"""
Tests for email ticket ingestion parser.
RED phase.
"""
import pytest


class TestEmailParser:

    def test_parse_basic_email(self):
        from ingestion.email_parser import parse_email
        raw = {
            "from": "james@corp.com",
            "subject": "Can't log into VPN",
            "body": "Hi IT team, I've been unable to connect to VPN since this morning. Please help.",
        }
        result = parse_email(raw)
        assert result["reporter_email"] == "james@corp.com"
        assert result["title"] == "Can't log into VPN"
        assert "unable to connect" in result["description"]

    def test_parse_extracts_device_hint(self):
        from ingestion.email_parser import parse_email
        raw = {
            "from": "sarah@corp.com",
            "subject": "Issue on LAPTOP-001",
            "body": "My laptop LAPTOP-001 keeps crashing.",
        }
        result = parse_email(raw)
        assert result["title"] is not None
        assert result["reporter_email"] == "sarah@corp.com"

    def test_parse_missing_subject_uses_body_snippet(self):
        from ingestion.email_parser import parse_email
        raw = {
            "from": "user@corp.com",
            "subject": "",
            "body": "Printer not working in office 3B, paper jam maybe.",
        }
        result = parse_email(raw)
        assert result["title"] is not None
        assert len(result["title"]) > 0

    def test_parse_sets_source_to_email(self):
        from ingestion.email_parser import parse_email
        raw = {"from": "a@b.com", "subject": "Help", "body": "Need help"}
        result = parse_email(raw)
        assert result["source"] == "email"

    def test_parse_empty_email_raises(self):
        from ingestion.email_parser import parse_email
        with pytest.raises((ValueError, KeyError)):
            parse_email({})

    def test_parse_infers_priority_from_keywords(self):
        from ingestion.email_parser import parse_email
        raw = {
            "from": "cto@corp.com",
            "subject": "URGENT: Production server down",
            "body": "Production database is completely down. Critical situation.",
        }
        result = parse_email(raw)
        assert result["priority"] in ("high", "critical")

    def test_parse_default_priority_is_medium(self):
        from ingestion.email_parser import parse_email
        raw = {
            "from": "user@corp.com",
            "subject": "Password reset request",
            "body": "Please reset my password when you get a chance.",
        }
        result = parse_email(raw)
        assert result["priority"] == "medium"


class TestWebhookParser:

    def test_parse_jira_webhook(self):
        from ingestion.webhook import parse_webhook
        payload = {
            "source": "jira",
            "issue": {
                "key": "IT-1234",
                "fields": {
                    "summary": "Slack not loading",
                    "description": "Slack app crashes on startup for 3 users.",
                    "reporter": {"emailAddress": "pm@corp.com"},
                    "priority": {"name": "Medium"},
                },
            },
        }
        result = parse_webhook(payload)
        assert result["title"] == "Slack not loading"
        assert result["reporter_email"] == "pm@corp.com"
        assert result["source"] == "jira"

    def test_parse_zendesk_webhook(self):
        from ingestion.webhook import parse_webhook
        payload = {
            "source": "zendesk",
            "ticket": {
                "id": 9876,
                "subject": "Can't print",
                "description": "Printer on floor 2 is offline.",
                "requester": {"email": "staff@corp.com"},
                "priority": "normal",
            },
        }
        result = parse_webhook(payload)
        assert result["title"] == "Can't print"
        assert result["reporter_email"] == "staff@corp.com"
        assert result["source"] == "zendesk"

    def test_parse_unknown_source_raises(self):
        from ingestion.webhook import parse_webhook
        with pytest.raises(ValueError):
            parse_webhook({"source": "unknown_crm", "data": {}})

    def test_parse_returns_standard_ticket_shape(self):
        from ingestion.webhook import parse_webhook
        payload = {
            "source": "jira",
            "issue": {
                "key": "IT-0001",
                "fields": {
                    "summary": "Test ticket",
                    "description": "Test description",
                    "reporter": {"emailAddress": "test@corp.com"},
                    "priority": {"name": "Low"},
                },
            },
        }
        result = parse_webhook(payload)
        for key in ("title", "description", "reporter_email", "source", "priority"):
            assert key in result
