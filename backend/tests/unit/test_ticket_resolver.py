"""
Sprint 2 — AI Ticket Resolution Agent tests.
RED phase: all tests written before implementation.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock


class TestTicketClassifier:
    """Tests for ticket triage/classification before LLM resolution."""

    def test_classify_password_reset(self):
        from agents.ticket_resolver import classify_ticket
        result = classify_ticket("I forgot my password and can't log in")
        assert result["category"] == "access"
        assert result["tier"] == 1
        assert result["auto_resolvable"] is True

    def test_classify_vpn_issue(self):
        from agents.ticket_resolver import classify_ticket
        result = classify_ticket("VPN keeps disconnecting every 10 minutes")
        assert result["category"] == "connectivity"
        assert result["tier"] == 1
        assert result["auto_resolvable"] is True

    def test_classify_hardware_failure(self):
        from agents.ticket_resolver import classify_ticket
        result = classify_ticket("Server hard drive making clicking noises and data loss")
        assert result["tier"] == 2
        assert result["auto_resolvable"] is False

    def test_classify_software_install(self):
        from agents.ticket_resolver import classify_ticket
        result = classify_ticket("Please install Microsoft Teams on my laptop")
        assert result["category"] == "software"
        assert result["tier"] == 1

    def test_classify_security_incident(self):
        from agents.ticket_resolver import classify_ticket
        result = classify_ticket("I think my account has been hacked, saw suspicious login from Russia")
        assert result["category"] == "security"
        assert result["tier"] == 2
        assert result["auto_resolvable"] is False

    def test_classify_returns_confidence_score(self):
        from agents.ticket_resolver import classify_ticket
        result = classify_ticket("Reset my password please")
        assert "confidence" in result
        assert 0.0 <= result["confidence"] <= 1.0

    def test_classify_unknown_ticket(self):
        from agents.ticket_resolver import classify_ticket
        result = classify_ticket("")
        assert result["category"] == "unknown"
        assert result["auto_resolvable"] is False


class TestTicketResolverAgent:
    """Tests for the AI resolution agent."""

    @pytest.mark.asyncio
    async def test_resolve_returns_dict_with_required_keys(self):
        from agents.ticket_resolver import resolve_ticket
        mock_llm_response = {
            "text": "Please go to Settings > Accounts > Reset Password and follow the prompts.",
            "model": "claude-sonnet-4-6",
            "layer": 1,
        }
        with patch("agents.ticket_resolver.llm") as mock_llm:
            mock_llm.complete = AsyncMock(return_value=mock_llm_response)
            result = await resolve_ticket(
                ticket_id="tkt-001",
                title="Password reset",
                description="I can't log in, forgot my password",
                reporter_email="james@corp.com",
            )
        assert "ticket_id" in result
        assert "resolved" in result
        assert "response" in result
        assert "model_used" in result
        assert "confidence" in result

    @pytest.mark.asyncio
    async def test_tier1_ticket_gets_resolved(self):
        from agents.ticket_resolver import resolve_ticket
        mock_llm_response = {
            "text": "To reset your password, visit the IT portal at portal.company.com/reset",
            "model": "claude-sonnet-4-6",
            "layer": 1,
        }
        with patch("agents.ticket_resolver.llm") as mock_llm:
            mock_llm.complete = AsyncMock(return_value=mock_llm_response)
            result = await resolve_ticket(
                ticket_id="tkt-002",
                title="Cannot access email",
                description="Outlook keeps asking for password",
                reporter_email="sarah@corp.com",
            )
        assert result["resolved"] is True
        assert len(result["response"]) > 10

    @pytest.mark.asyncio
    async def test_tier2_ticket_escalates(self):
        from agents.ticket_resolver import resolve_ticket
        with patch("agents.ticket_resolver.llm") as mock_llm:
            mock_llm.complete = AsyncMock(return_value={
                "text": "Escalating to human agent.",
                "model": "claude-sonnet-4-6",
                "layer": 1,
            })
            result = await resolve_ticket(
                ticket_id="tkt-003",
                title="Server hardware failure",
                description="Hard drive clicking, data may be lost on prod-db-01",
                reporter_email="admin@corp.com",
            )
        assert result["escalated"] is True

    @pytest.mark.asyncio
    async def test_resolution_includes_ticket_id(self):
        from agents.ticket_resolver import resolve_ticket
        with patch("agents.ticket_resolver.llm") as mock_llm:
            mock_llm.complete = AsyncMock(return_value={
                "text": "Here is your resolution.",
                "model": "claude-sonnet-4-6",
                "layer": 1,
            })
            result = await resolve_ticket(
                ticket_id="tkt-specific-99",
                title="VPN issue",
                description="Can't connect",
                reporter_email="user@corp.com",
            )
        assert result["ticket_id"] == "tkt-specific-99"

    @pytest.mark.asyncio
    async def test_llm_failure_triggers_offline_fallback(self):
        from agents.ticket_resolver import resolve_ticket
        with patch("agents.ticket_resolver.llm") as mock_llm:
            mock_llm.complete = AsyncMock(return_value={
                "text": "Your request has been received and logged. A human agent will review.",
                "model": "offline-template",
                "layer": 3,
            })
            result = await resolve_ticket(
                ticket_id="tkt-004",
                title="Network issue",
                description="Cannot reach internet",
                reporter_email="bob@corp.com",
            )
        assert result["resolved"] is not None
        assert result["model_used"] is not None

    @pytest.mark.asyncio
    async def test_security_ticket_always_escalates(self):
        from agents.ticket_resolver import resolve_ticket
        with patch("agents.ticket_resolver.llm") as mock_llm:
            mock_llm.complete = AsyncMock(return_value={
                "text": "Security incident detected.",
                "model": "claude-sonnet-4-6",
                "layer": 1,
            })
            result = await resolve_ticket(
                ticket_id="tkt-005",
                title="Account hacked",
                description="Suspicious login from unknown country, possible breach",
                reporter_email="victim@corp.com",
            )
        assert result["escalated"] is True


class TestTicketPromptBuilder:
    """Tests for the prompt construction layer."""

    def test_prompt_includes_ticket_title(self):
        from agents.ticket_resolver import build_resolution_prompt
        prompt = build_resolution_prompt(
            title="VPN not working",
            description="Cannot connect since Monday",
            reporter_email="user@corp.com",
            category="connectivity",
        )
        assert "VPN not working" in prompt

    def test_prompt_includes_description(self):
        from agents.ticket_resolver import build_resolution_prompt
        prompt = build_resolution_prompt(
            title="Test",
            description="Very specific description here",
            reporter_email="user@corp.com",
            category="software",
        )
        assert "Very specific description here" in prompt

    def test_prompt_includes_category_context(self):
        from agents.ticket_resolver import build_resolution_prompt
        prompt = build_resolution_prompt(
            title="Test",
            description="desc",
            reporter_email="user@corp.com",
            category="access",
        )
        assert "access" in prompt.lower()

    def test_prompt_is_non_empty_string(self):
        from agents.ticket_resolver import build_resolution_prompt
        prompt = build_resolution_prompt("t", "d", "e@e.com", "unknown")
        assert isinstance(prompt, str)
        assert len(prompt) > 50
