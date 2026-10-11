"""End-to-end tests for tenant-scoped AI drafting and provenance persistence."""
import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from core.database import AsyncSessionLocal
from models.knowledge_article import KnowledgeArticle
from models.ticket import Ticket


def _published_article(article_id: str, content: str) -> KnowledgeArticle:
    return KnowledgeArticle(
        id=article_id,
        org_id="test-tenant",
        article_key=f"test-tenant:{article_id}:v1",
        slug=article_id,
        title="VPN troubleshooting",
        category="connectivity",
        content=content,
        content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        status="published",
        version=1,
        approved_by="test-knowledge-approver",
        approved_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_ticket_draft_persists_provenance_without_closing_ticket():
    article_content = "Check the approved VPN client status, then reconnect using company settings."
    async with AsyncSessionLocal() as db:
        db.add(_published_article("vpn-approved", article_content))
        await db.commit()

    from main import app
    with patch("agents.ticket_resolver.llm") as mock_llm:
        mock_llm.complete = AsyncMock(return_value={
            "text": "Please check the VPN client status and reconnect using your approved company settings.",
            "model": "test-model",
            "layer": 1,
        })
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            created = await client.post("/tickets/ingest", json={
                "title": "VPN not connecting",
                "description": "The VPN client fails to connect from my laptop.",
                "reporter_email": "person@example.invalid",
                "source": "manual",
            })
            assert created.status_code == 201
            ticket_id = created.json()["ticket"]["id"]
            response = await client.post(f"/tickets/{ticket_id}/resolve")

    assert response.status_code == 200
    payload = response.json()
    assert payload["resolved"] is False
    assert payload["outcome_verified"] is False
    assert payload["ticket"]["status"] == "open"
    assert payload["ticket"]["ai_resolved"] is False
    assert payload["ticket"]["ai_triage_category"] == "connectivity"
    assert payload["ticket"]["ai_triage_tier"] == 1
    assert payload["ticket"]["ai_confidence_semantics"] == "heuristic_not_probability"
    assert payload["ticket"]["ai_escalation_reason"] is None
    assert payload["ticket"]["ai_prompt_version"] == "ticket-resolution.v2"
    assert len(payload["ticket"]["ai_prompt_sha256"]) == 64
    assert len(payload["ticket"]["ai_response_sha256"]) == 64
    assert payload["ticket"]["ai_knowledge_refs"][0]["article_id"] == "vpn-approved"
    assert payload["ticket"]["ai_generated_at"]
    prompt = mock_llm.complete.await_args.args[0]
    assert "person@example.invalid" not in prompt
    assert "untrusted_knowledge_references" in prompt

    async with AsyncSessionLocal() as db:
        saved = await db.get(Ticket, ticket_id)
        assert saved.status.value == "open"
        assert saved.ai_resolved is False
        assert saved.ai_prompt_version == "ticket-resolution.v2"
        assert saved.ai_knowledge_refs[0]["article_id"] == "vpn-approved"


@pytest.mark.asyncio
async def test_tampered_knowledge_fails_closed_before_external_model_call():
    article_content = "Approved VPN troubleshooting steps."
    async with AsyncSessionLocal() as db:
        db.add(_published_article("vpn-tampered", article_content))
        await db.commit()
        article = await db.get(KnowledgeArticle, "vpn-tampered")
        article.content = "Tampered instructions that should never reach the model."
        await db.commit()

    from main import app
    with patch("agents.ticket_resolver.llm") as mock_llm:
        mock_llm.complete = AsyncMock()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            created = await client.post("/tickets/ingest", json={
                "title": "VPN not connecting",
                "description": "The VPN client fails to connect.",
                "reporter_email": "person@example.invalid",
            })
            ticket_id = created.json()["ticket"]["id"]
            response = await client.post(f"/tickets/{ticket_id}/resolve")

    assert response.status_code == 503
    assert "integrity verification failed" in response.json()["detail"]
    mock_llm.complete.assert_not_awaited()



@pytest.mark.asyncio
async def test_high_impact_ticket_persists_escalation_reason_without_model_call():
    from main import app
    with patch("agents.ticket_resolver.llm") as mock_llm:
        mock_llm.complete = AsyncMock()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            created = await client.post("/tickets/ingest", json={
                "title": "Account hacked",
                "description": "Suspicious login from an unknown country.",
                "reporter_email": "person@example.invalid",
            })
            assert created.status_code == 201
            ticket_id = created.json()["ticket"]["id"]
            response = await client.post(f"/tickets/{ticket_id}/resolve")

    assert response.status_code == 200
    ticket = response.json()["ticket"]
    assert ticket["status"] == "escalated"
    assert ticket["ai_escalation_reason"] == "security_signal"
    assert ticket["ai_model_used"] is None
    assert response.json()["resolved"] is False
    mock_llm.complete.assert_not_awaited()
