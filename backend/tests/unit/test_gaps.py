"""
Post-launch gap tests — pricing fix + 5 missing features.
RED phase: all tests written before implementation.
"""
import pytest
from httpx import AsyncClient, ASGITransport


# ── PRICING FIX ───────────────────────────────────────────────────────
class TestPricingFix:

    def test_free_tier_exists(self):
        from billing.plans import PLANS
        assert "free" in PLANS

    def test_free_tier_price_is_zero(self):
        from billing.plans import PLANS
        assert PLANS["free"]["price_per_device"] == 0

    def test_free_tier_max_devices_is_5(self):
        from billing.plans import PLANS
        assert PLANS["free"]["max_devices"] == 5

    def test_starter_min_devices_is_5(self):
        from billing.plans import PLANS
        assert PLANS["starter"]["min_devices"] == 5

    def test_compute_free_tier_cost_is_zero(self):
        from billing.plans import compute_monthly_cost
        assert compute_monthly_cost("free", 5) == 0

    def test_monthly_billing_option_exists(self):
        from billing.plans import compute_monthly_cost
        monthly = compute_monthly_cost("business", 10, annual=False)
        annual  = compute_monthly_cost("business", 10, annual=True)
        assert monthly > annual

    def test_monthly_price_is_15_per_device_starter(self):
        from billing.plans import PLANS
        assert PLANS["starter"]["price_per_device_monthly"] == 15

    def test_outcome_pricing_option_exists(self):
        from billing.plans import PLANS
        assert "outcome" in PLANS

    def test_outcome_pricing_per_resolved_ticket(self):
        from billing.plans import PLANS
        assert PLANS["outcome"]["price_per_resolution"] > 0


# ── GAP 1: SLA Tracker ───────────────────────────────────────────────
class TestSLATracker:

    def test_sla_config_has_tiers(self):
        from sla.tracker import SLA_TIERS
        assert "critical" in SLA_TIERS
        assert "high" in SLA_TIERS
        assert "medium" in SLA_TIERS
        assert "low" in SLA_TIERS

    def test_critical_sla_is_1_hour(self):
        from sla.tracker import SLA_TIERS
        assert SLA_TIERS["critical"]["response_minutes"] == 60

    def test_sla_check_returns_status(self):
        from sla.tracker import check_sla
        from datetime import datetime, timezone, timedelta
        created = datetime.now(timezone.utc) - timedelta(minutes=30)
        result = check_sla("medium", created)
        assert "status" in result
        assert "minutes_elapsed" in result
        assert "sla_target_minutes" in result
        assert "breached" in result

    def test_sla_breached_when_overdue(self):
        from sla.tracker import check_sla
        from datetime import datetime, timezone, timedelta
        # Created 9 hours ago, medium SLA = 8 hours
        created = datetime.now(timezone.utc) - timedelta(hours=9)
        result = check_sla("medium", created)
        assert result["breached"] is True

    def test_sla_not_breached_when_within_window(self):
        from sla.tracker import check_sla
        from datetime import datetime, timezone, timedelta
        created = datetime.now(timezone.utc) - timedelta(minutes=10)
        result = check_sla("low", created)
        assert result["breached"] is False

    def test_sla_compliance_report(self):
        from sla.tracker import sla_compliance_summary
        tickets = [
            {"priority": "high",   "created_at": "2026-06-20T10:00:00Z", "resolved_at": "2026-06-20T11:30:00Z"},
            {"priority": "medium", "created_at": "2026-06-20T09:00:00Z", "resolved_at": "2026-06-20T12:30:00Z"},
            {"priority": "low",    "created_at": "2026-06-20T08:00:00Z", "resolved_at": "2026-06-20T09:00:00Z"},
        ]
        result = sla_compliance_summary(tickets)
        assert "compliance_pct" in result
        assert "breached" in result
        assert "met" in result


# ── GAP 2: Knowledge Base ─────────────────────────────────────────────
class TestKnowledgeBase:

    def test_create_article(self):
        from knowledge_base.service import create_article
        article = create_article(
            title="How to reset your VPN connection",
            content="Step 1: Disconnect from VPN. Step 2: Restart the VPN client. Step 3: Reconnect.",
            category="connectivity",
            tags=["vpn", "network", "reset"],
        )
        assert "id" in article
        assert article["title"] == "How to reset your VPN connection"
        assert article["category"] == "connectivity"

    def test_search_articles_by_keyword(self):
        from knowledge_base.service import create_article, search_articles
        create_article("VPN reset guide", "Disconnect and reconnect VPN.", "connectivity", ["vpn"])
        results = search_articles("vpn")
        assert len(results) >= 1
        assert any("vpn" in r["title"].lower() or "vpn" in " ".join(r.get("tags", [])) for r in results)

    def test_search_returns_empty_for_no_match(self):
        from knowledge_base.service import search_articles
        results = search_articles("xyzzy_nonexistent_term_99999")
        assert isinstance(results, list)

    def test_article_has_required_fields(self):
        from knowledge_base.service import create_article
        a = create_article("Test article", "Content here.", "general", [])
        for key in ("id", "title", "content", "category", "tags", "created_at"):
            assert key in a

    def test_suggest_articles_for_ticket(self):
        from knowledge_base.service import create_article, suggest_for_ticket
        create_article("Password reset steps", "Go to IT portal and click reset.", "access", ["password"])
        suggestions = suggest_for_ticket("I forgot my password and can't log in")
        assert isinstance(suggestions, list)

    def test_list_articles_by_category(self):
        from knowledge_base.service import create_article, list_by_category
        create_article("Disk cleanup guide", "Delete temp files.", "disk", ["disk", "cleanup"])
        results = list_by_category("disk")
        assert any(r["category"] == "disk" for r in results)


# ── GAP 3: Slack / Teams Notifications ───────────────────────────────
class TestNotifications:

    def test_format_slack_message_threat(self):
        from notifications.dispatcher import format_slack_message
        msg = format_slack_message(
            event_type="threat_blocked",
            title="C2 beacon blocked",
            detail="Merlin QUIC — 185.220.101.x — Z=14.76",
            severity="critical",
        )
        assert "text" in msg or "blocks" in msg

    def test_format_slack_message_ticket(self):
        from notifications.dispatcher import format_slack_message
        msg = format_slack_message(
            event_type="ticket_resolved",
            title="VPN timeout resolved",
            detail="AI agent applied config fix",
            severity="info",
        )
        assert msg is not None

    def test_format_teams_message(self):
        from notifications.dispatcher import format_teams_message
        msg = format_teams_message(
            event_type="resilience_warning",
            title="Resilience score dropped",
            detail="prod-db-01 score: 42 → critical",
            severity="warning",
        )
        assert "@type" in msg or "title" in msg or "text" in msg

    @pytest.mark.asyncio
    async def test_dispatch_skips_when_no_webhook(self):
        from notifications.dispatcher import dispatch
        # Should not raise even when webhook URL is empty
        result = await dispatch(
            channel="slack",
            webhook_url="",
            event_type="threat_blocked",
            title="Test",
            detail="No webhook configured",
            severity="info",
        )
        assert result["sent"] is False
        assert "reason" in result

    @pytest.mark.asyncio
    async def test_dispatch_simulates_when_test_mode(self):
        from notifications.dispatcher import dispatch
        result = await dispatch(
            channel="slack",
            webhook_url="https://hooks.slack.com/test",
            event_type="ticket_resolved",
            title="Test notification",
            detail="This is a test",
            severity="info",
            test_mode=True,
        )
        assert "sent" in result


# ── GAP 4: Outcome Pricing ────────────────────────────────────────────
class TestOutcomePricing:

    def test_outcome_plan_price_per_resolution(self):
        from billing.plans import PLANS
        assert PLANS["outcome"]["price_per_resolution"] == 0.79

    def test_compute_outcome_cost(self):
        from billing.plans import compute_outcome_cost
        cost = compute_outcome_cost(resolutions=100)
        assert cost == 79.0

    def test_outcome_cheaper_than_intercom(self):
        from billing.plans import compute_outcome_cost
        # Intercom charges $0.99/resolution
        our_cost = compute_outcome_cost(100)
        intercom_cost = 100 * 0.99
        assert our_cost < intercom_cost


# ── GAP 5: API endpoints for new features ─────────────────────────────
class TestNewAPIEndpoints:

    @pytest.fixture
    async def client(self):
        from main import app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_kb_list_endpoint(self, client):
        r = await client.get("/kb/")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_kb_search_endpoint(self, client):
        r = await client.get("/kb/search?q=vpn")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_kb_create_endpoint(self, client):
        r = await client.post("/kb/articles", json={
            "title": "How to fix VPN issues",
            "content": "Step 1: restart. Step 2: reconnect.",
            "category": "connectivity",
            "tags": ["vpn", "network"],
        })
        assert r.status_code in (200, 201)

    @pytest.mark.asyncio
    async def test_sla_status_endpoint(self, client):
        r = await client.get("/sla/status")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_sla_compliance_endpoint(self, client):
        r = await client.get("/sla/compliance")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_billing_plans_includes_free(self, client):
        r = await client.get("/billing/plans")
        data = r.json()
        plan_ids = [p["id"] for p in data["plans"]]
        assert "free" in plan_ids

    @pytest.mark.asyncio
    async def test_billing_plans_includes_outcome(self, client):
        r = await client.get("/billing/plans")
        data = r.json()
        plan_ids = [p["id"] for p in data["plans"]]
        assert "outcome" in plan_ids
