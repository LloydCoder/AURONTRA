"""
Sprint 6 — Billing + Auth + ROI + Compliance + Deploy tests.
RED phase: all tests written before implementation.
Addresses 6 competitive gaps competitors all miss.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import AsyncClient, ASGITransport


# ── GAP 1: LemonSqueezy Billing ───────────────────────────────────────
class TestLemonSqueezyBilling:

    def test_plan_config_has_three_tiers(self):
        from billing.plans import PLANS
        assert "starter" in PLANS
        assert "business" in PLANS
        assert "enterprise" in PLANS

    def test_starter_plan_price_per_device(self):
        from billing.plans import PLANS
        assert PLANS["starter"]["price_per_device"] == 12

    def test_business_plan_price_per_device(self):
        from billing.plans import PLANS
        assert PLANS["business"]["price_per_device"] == 22

    def test_plans_have_required_keys(self):
        from billing.plans import PLANS
        required = {"name", "price_per_device", "features", "ls_variant_id"}
        for tier, plan in PLANS.items():
            for key in required:
                assert key in plan, f"Plan '{tier}' missing key '{key}'"

    def test_compute_monthly_cost_starter(self):
        from billing.plans import compute_monthly_cost
        cost = compute_monthly_cost("starter", device_count=10, annual=True)
        assert cost == 96.0  # 10 * $12 * 0.8 annual

    def test_compute_monthly_cost_business(self):
        from billing.plans import compute_monthly_cost
        cost = compute_monthly_cost("business", device_count=50, annual=True)
        assert cost == 880.0  # 50 * $22 * 0.8 annual

    def test_compute_annual_cost_has_20_percent_discount(self):
        from billing.plans import compute_monthly_cost
        monthly = compute_monthly_cost("business", device_count=10, annual=False)
        annual_monthly = compute_monthly_cost("business", device_count=10, annual=True)
        assert annual_monthly < monthly

    def test_unknown_plan_raises(self):
        from billing.plans import compute_monthly_cost
        with pytest.raises(ValueError):
            compute_monthly_cost("premium_ultra", device_count=10)


class TestLemonSqueezyWebhook:

    @pytest.fixture
    async def client(self):
        from main import app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_webhook_endpoint_exists(self, client):
        r = await client.post("/billing/webhook", json={}, headers={"X-Signature": "test"})
        assert r.status_code in (200, 400, 422)

    @pytest.mark.asyncio
    async def test_billing_overview_endpoint(self, client):
        r = await client.get("/billing/")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_billing_plans_endpoint(self, client):
        r = await client.get("/billing/plans")
        assert r.status_code == 200
        data = r.json()
        assert "plans" in data
        assert len(data["plans"]) >= 3

    @pytest.mark.asyncio
    async def test_billing_estimate_endpoint(self, client):
        r = await client.post("/billing/estimate", json={
            "plan": "business",
            "device_count": 50,
            "annual": True,
        })
        assert r.status_code == 200
        data = r.json()
        assert "monthly_cost" in data
        assert "annual_cost" in data
        assert "savings" in data

    @pytest.mark.asyncio
    async def test_checkout_url_endpoint(self, client):
        r = await client.post("/billing/checkout", json={
            "plan": "business",
            "device_count": 25,
            "org_id": "org-test-001",
            "email": "cto@corp.com",
        })
        assert r.status_code in (200, 201)
        data = r.json()
        assert "checkout_url" in data


# ── GAP 2: ROI Report Generator ───────────────────────────────────────
class TestROIReport:

    def test_roi_report_returns_dict(self):
        from reporting.roi import generate_roi_report
        result = generate_roi_report(
            org_id="org-001",
            device_count=50,
            tickets_resolved_ai=120,
            tickets_total=150,
            threats_blocked=8,
            avg_hourly_rate=45,
            period_days=30,
        )
        assert isinstance(result, dict)

    def test_roi_report_has_required_keys(self):
        from reporting.roi import generate_roi_report
        result = generate_roi_report(
            org_id="org-001",
            device_count=50,
            tickets_resolved_ai=100,
            tickets_total=120,
            threats_blocked=5,
            avg_hourly_rate=45,
            period_days=30,
        )
        required = {"org_id", "period_days", "tickets_resolved_ai", "hours_saved",
                    "labour_cost_saved", "breach_cost_avoided", "total_roi_usd",
                    "roi_multiple", "resolution_rate_pct"}
        for key in required:
            assert key in result, f"Missing key: {key}"

    def test_resolution_rate_correct(self):
        from reporting.roi import generate_roi_report
        result = generate_roi_report("org-001", 50, 80, 100, 5, 45, 30)
        assert result["resolution_rate_pct"] == 80.0

    def test_roi_multiple_above_one_for_reasonable_inputs(self):
        from reporting.roi import generate_roi_report
        result = generate_roi_report("org-001", 50, 100, 120, 5, 45, 30)
        assert result["roi_multiple"] >= 1.0

    def test_zero_tickets_does_not_crash(self):
        from reporting.roi import generate_roi_report
        result = generate_roi_report("org-001", 10, 0, 0, 0, 45, 30)
        assert result["resolution_rate_pct"] == 0.0
        assert result["hours_saved"] == 0


# ── GAP 3: Compliance Evidence Report ─────────────────────────────────
class TestComplianceReport:

    def test_compliance_report_returns_dict(self):
        from reporting.compliance import generate_compliance_report
        result = generate_compliance_report(
            org_id="org-001",
            framework="NIS2",
            device_count=50,
            threats_blocked=8,
            avg_resilience_score=84,
            tickets_resolved=120,
            siem_active=True,
            mfa_enabled=True,
        )
        assert isinstance(result, dict)

    def test_nis2_report_has_controls(self):
        from reporting.compliance import generate_compliance_report
        result = generate_compliance_report(
            org_id="org-001", framework="NIS2",
            device_count=50, threats_blocked=8,
            avg_resilience_score=84, tickets_resolved=120,
            siem_active=True, mfa_enabled=True,
        )
        assert "controls" in result
        assert len(result["controls"]) > 0

    def test_dora_framework_supported(self):
        from reporting.compliance import generate_compliance_report
        result = generate_compliance_report(
            org_id="org-001", framework="DORA",
            device_count=20, threats_blocked=3,
            avg_resilience_score=90, tickets_resolved=40,
            siem_active=True, mfa_enabled=False,
        )
        assert result["framework"] == "DORA"

    def test_compliance_score_is_0_to_100(self):
        from reporting.compliance import generate_compliance_report
        result = generate_compliance_report(
            org_id="org-001", framework="NIS2",
            device_count=50, threats_blocked=8,
            avg_resilience_score=84, tickets_resolved=120,
            siem_active=True, mfa_enabled=True,
        )
        assert 0 <= result["compliance_score"] <= 100

    def test_missing_mfa_lowers_score(self):
        from reporting.compliance import generate_compliance_report
        with_mfa    = generate_compliance_report("org-001", "NIS2", 50, 8, 84, 120, True, True)
        without_mfa = generate_compliance_report("org-001", "NIS2", 50, 8, 84, 120, True, False)
        assert with_mfa["compliance_score"] > without_mfa["compliance_score"]

    def test_unknown_framework_raises(self):
        from reporting.compliance import generate_compliance_report
        with pytest.raises(ValueError):
            generate_compliance_report("org-001", "ISO27001_INVALID", 10, 0, 80, 10, True, True)


# ── GAP 4: Onboarding Flow ────────────────────────────────────────────
class TestOnboarding:

    @pytest.fixture
    async def client(self):
        from main import app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_onboarding_register_org(self, client):
        r = await client.post("/onboarding/register", json={
            "org_name": "Acme Corp",
            "admin_email": "admin@acme.com",
            "plan": "business",
            "device_count": 50,
        })
        assert r.status_code in (200, 201)
        data = r.json()
        assert "org_id" in data
        assert "api_key" in data

    @pytest.mark.asyncio
    async def test_onboarding_returns_install_command(self, client):
        r = await client.post("/onboarding/register", json={
            "org_name": "Beta Corp",
            "admin_email": "cto@beta.com",
            "plan": "starter",
            "device_count": 15,
        })
        assert r.status_code in (200, 201)
        data = r.json()
        assert "agent_install_cmd" in data
        assert "curl" in data["agent_install_cmd"].lower() or "pip" in data["agent_install_cmd"].lower()

    @pytest.mark.asyncio
    async def test_onboarding_health_check_endpoint(self, client):
        r = await client.get("/onboarding/health")
        assert r.status_code == 200


# ── GAP 5: Reporting API endpoints ────────────────────────────────────
class TestReportingAPI:

    @pytest.fixture
    async def client(self):
        from main import app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_roi_report_endpoint(self, client):
        r = await client.post("/reports/roi", json={
            "org_id": "org-001",
            "device_count": 50,
            "tickets_resolved_ai": 120,
            "tickets_total": 150,
            "threats_blocked": 8,
            "avg_hourly_rate": 45,
            "period_days": 30,
        })
        assert r.status_code == 200
        data = r.json()
        assert "roi_multiple" in data

    @pytest.mark.asyncio
    async def test_compliance_report_endpoint(self, client):
        r = await client.post("/reports/compliance", json={
            "org_id": "org-001",
            "framework": "NIS2",
            "device_count": 50,
            "threats_blocked": 8,
            "avg_resilience_score": 84,
            "tickets_resolved": 120,
            "siem_active": True,
            "mfa_enabled": True,
        })
        assert r.status_code == 200
        data = r.json()
        assert "compliance_score" in data
        assert "controls" in data

    @pytest.mark.asyncio
    async def test_summary_report_endpoint(self, client):
        r = await client.get("/reports/summary/org-001")
        assert r.status_code == 200
        data = r.json()
        assert "org_id" in data
