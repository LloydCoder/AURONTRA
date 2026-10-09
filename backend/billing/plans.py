"""
Billing plans — ResilientAI SaaS pricing.
Updated post-research: Free tier + Outcome pricing + Monthly billing surfaced.
LemonSqueezy store: 247127
"""
from core.config import settings

PLANS: dict[str, dict] = {
    "free": {
        "name": "Free",
        "price_per_device": 0,
        "price_per_device_monthly": 0,
        "min_devices": 1,
        "max_devices": 5,
        "ls_variant_id": "",
        "annual_discount": 0.0,
        "features": [
            "Up to 5 devices monitored",
            "Resilience scoring dashboard",
            "50 AI-resolved tickets/month",
            "Threat monitoring (detect only)",
            "Community support",
        ],
    },
    "starter": {
        "name": "Starter",
        "price_per_device": 12,
        "price_per_device_monthly": 15,
        "min_devices": 5,
        "max_devices": None,
        "ls_variant_id": settings.LS_STARTER_VARIANT_ID,
        "annual_discount": 0.20,
        "features": [
            "Resilience scoring dashboard",
            "200 AI-resolved tickets/month",
            "Threat monitoring (detect only)",
            "1 self-healing playbook",
            "Email + webhook integrations",
            "5 team members",
            "ROI report",
            "Knowledge base (50 articles)",
            "SLA tracking",
        ],
    },
    "business": {
        "name": "Business",
        "price_per_device": 22,
        "price_per_device_monthly": 27,
        "min_devices": 1,
        "max_devices": 500,
        "ls_variant_id": settings.LS_BUSINESS_VARIANT_ID,
        "annual_discount": 0.20,
        "features": [
            "Unlimited ticket resolution",
            "Auto threat blocking (ThreatFade)",
            "72-hour failure forecasting",
            "All self-healing playbooks",
            "Unlimited team members",
            "Priority support",
            "SIEM export (Splunk/CEF/JSON)",
            "NIS2 / DORA compliance report",
            "ROI report",
            "Knowledge base (unlimited articles)",
            "SLA tracking + breach alerts",
            "Slack + Teams notifications",
        ],
    },
    "enterprise": {
        "name": "Enterprise",
        "price_per_device": 18,
        "price_per_device_monthly": 22,
        "min_devices": 500,
        "max_devices": None,
        "ls_variant_id": settings.LS_ENTERPRISE_VARIANT_ID,
        "annual_discount": 0.20,
        "features": [
            "White-label for MSPs",
            "Custom self-healing playbooks",
            "Air-gap / on-premise deployment",
            "99.9% uptime SLA",
            "Dedicated onboarding",
            "Quarterly security reviews",
            "Full API access",
            "All compliance frameworks",
            "Full audit trail export",
        ],
    },
    "outcome": {
        "name": "Outcome",
        "price_per_device": 0,
        "price_per_device_monthly": 0,
        "price_per_resolution": 0.79,
        "min_devices": 1,
        "max_devices": None,
        "ls_variant_id": settings.LS_STARTER_VARIANT_ID,
        "annual_discount": 0.0,
        "features": [
            "Pay only per AI-resolved ticket ($0.79)",
            "Undercuts Intercom Fin ($0.99/resolution)",
            "All self-healing playbooks included",
            "ThreatFade threat monitoring",
            "No monthly commitment",
            "Best for variable-volume teams",
        ],
    },
}


def compute_monthly_cost(plan: str, device_count: int, annual: bool = False) -> float:
    if plan not in PLANS:
        raise ValueError(f"Unknown plan '{plan}'. Available: {', '.join(PLANS.keys())}")
    p = PLANS[plan]
    if plan in ("free", "outcome"):
        return 0.0
    price = p["price_per_device"] if annual else p.get("price_per_device_monthly", p["price_per_device"])
    base = price * device_count
    if annual:
        discount = p.get("annual_discount", 0.0)
        return round(base * (1 - discount), 2)
    return round(float(base), 2)


def compute_outcome_cost(resolutions: int) -> float:
    return round(resolutions * PLANS["outcome"]["price_per_resolution"], 2)


def get_plan_for_device_count(device_count: int) -> str:
    if device_count <= 5:  return "free"
    if device_count >= 500: return "enterprise"
    return "business"
