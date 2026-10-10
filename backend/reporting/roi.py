"""
Aurontra ROI model.

This module computes an illustrative estimate from caller-supplied counts and
assumptions. It is not measured savings, proof of successful containment, or a
guarantee of avoided breach costs. Production reporting must use verified,
tenant-scoped event evidence and disclose the provenance of each input.
"""
from datetime import datetime, timezone


_AVG_TICKET_RESOLUTION_MINUTES = 15    # human time per Tier-1 ticket
_BREACH_PROBABILITY_PER_THREAT = 0.03  # 3% chance any blocked C2 = full breach
_IBM_AVG_BREACH_COST_USD = 4_450_000


def generate_roi_report(
    org_id: str,
    device_count: int,
    tickets_resolved_ai: int,
    tickets_total: int,
    threats_blocked: int,
    avg_hourly_rate: float,
    period_days: int,
) -> dict:
    """
    Generate an ROI evidence report for a given organisation period.

    Args:
        org_id:               organisation identifier
        device_count:         total monitored devices
        tickets_resolved_ai:  tickets auto-resolved by AI agent
        tickets_total:        all tickets in period
        threats_blocked:      C2/threat events blocked by ThreatFade
        avg_hourly_rate:      average IT staff hourly cost (USD)
        period_days:          reporting period length in days

    Returns:
        dict with full ROI breakdown, ready for PDF/email export
    """
    # Resolution rate
    resolution_rate = (
        round(tickets_resolved_ai / tickets_total * 100, 1)
        if tickets_total > 0
        else 0.0
    )

    # Labour saved
    minutes_saved = tickets_resolved_ai * _AVG_TICKET_RESOLUTION_MINUTES
    hours_saved = round(minutes_saved / 60, 2)
    labour_cost_saved = round(hours_saved * avg_hourly_rate, 2)

    # Breach cost avoided (expected value)
    breach_cost_avoided = round(
        threats_blocked * _BREACH_PROBABILITY_PER_THREAT * _IBM_AVG_BREACH_COST_USD, 2
    )

    # Total illustrative value modelled
    total_value = labour_cost_saved + breach_cost_avoided

    # Approximate subscription cost for period
    from billing.plans import compute_monthly_cost, get_plan_for_device_count
    plan = get_plan_for_device_count(device_count)
    monthly_cost = compute_monthly_cost(plan, device_count, annual=True)
    period_cost = round(monthly_cost * (period_days / 30), 2)

    roi_multiple = round(total_value / period_cost, 1) if period_cost > 0 else 0.0

    return {
        "org_id": org_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_days": period_days,
        "device_count": device_count,
        "plan": plan,

        # Ticket metrics
        "tickets_total": tickets_total,
        "tickets_resolved_ai": tickets_resolved_ai,
        "resolution_rate_pct": resolution_rate,

        # Labour savings
        "minutes_saved": minutes_saved,
        "hours_saved": hours_saved,
        "avg_hourly_rate_usd": avg_hourly_rate,
        "labour_cost_saved": labour_cost_saved,

        # Threat value — caller-supplied counts are not verified containment evidence.
        "threats_blocked": threats_blocked,  # deprecated compatibility alias
        "threats_reported_blocked_unverified": threats_blocked,
        "breach_probability_per_threat_assumption": _BREACH_PROBABILITY_PER_THREAT,
        "breach_cost_avoided": breach_cost_avoided,  # deprecated compatibility alias
        "breach_cost_avoided_modelled_usd": breach_cost_avoided,

        # ROI summary
        "total_value_delivered_usd": total_value,  # deprecated compatibility alias; not measured
        "total_value_modelled_usd": total_value,
        "total_roi_usd": total_value,  # deprecated compatibility alias
        "subscription_cost_period_usd": period_cost,
        "roi_multiple": roi_multiple,
        "measured_savings": False,
        "methodology_status": "illustrative_model_not_measured",
        "input_provenance": "caller_supplied_unverified",
        "roi_summary": f"Illustrative model estimates ${total_value:,.0f} in value against a ${period_cost:,.0f} subscription over {period_days} days. This is not verified savings or confirmed breach avoidance.",
    }
