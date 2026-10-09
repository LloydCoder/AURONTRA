"""
SLA Tracker — response time SLAs per ticket priority.

Competitive gap: no ITSM platform surfaces SLA breach risk proactively.
We show time-to-breach on every open ticket and alert before breach happens.

SLA tiers (industry standard):
  critical → 1hr response
  high     → 4hr response
  medium   → 8hr response
  low      → 24hr response
"""
from datetime import datetime, timezone

SLA_TIERS = {
    "critical": {"response_minutes": 60,   "label": "1 hour"},
    "high":     {"response_minutes": 240,  "label": "4 hours"},
    "medium":   {"response_minutes": 480,  "label": "8 hours"},
    "low":      {"response_minutes": 1440, "label": "24 hours"},
}


def check_sla(priority: str, created_at: datetime) -> dict:
    """
    Check SLA status for a ticket.

    Args:
        priority:   ticket priority string
        created_at: when the ticket was created (timezone-aware)

    Returns:
        dict with status, minutes_elapsed, sla_target_minutes, breached,
        minutes_remaining, pct_elapsed
    """
    tier = SLA_TIERS.get(priority.lower(), SLA_TIERS["medium"])
    target_minutes = tier["response_minutes"]

    now = datetime.now(timezone.utc)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)

    elapsed = (now - created_at).total_seconds() / 60
    remaining = target_minutes - elapsed
    breached = elapsed > target_minutes
    pct = min(100, round(elapsed / target_minutes * 100, 1))

    if breached:
        status = "breached"
    elif pct >= 80:
        status = "at_risk"
    elif pct >= 50:
        status = "warning"
    else:
        status = "on_track"

    return {
        "priority": priority,
        "sla_target_minutes": target_minutes,
        "sla_label": tier["label"],
        "minutes_elapsed": round(elapsed, 1),
        "minutes_remaining": round(remaining, 1),
        "pct_elapsed": pct,
        "status": status,
        "breached": breached,
    }


def sla_compliance_summary(tickets: list[dict]) -> dict:
    """
    Compute SLA compliance across a list of resolved tickets.

    Each ticket must have: priority, created_at (ISO str), resolved_at (ISO str or None)
    """
    met = 0
    breached = 0

    for t in tickets:
        priority = t.get("priority", "medium")
        created_str  = t.get("created_at", "")
        resolved_str = t.get("resolved_at")

        if not created_str:
            continue

        try:
            created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
        except ValueError:
            continue

        if resolved_str:
            try:
                resolved = datetime.fromisoformat(resolved_str.replace("Z", "+00:00"))
            except ValueError:
                continue
            elapsed_minutes = (resolved - created).total_seconds() / 60
            target = SLA_TIERS.get(priority.lower(), SLA_TIERS["medium"])["response_minutes"]
            if elapsed_minutes <= target:
                met += 1
            else:
                breached += 1
        else:
            # Still open — check against now
            result = check_sla(priority, created)
            if result["breached"]:
                breached += 1
            else:
                met += 1

    total = met + breached
    return {
        "total": total,
        "met": met,
        "breached": breached,
        "compliance_pct": round(met / total * 100, 1) if total > 0 else 100.0,
    }
