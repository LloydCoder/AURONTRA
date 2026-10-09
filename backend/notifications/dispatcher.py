"""
Notification Dispatcher — Slack + Microsoft Teams webhooks.

Competitive gap: every major RMM (NinjaOne, ConnectWise, ManageEngine) has
native Slack/Teams alerting. We ship it built-in, not as a paid add-on.

Triggers:
  - Threat blocked (critical/high → immediate)
  - Resilience score drops below warning threshold
  - Ticket escalated to human
  - Self-healing playbook executed
  - SLA breach imminent
"""
import json
import logging
import httpx
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_SEVERITY_COLORS = {
    "critical": "#FF4B6E",
    "warning":  "#FFB547",
    "info":     "#00C9B1",
    "success":  "#28CA41",
}

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "warning":  "⚠️",
    "info":     "ℹ️",
    "success":  "✅",
}


def format_slack_message(
    event_type: str,
    title: str,
    detail: str,
    severity: str = "info",
) -> dict:
    """Build a Slack Block Kit message payload."""
    color  = _SEVERITY_COLORS.get(severity, "#00C9B1")
    emoji  = _SEVERITY_EMOJI.get(severity, "ℹ️")
    ts_str = datetime.now(timezone.utc).strftime("%H:%M UTC")

    return {
        "text": f"{emoji} *{title}*",
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*{emoji} {title}*\n{detail}",
                        },
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"ResilientAI · `{event_type}` · {ts_str}",
                            }
                        ],
                    },
                ],
            }
        ],
    }


def format_teams_message(
    event_type: str,
    title: str,
    detail: str,
    severity: str = "info",
) -> dict:
    """Build a Microsoft Teams Adaptive Card payload."""
    color = {
        "critical": "attention",
        "warning":  "warning",
        "info":     "accent",
        "success":  "good",
    }.get(severity, "accent")

    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": _SEVERITY_COLORS.get(severity, "#00C9B1").lstrip("#"),
        "title": f"ResilientAI — {title}",
        "text": detail,
        "sections": [
            {
                "facts": [
                    {"name": "Event",    "value": event_type},
                    {"name": "Severity", "value": severity.upper()},
                    {"name": "Time",     "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")},
                ]
            }
        ],
    }


async def dispatch(
    channel: str,
    webhook_url: str,
    event_type: str,
    title: str,
    detail: str,
    severity: str = "info",
    test_mode: bool = False,
) -> dict:
    """
    Dispatch a notification to Slack or Teams.

    Args:
        channel:     'slack' | 'teams'
        webhook_url: Incoming webhook URL
        event_type:  e.g. 'threat_blocked', 'ticket_escalated'
        title:       Short summary
        detail:      Full message body
        severity:    'critical' | 'warning' | 'info' | 'success'
        test_mode:   If True, builds payload but doesn't send

    Returns:
        dict with sent (bool), channel, and optional error/reason
    """
    if not webhook_url:
        return {
            "sent": False,
            "channel": channel,
            "reason": "No webhook URL configured",
        }

    if channel == "slack":
        payload = format_slack_message(event_type, title, detail, severity)
    elif channel == "teams":
        payload = format_teams_message(event_type, title, detail, severity)
    else:
        return {"sent": False, "channel": channel, "reason": f"Unknown channel: {channel}"}

    if test_mode:
        return {"sent": True, "channel": channel, "mode": "test", "payload": payload}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                webhook_url,
                content=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
            return {
                "sent": r.status_code in (200, 204),
                "channel": channel,
                "http_status": r.status_code,
            }
    except Exception as e:
        logger.warning(f"[notifications] Dispatch failed: {e}")
        return {"sent": False, "channel": channel, "error": str(e)}
