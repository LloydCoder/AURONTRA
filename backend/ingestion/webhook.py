"""
Webhook ticket ingestion parser.
Normalises Jira, Zendesk, and Linear payloads into standard ticket shape.
"""

_PRIORITY_MAP = {
    # Jira
    "highest": "critical", "high": "high",
    "medium": "medium", "low": "low", "lowest": "low",
    # Zendesk
    "urgent": "critical", "normal": "medium",
    # Linear
    "urgent": "critical", "high": "high", "medium": "medium", "low": "low",
}


def _normalise_priority(raw_priority: str) -> str:
    return _PRIORITY_MAP.get(raw_priority.lower(), "medium")


def _parse_jira(payload: dict) -> dict:
    issue = payload.get("issue", {})
    fields = issue.get("fields", {})
    reporter = fields.get("reporter", {})
    priority_obj = fields.get("priority", {})

    return {
        "title": fields.get("summary", "Untitled Jira Issue"),
        "description": fields.get("description", ""),
        "reporter_email": reporter.get("emailAddress", "unknown@jira"),
        "source": "jira",
        "priority": _normalise_priority(priority_obj.get("name", "medium")),
        "external_id": issue.get("key"),
    }


def _parse_zendesk(payload: dict) -> dict:
    ticket = payload.get("ticket", {})
    requester = ticket.get("requester", {})

    return {
        "title": ticket.get("subject", "Untitled Zendesk Ticket"),
        "description": ticket.get("description", ""),
        "reporter_email": requester.get("email", "unknown@zendesk"),
        "source": "zendesk",
        "priority": _normalise_priority(ticket.get("priority", "normal")),
        "external_id": str(ticket.get("id", "")),
    }


def _parse_linear(payload: dict) -> dict:
    issue = payload.get("issue", {})
    creator = issue.get("creator", {})

    return {
        "title": issue.get("title", "Untitled Linear Issue"),
        "description": issue.get("description", ""),
        "reporter_email": creator.get("email", "unknown@linear"),
        "source": "linear",
        "priority": _normalise_priority(issue.get("priority", "medium")),
        "external_id": issue.get("identifier"),
    }


_PARSERS = {
    "jira": _parse_jira,
    "zendesk": _parse_zendesk,
    "linear": _parse_linear,
}


def parse_webhook(payload: dict) -> dict:
    """
    Parse an inbound webhook payload into a standard ticket shape.

    Args:
        payload: dict with 'source' key identifying the originating system

    Returns:
        Standardised ticket dict

    Raises:
        ValueError: if source is unknown or payload is malformed
    """
    source = payload.get("source", "").lower()
    parser = _PARSERS.get(source)

    if not parser:
        raise ValueError(
            f"Unknown webhook source: '{source}'. "
            f"Supported: {', '.join(_PARSERS.keys())}"
        )

    return parser(payload)
