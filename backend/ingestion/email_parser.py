"""
Email ticket ingestion parser.
Converts raw email dicts into standardised ticket payloads.
"""
import re

_PRIORITY_KEYWORDS_CRITICAL = ["critical", "production down", "outage", "down now", "emergency"]
_PRIORITY_KEYWORDS_HIGH = ["urgent", "asap", "immediately", "blocked", "cannot work", "broken"]
_PRIORITY_KEYWORDS_LOW = ["fyi", "minor", "low priority", "not urgent"]


def _infer_priority(text: str) -> str:
    lower = text.lower()
    if any(kw in lower for kw in _PRIORITY_KEYWORDS_CRITICAL):
        return "critical"
    if any(kw in lower for kw in _PRIORITY_KEYWORDS_HIGH):
        return "high"
    if any(kw in lower for kw in _PRIORITY_KEYWORDS_LOW):
        return "low"
    return "medium"


def parse_email(raw: dict) -> dict:
    if not raw:
        raise ValueError("Empty email payload")
    from_addr = raw.get("from", "").strip()
    if not from_addr:
        raise KeyError("Missing 'from' field in email")
    subject = raw.get("subject", "").strip()
    body = raw.get("body", "").strip()
    if not body:
        raise ValueError("Email body is empty")
    if subject:
        title = subject
    else:
        clean = re.sub(r'\s+', ' ', body)
        title = clean[:80].rstrip() + ("..." if len(clean) > 80 else "")
    combined = f"{subject} {body}"
    priority = _infer_priority(combined)
    return {
        "title": title,
        "description": body,
        "reporter_email": from_addr,
        "source": "email",
        "priority": priority,
    }
