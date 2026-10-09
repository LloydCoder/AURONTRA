"""
AI Ticket Resolution Agent — Sprint 2 core deliverable.

Pipeline:
  1. classify_ticket()  — keyword + pattern triage, no LLM needed
  2. build_resolution_prompt() — context-aware prompt construction
  3. resolve_ticket() — LLM call via gateway, auto-escalation logic
"""
import re
from core.llm_gateway import llm

# ── Tier-1 keyword patterns (auto-resolvable) ──────────────────────────
_TIER1_PATTERNS = {
    "connectivity": [
        r"\bvpn\b", r"wifi", r"internet.*down", r"network.*slow",
        r"can'?t connect", r"disconnecting", r"no.*internet",
        r"vpn.*connect", r"connect.*vpn",
    ],
    "access": [
        r"password", r"forgot.*login", r"can'?t log", r"locked out",
        r"reset.*account", r"mfa", r"2fa", r"authenticator",
        r"access denied", r"permission",
    ],
    "software": [
        r"install", r"software", r"application.*crash", r"app.*not.*open",
        r"update", r"teams", r"outlook", r"slack", r"zoom",
        r"browser", r"error.*message", r"not.*respond",
    ],
    "hardware_minor": [
        r"printer", r"monitor", r"keyboard", r"mouse",
        r"headset", r"webcam", r"usb", r"display",
    ],
}

# ── Tier-2 patterns — always escalate ─────────────────────────────────
_TIER2_PATTERNS = [
    r"hack", r"breach", r"suspicious.*login", r"ransomware",
    r"data.*loss", r"server.*down", r"production.*down", r"database.*down",
    r"hard.*drive.*fail", r"hard.*drive.*click", r"clicking.*noise",
    r"fire", r"flood", r"critical.*outage", r"complete.*outage",
    r"data loss", r"may be lost",
]

# ── Security patterns — always escalate regardless of tier ─────────────
_SECURITY_PATTERNS = [
    r"hacked", r"compromised", r"suspicious.*login", r"unknown.*country",
    r"breach", r"malware", r"ransomware", r"phishing",
]


def classify_ticket(text: str) -> dict:
    """
    Classify a ticket by category and tier without an LLM call.
    Returns: {category, tier, auto_resolvable, confidence}
    """
    if not text or not text.strip():
        return {
            "category": "unknown",
            "tier": 1,
            "auto_resolvable": False,
            "confidence": 0.0,
        }

    lower = text.lower()

    # Security check — always tier 2
    for pattern in _SECURITY_PATTERNS:
        if re.search(pattern, lower):
            return {
                "category": "security",
                "tier": 2,
                "auto_resolvable": False,
                "confidence": 0.95,
            }

    # Tier-2 escalation check
    for pattern in _TIER2_PATTERNS:
        if re.search(pattern, lower):
            return {
                "category": "infrastructure",
                "tier": 2,
                "auto_resolvable": False,
                "confidence": 0.85,
            }

    # Tier-1 classification
    for category, patterns in _TIER1_PATTERNS.items():
        matches = sum(1 for p in patterns if re.search(p, lower))
        if matches > 0:
            confidence = min(0.95, 0.6 + matches * 0.1)
            return {
                "category": category,
                "tier": 1,
                "auto_resolvable": True,
                "confidence": round(confidence, 2),
            }

    # Default — attempt resolution but with low confidence
    return {
        "category": "general",
        "tier": 1,
        "auto_resolvable": True,
        "confidence": 0.5,
    }


def build_resolution_prompt(
    title: str,
    description: str,
    reporter_email: str,
    category: str,
) -> str:
    """
    Build a context-aware resolution prompt for the LLM gateway.
    Category context shapes the system's approach.
    """
    category_context = {
        "access": "Focus on account recovery, password reset procedures, and MFA troubleshooting steps.",
        "connectivity": "Focus on network diagnostics, VPN configuration, and connectivity troubleshooting steps.",
        "software": "Focus on application troubleshooting, reinstallation procedures, and configuration fixes.",
        "hardware_minor": "Focus on driver updates, physical connection checks, and hardware diagnostics.",
        "security": "This is a security incident. Escalate immediately and do not attempt self-service resolution.",
        "infrastructure": "This is a critical infrastructure issue. Escalate to senior engineers immediately.",
        "general": "Provide clear, step-by-step troubleshooting guidance.",
        "unknown": "Acknowledge the issue and gather more information.",
    }.get(category, "Provide helpful IT support guidance.")

    return f"""You are ResilientAI, an expert IT support agent resolving a {category} ticket.

TICKET DETAILS:
Title: {title}
Description: {description}
Reporter: {reporter_email}
Category: {category}

INSTRUCTIONS:
{category_context}

Provide a clear, professional, actionable response the reporter can follow immediately.
- Use numbered steps if there are multiple actions
- Be specific (name exact menu paths, settings, URLs where relevant)
- Keep it under 200 words
- End with: "Reply to this ticket if the issue persists."

RESPONSE:"""


async def resolve_ticket(
    ticket_id: str,
    title: str,
    description: str,
    reporter_email: str,
    device_id: str | None = None,
) -> dict:
    """
    Core ticket resolution function.
    Classifies → escalates if tier 2 → resolves via LLM if tier 1.

    Returns standardised resolution result dict.
    """
    combined_text = f"{title} {description}"
    classification = classify_ticket(combined_text)

    base = {
        "ticket_id": ticket_id,
        "category": classification["category"],
        "tier": classification["tier"],
        "confidence": classification["confidence"],
        "escalated": False,
        "resolved": False,
        "response": "",
        "model_used": None,
    }

    # ── Tier 2 or security — always escalate ──────────────────────────
    if not classification["auto_resolvable"] or classification["tier"] == 2:
        base["escalated"] = True
        base["resolved"] = False
        base["response"] = (
            f"Ticket #{ticket_id} has been escalated to a senior engineer. "
            f"Category: {classification['category'].upper()}. "
            "You will receive an update within 1 hour."
        )
        base["model_used"] = "escalation-rule"
        return base

    # ── Tier 1 — attempt AI resolution ────────────────────────────────
    prompt = build_resolution_prompt(
        title=title,
        description=description,
        reporter_email=reporter_email,
        category=classification["category"],
    )

    llm_result = await llm.complete(prompt)
    response_text = llm_result.get("text", "").strip()

    if not response_text or len(response_text) < 10:
        base["escalated"] = True
        base["response"] = "AI resolution unavailable. Ticket escalated to human agent."
        base["model_used"] = "fallback-escalation"
        return base

    base["resolved"] = True
    base["response"] = response_text
    base["model_used"] = llm_result.get("model", "unknown")

    return base
