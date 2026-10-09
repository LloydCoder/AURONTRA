"""
Onboarding — one-click organisation registration.

Competitive gap closed:
- NinjaOne reviews cite "multi-tenant email friction" as #1 complaint
- MSPs want instant onboarding, not a 3-day sales process
- This generates org_id + api_key + agent install command in one POST
"""
import uuid
import secrets
from datetime import datetime, timezone
from billing.plans import PLANS, get_plan_for_device_count

# In-memory org store — replaced by DB in post-launch hardening
_orgs: dict[str, dict] = {}


def register_organisation(
    org_name: str,
    admin_email: str,
    plan: str,
    device_count: int,
) -> dict:
    """
    Register a new organisation and return everything needed to get started.

    Returns:
        org_id, api_key, agent_install_cmd, checkout_url, onboarding_steps
    """
    org_id  = f"org-{uuid.uuid4().hex[:12]}"
    api_key = f"ra_{secrets.token_urlsafe(32)}"

    # Suggested plan if not specified
    suggested_plan = get_plan_for_device_count(device_count)
    active_plan = plan if plan in PLANS else suggested_plan

    org = {
        "org_id":       org_id,
        "org_name":     org_name,
        "admin_email":  admin_email,
        "plan":         active_plan,
        "device_count": device_count,
        "api_key":      api_key,
        "status":       "trial",
        "trial_days_remaining": 14,
        "created_at":   datetime.now(timezone.utc).isoformat(),
    }
    _orgs[org_id] = org

    # One-line agent install command
    agent_install_cmd = (
        f"curl -fsSL https://raw.githubusercontent.com/Tinlance/resilientai/main/agent/install.sh | "
        f"RESILIENTAI_API_KEY={api_key} RESILIENTAI_ORG_ID={org_id} bash"
    )

    onboarding_steps = [
        {"step": 1, "title": "Install agent",    "detail": "Run the install command on each device you want to monitor", "done": False},
        {"step": 2, "title": "Connect tickets",  "detail": "Paste your Jira/Zendesk webhook URL in Settings → Integrations", "done": False},
        {"step": 3, "title": "Enable SIEM",      "detail": "Add your Splunk HEC URL or download CEF format in Settings → SIEM", "done": False},
        {"step": 4, "title": "Activate billing", "detail": "Click the checkout link to start your paid plan after the trial", "done": False},
    ]

    return {
        **org,
        "agent_install_cmd":  agent_install_cmd,
        "dashboard_url":      f"https://resilientai.tinlance.com/dashboard?org={org_id}",
        "docs_url":           "https://docs.resilientai.tinlance.com",
        "onboarding_steps":   onboarding_steps,
        "message":            f"Welcome to ResilientAI, {org_name}! Your 14-day trial starts now.",
    }


def get_org(org_id: str) -> dict | None:
    return _orgs.get(org_id)
