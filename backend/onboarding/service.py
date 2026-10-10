"""Onboarding service — fail-closed placeholder pending durable tenant/key lifecycle."""


def register_organisation(
    org_name: str,
    admin_email: str,
    plan: str,
    device_count: int,
) -> dict:
    """Never mint credentials in memory or return an unverified install command."""
    raise RuntimeError(
        "Organization registration is disabled until durable tenant storage, "
        "credential hashing/rotation, authorization, and signed installation exist."
    )


def get_org(org_id: str) -> dict | None:
    """No durable organization repository is configured; do not expose in-memory state."""
    return None
