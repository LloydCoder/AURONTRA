"""Certificate expiry playbook — recommendation-only until domain ownership is verified."""
from resilience.playbooks.base import BasePlaybook

_DEFAULT_DOMAIN = "localhost"


class CertExpiryPlaybook(BasePlaybook):
    name = "cert_expiry"

    async def execute(self, context: dict) -> dict:
        """Do not probe arbitrary domains or invoke certbot on the API host."""
        domain = context.get("domain", _DEFAULT_DOMAIN)
        days = context.get("days_until_expiry")
        result = self._base_result(
            context,
            status="simulated",
            domain=domain,
            days_until_expiry=days,
            days_until_expiry_source="caller_supplied_unverified" if days is not None else "not_provided",
            renewal_triggered=False,
            actions_taken=[
                "No outbound certificate probe was performed.",
                "No certbot or web-server command was executed.",
                "Verify domain ownership and certificate inventory before scheduling a renewal on the authorized endpoint.",
            ],
            enforcement_verified=False,
            action_required="verify_owned_domain_certificate_and_request_approval",
        )
        await self.audit(context.get("device_id", "unknown"), result)
        return result
