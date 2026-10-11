# Security Policy

## Supported versions

Security fixes target the current default branch (main). No separate long-term support branches or guaranteed backport policy are currently declared.

## Report a vulnerability privately

**Do not open a public issue or pull request for an unpatched vulnerability.**

Email **security@tinlance.com** with the subject “Aurontra security report”. Include, where safe:

- A concise description and potential impact.
- Affected version, commit, component, and configuration.
- Minimal reproduction steps or a proof of concept that does not access third-party data.
- Any suggested mitigation.
- A way to contact you for clarification.

Do not attach real credentials, customer data, production dumps, or unnecessary personal information. If email is not an appropriate channel, contact the repository owner through GitHub and request a private reporting route. Do not include exploit details in a public post while a report is being triaged.

## Response expectations

These are target service levels, not a guarantee of a fixed resolution date:

| Activity | Target |
|---|---|
| Acknowledge report | Within 3 business days |
| Initial triage and severity assessment | Within 7 business days |
| Status update | At least every 14 calendar days while active |
| Fix and disclosure | Based on severity, exploitability, affected users, and release readiness |

If a target cannot be met, the maintainer should provide a status update and revised expectation. Please allow reasonable time for investigation and a coordinated fix before public disclosure.

## Scope and security boundaries

Potentially relevant issues include authentication or authorization bypass, cross-tenant data exposure, DPoP/replay protection defects, unsafe execution paths, secret disclosure, insecure webhook verification, tenant-isolation failures, and supply-chain vulnerabilities.

Aurontra is not certified production-ready. Its business data plane, endpoint-agent authentication, governed remediation, and threat containment have documented release gates. Do not interpret a disabled feature, a passing test suite, or a CI scan as evidence that every deployment is secure.

## Safe harbor

Good-faith research should minimize harm, avoid privacy violations, avoid service disruption, and stop if sensitive data or unexpected access is encountered. This policy does not authorize testing systems or accounts you do not own or have permission to assess.
