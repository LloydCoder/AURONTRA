# Repository maintenance and release checklist

## GitHub About section

Suggested description (confirm before publishing):

> Governed IT resilience platform for operational risk, telemetry evidence, and auditable remediation workflows.

Suggested website: leave unset unless the maintainer confirms the canonical product or documentation URL. Do not point to a demo or status page that has not been verified.

Suggested topics (select only those that accurately describe the current repository):

- it-operations
- infrastructure-resilience
- fastapi
- python
- cybersecurity
- observability
- incident-response
- tenant-isolation

Avoid claims such as production-ready, autonomous containment, compliance-certified, or predictive accuracy unless independently substantiated. Revisit topics when the repository's actual shipped capabilities change.

## Before each pull request

- [ ] README commands and links still match the code and CI workflow.
- [ ] Tests cover both successful and denied/error paths for changed behavior.
- [ ] Security-sensitive changes preserve default-deny and Platform authority boundaries.
- [ ] Dependency changes are pinned, reviewed, and audited.
- [ ] Database migrations have a forward plan, backup, and rollback/recovery assessment.
- [ ] Documentation distinguishes local/test behavior from deployed behavior.
- [ ] CI and secret/history/archive scan pass.
- [ ] No credentials, customer data, private telemetry, or generated deployment archives are included.

## Before each release

- [ ] Choose a release version and create reviewed release notes.
- [ ] Confirm the selected license is present and third-party notices are accurate.
- [ ] Revalidate every roadmap phase claimed as complete against the release candidate.
- [ ] Run backend tests, dependency audit, migration checks, PostgreSQL RLS tests, and backup/restore checks.
- [ ] Run frontend build/type/lint/integration checks if a frontend is added or changed.
- [ ] Complete security review, SAST/DAST where applicable, and deployment configuration review.
- [ ] Verify the production identity provider, tenant isolation, Platform tool registrations, approvals, and independent postcondition verifier.
- [ ] Confirm worker, scheduler, queue, telemetry retention, monitoring, alerting, incident response, and recovery processes are operational.
- [ ] Deploy the exact reviewed commit and independently verify the service and critical workflows.
- [ ] Publish release notes that distinguish tested code, deployed systems, and any remaining limitations.

## Maintainer settings to verify manually

- [ ] Require pull requests and successful required checks for the default branch.
- [ ] Require review from code owners for security-sensitive paths.
- [ ] Restrict force pushes and branch deletion on protected branches.
- [ ] Enable private vulnerability reporting if available and verify the reporting mailbox is monitored.
- [ ] Confirm issue tracker settings, label availability, and discussion policy.
- [ ] Confirm the security and conduct reporting contacts are actively monitored.
- [ ] Add a real logo or demo only when the asset exists and is current.
- [ ] Publish a license only after the rights holder has selected and approved it.

This checklist is operational guidance, not evidence that any GitHub setting or production control is currently enabled.
