# Changelog

All notable changes to Aurontra should be documented here. This project follows the spirit of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses semantic versioning when versioned releases are published.

The repository did not previously provide a verified release history in this file. The entries below summarize documentation changes proposed on the current branch; they are not a substitute for tagged release notes.

## [Unreleased]

### Added
- A README with a direct development Quick Start and explicit maturity warnings.
- Contributor, security reporting, support, and community-health documentation.
- Structured issue forms and a pull request checklist.
- A concise LLM-oriented documentation index.

### Changed
- Clarified the distinction between code/CI acceptance and production deployment.
- Expanded ignore patterns for local secrets, generated output, and test artifacts.

### Maintained release constraints
- Production business data plane remains gated.
- Endpoint-agent authentication and Platform-governed action features remain disabled by default or blocked on documented external prerequisites.
- Threat scores and predictive outputs are not presented as calibrated or independently validated outcomes.

## Historical milestones

Historical phase status and CI evidence are maintained in [docs/ROADMAP.md](docs/ROADMAP.md) and [docs/SECURITY_BASELINE.md](docs/SECURITY_BASELINE.md). Consult those records for commit and workflow references; do not infer a published release from a phase completion.
