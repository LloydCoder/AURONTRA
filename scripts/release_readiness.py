#!/usr/bin/env python3
"""Fail-closed repository and evidence gate for Aurontra production releases."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "release" / "acceptance-manifest.json"
EVIDENCE_ROOT = (ROOT / "release" / "evidence").resolve()
ALLOWED_STATUSES = {"accepted", "blocked"}
REQUIRED_GATE_IDS = {
    "phase17_agent_platform_integration",
    "phase18_authenticated_console",
    "phase19_billing_checkout_and_entitlements",
    "phase20_api_key_runtime_authentication",
    "phase21_compliance_control_mapping_review",
    "phase22_production_slo_and_disaster_recovery",
    "phase23_frontend_reproducible_dependencies",
    "phase24_production_deployment_and_rollback",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evaluate() -> dict:
    blockers: list[dict[str, str]] = []
    checks: list[dict[str, object]] = []

    def check(check_id: str, passed: bool, detail: str) -> None:
        checks.append({"id": check_id, "passed": passed, "detail": detail})
        if not passed:
            blockers.append({"id": check_id, "reason": detail})

    if not MANIFEST_PATH.is_file():
        return {
            "product": "Aurontra",
            "release_status": "not_ready",
            "production_release_ready": False,
            "checks": [],
            "blockers": [{"id": "acceptance_manifest", "reason": "release/acceptance-manifest.json is missing"}],
        }

    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "product": "Aurontra",
            "release_status": "not_ready",
            "production_release_ready": False,
            "checks": [],
            "blockers": [{"id": "acceptance_manifest", "reason": "acceptance manifest is unreadable or invalid JSON"}],
        }

    if not isinstance(manifest, dict):
        return {
            "product": "Aurontra",
            "release_status": "not_ready",
            "production_release_ready": False,
            "checks": [{"id": "manifest_schema", "passed": False,
                        "detail": "Manifest root must be a JSON object."}],
            "blockers": [{"id": "manifest_schema",
                          "reason": "Manifest root must be a JSON object."}],
        }

    manifest_valid = manifest.get("schema_version") == 1 and isinstance(manifest.get("gates"), list)
    check("manifest_schema", manifest_valid,
          "Manifest schema must be version 1 and contain a gates array.")
    gate_ids: set[str] = set()
    gates = manifest.get("gates", [])
    for gate in gates if isinstance(gates, list) else []:
        if not isinstance(gate, dict):
            blockers.append({"id": "manifest_gate_shape", "reason": "Each gate must be an object."})
            continue
        gate_id = gate.get("id")
        status = gate.get("status")
        if not isinstance(gate_id, str) or not gate_id or gate_id in gate_ids:
            blockers.append({"id": "manifest_gate_id", "reason": "Gate IDs must be unique, non-empty strings."})
            continue
        gate_ids.add(gate_id)
        if not isinstance(status, str) or status not in ALLOWED_STATUSES:
            blockers.append({"id": gate_id, "reason": "Gate status must be accepted or blocked."})
            continue
        evidence = gate.get("evidence")
        if status == "blocked":
            blockers.append({"id": gate_id, "reason": str(gate.get("reason") or "Required gate is blocked.")})
            if evidence is not None:
                blockers.append({"id": gate_id, "reason": "Blocked gates must not present evidence as accepted."})
            continue
        if not isinstance(evidence, dict):
            blockers.append({"id": gate_id, "reason": "Accepted gates require a path and SHA-256 evidence digest."})
            continue
        relative_path = evidence.get("path")
        expected_digest = evidence.get("sha256")
        if not isinstance(relative_path, str) or not relative_path or not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
            blockers.append({"id": gate_id, "reason": "Evidence path or SHA-256 digest is malformed."})
            continue
        path = (ROOT / relative_path).resolve()
        if not path.is_relative_to(EVIDENCE_ROOT) or not path.is_file():
            blockers.append({"id": gate_id, "reason": "Evidence must be a tracked file under release/evidence/."})
            continue
        actual_digest = _sha256(path)
        if actual_digest != expected_digest:
            blockers.append({"id": gate_id, "reason": "Evidence SHA-256 does not match the manifest."})
            continue
        checks.append({"id": gate_id, "passed": True, "detail": "Accepted evidence digest verified."})

    missing_gate_ids = REQUIRED_GATE_IDS - gate_ids
    unexpected_gate_ids = gate_ids - REQUIRED_GATE_IDS
    for gate_id in sorted(missing_gate_ids):
        blockers.append({"id": gate_id, "reason": "Required release gate is missing from the acceptance manifest."})
    for gate_id in sorted(unexpected_gate_ids):
        blockers.append({"id": gate_id, "reason": "Unexpected release gate ID is not part of the canonical 24-phase release contract."})

    config_path = ROOT / "backend" / "core" / "config.py"
    config = config_path.read_text(encoding="utf-8") if config_path.is_file() else ""
    safety_flags = (
        "DATA_PLANE_ENABLED: bool = False",
        "AGENT_PLATFORM_ENABLED: bool = False",
        "REMEDIATION_SUBMISSION_ENABLED: bool = False",
        "THREAT_CONTAINMENT_ENABLED: bool = False",
    )
    flags_safe = all(flag in config for flag in safety_flags)
    check("fail_closed_production_defaults", flags_safe,
          "Production data-plane, Platform, remediation, and containment flags must remain disabled until external acceptance.")

    lockfile = ROOT / "frontend" / "package-lock.json"
    check("frontend_lockfile", lockfile.is_file(),
          "A committed frontend/package-lock.json is required for reproducible npm ci builds.")

    revision_match = re.search(r'DB_SCHEMA_REVISION: str = "([^"]+)"', config)
    migration_files = list((ROOT / "backend" / "alembic" / "versions").glob("*.py"))
    migration_revisions = set()
    for migration in migration_files:
        text = migration.read_text(encoding="utf-8")
        migration_revisions.update(re.findall(r'^revision\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE))
    revision = revision_match.group(1) if revision_match else None
    check("schema_revision_consistency", bool(revision and revision in migration_revisions),
          "Configured DB_SCHEMA_REVISION must match a checked-in Alembic migration.")

    declared_status = manifest.get("release_status")
    all_accepted = (
        isinstance(gates, list)
        and bool(gates)
        and all(isinstance(g, dict) and g.get("status") == "accepted" for g in gates)
    )
    ready = manifest_valid and not blockers and all_accepted and declared_status == "ready"
    if declared_status != ("ready" if all_accepted else "not_ready"):
        blockers.append({"id": "manifest_release_status", "reason": "release_status must agree with the status of every required gate."})
        ready = False

    return {
        "product": manifest.get("product", "Aurontra"),
        "release_status": "ready" if ready else "not_ready",
        "production_release_ready": ready,
        "checks": checks,
        "blockers": blockers,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="exit non-zero unless all release gates are accepted with valid evidence")
    args = parser.parse_args()
    result = evaluate()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if args.strict and not result["production_release_ready"] else 0


if __name__ == "__main__":
    sys.exit(main())
