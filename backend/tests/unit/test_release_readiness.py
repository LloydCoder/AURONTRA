"""Production release readiness gate tests."""
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("release_readiness", ROOT / "scripts" / "release_readiness.py")
release_readiness = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(release_readiness)


def test_current_manifest_fails_closed_and_lists_external_blockers():
    result = release_readiness.evaluate()
    assert result["production_release_ready"] is False
    assert result["release_status"] == "not_ready"
    blocker_ids = {item["id"] for item in result["blockers"]}
    assert "phase17_agent_platform_integration" in blocker_ids
    assert "phase19_billing_checkout_and_entitlements" in blocker_ids
    assert "phase24_production_deployment_and_rollback" in blocker_ids
    assert "schema_revision_consistency" not in blocker_ids


def test_release_gate_accepts_only_digest_verified_evidence(monkeypatch, tmp_path):
    root = tmp_path
    (root / "backend/core").mkdir(parents=True)
    (root / "backend/alembic/versions").mkdir(parents=True)
    (root / "frontend").mkdir()
    evidence_dir = root / "release/evidence"
    evidence_dir.mkdir(parents=True)
    (root / "backend/core/config.py").write_text(
        'DB_SCHEMA_REVISION: str = "0014_test"\n'
        "DATA_PLANE_ENABLED: bool = False\n"
        "AGENT_PLATFORM_ENABLED: bool = False\n"
        "REMEDIATION_SUBMISSION_ENABLED: bool = False\n"
        "THREAT_CONTAINMENT_ENABLED: bool = False\n",
        encoding="utf-8",
    )
    (root / "backend/alembic/versions/0014_test.py").write_text(
        'revision = "0014_test"\n', encoding="utf-8"
    )
    (root / "frontend/package-lock.json").write_text('{"lockfileVersion":3}', encoding="utf-8")
    evidence_path = evidence_dir / "platform-acceptance.json"
    evidence_path.write_text('{"verified":true}', encoding="utf-8")
    digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    evidence = {"path": "release/evidence/platform-acceptance.json", "sha256": digest}
    manifest = {
        "schema_version": 1,
        "product": "Aurontra",
        "release_status": "ready",
        "gates": [{
            "id": gate_id,
            "status": "accepted",
            "owner": "platform-operator",
            "evidence": evidence,
        } for gate_id in sorted(release_readiness.REQUIRED_GATE_IDS)],
    }
    manifest_path = root / "release/acceptance-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(release_readiness, "ROOT", root)
    monkeypatch.setattr(release_readiness, "MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(release_readiness, "EVIDENCE_ROOT", evidence_dir.resolve())

    # A subset of otherwise valid gates must never satisfy the full release contract.
    incomplete = dict(manifest)
    incomplete["gates"] = manifest["gates"][:-1]
    manifest_path.write_text(json.dumps(incomplete), encoding="utf-8")
    result = release_readiness.evaluate()
    assert result["production_release_ready"] is False
    assert any(item["id"] == "phase24_production_deployment_and_rollback" for item in result["blockers"])

    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = release_readiness.evaluate()
    assert result["production_release_ready"] is True
    assert result["blockers"] == []

    evidence_path.write_text('{"verified":false}', encoding="utf-8")
    result = release_readiness.evaluate()
    assert result["production_release_ready"] is False
    assert any("does not match" in item["reason"] for item in result["blockers"])


def test_release_gate_rejects_evidence_path_traversal(monkeypatch, tmp_path):
    root = tmp_path
    (root / "backend/core").mkdir(parents=True)
    (root / "backend/alembic/versions").mkdir(parents=True)
    (root / "frontend").mkdir()
    evidence_dir = root / "release/evidence"
    evidence_dir.mkdir(parents=True)
    (root / "backend/core/config.py").write_text(
        'DB_SCHEMA_REVISION: str = "0014_test"\n'
        "DATA_PLANE_ENABLED: bool = False\n"
        "AGENT_PLATFORM_ENABLED: bool = False\n"
        "REMEDIATION_SUBMISSION_ENABLED: bool = False\n"
        "THREAT_CONTAINMENT_ENABLED: bool = False\n",
        encoding="utf-8",
    )
    (root / "backend/alembic/versions/0014_test.py").write_text('revision = "0014_test"\n', encoding="utf-8")
    (root / "frontend/package-lock.json").write_text('{"lockfileVersion":3}', encoding="utf-8")
    outside = root / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    manifest_path = root / "release/acceptance-manifest.json"
    manifest_path.write_text(json.dumps({
        "schema_version": 1, "product": "Aurontra", "release_status": "ready",
        "gates": [{
            "id": "unsafe", "status": "accepted", "owner": "operator",
            "evidence": {"path": "../outside.json", "sha256": hashlib.sha256(outside.read_bytes()).hexdigest()},
        }],
    }), encoding="utf-8")
    monkeypatch.setattr(release_readiness, "ROOT", root)
    monkeypatch.setattr(release_readiness, "MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(release_readiness, "EVIDENCE_ROOT", evidence_dir.resolve())

    result = release_readiness.evaluate()
    assert result["production_release_ready"] is False
    assert any("release/evidence" in item["reason"] for item in result["blockers"])


def test_strict_release_cli_fails_while_required_gates_are_blocked():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "release_readiness.py"), "--strict"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["production_release_ready"] is False
