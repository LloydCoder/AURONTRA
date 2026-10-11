"""Production release readiness gate tests."""
import hashlib
import importlib.util
import json
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
    manifest = {
        "schema_version": 1,
        "product": "Aurontra",
        "release_status": "ready",
        "gates": [{
            "id": "phase17",
            "status": "accepted",
            "owner": "platform-operator",
            "evidence": {"path": "release/evidence/platform-acceptance.json", "sha256": digest},
        }],
    }
    manifest_path = root / "release/acceptance-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(release_readiness, "ROOT", root)
    monkeypatch.setattr(release_readiness, "MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(release_readiness, "EVIDENCE_ROOT", evidence_dir.resolve())

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
