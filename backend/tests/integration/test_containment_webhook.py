"""Signed independent control-plane evidence webhook tests."""
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from core.config import settings
from core.database import AsyncSessionLocal
from models.containment_verification_evidence import ContainmentVerificationEvidence
from models.device import Device
from models.telemetry_record import TelemetryRecord
from models.threat_containment_attempt import ThreatContainmentAttempt
from models.threat_finding import ThreatFinding


async def _seed_completed_attempt():
    now = datetime.now(timezone.utc)
    device_id = "control-plane-verified-device"
    action_id, finding_id = str(uuid4()), str(uuid4())
    run_id, execution_id = str(uuid4()), str(uuid4())
    async with AsyncSessionLocal() as db:
        db.info["tenant_id"] = "test-tenant"
        device = Device(
            id=device_id, org_id="test-tenant", name="Control-plane verified endpoint",
            is_active=True, enrolled_at=now, last_seen_at=now,
            agent_key_thumbprint="test-thumbprint", agent_version="2.1.0",
        )
        db.add(device)
        await db.flush()
        telemetry = TelemetryRecord(
            id=str(uuid4()), org_id="test-tenant", device_id=device_id, event_id=str(uuid4()),
            schema_version="2", source="endpoint_agent", agent_version="2.1.0",
            key_thumbprint="test-thumbprint", proof_jti=f"proof-{uuid4().hex}",
            request_id=f"request-{uuid4().hex}", request_hash="a" * 64, payload_hash="b" * 64,
            observed_at=now, metrics={"cpu_percent": 10, "memory_percent": 20, "disk_percent": 30},
            missing_metrics=[], quality_flags=[], computed_score=90, score_components={"cpu_percent": 10},
            score_status="ok", retention_expires_at=now + timedelta(days=90),
        )
        db.add(telemetry)
        await db.flush()
        finding = ThreatFinding(
            id=finding_id, org_id="test-tenant", event_id=f"finding-event-{uuid4().hex}",
            device_id=device_id, telemetry_record_id=telemetry.id, source="endpoint_agent",
            detector_version="threat-heuristic.v2", observed_at=now, signal_sha256="c" * 64,
            signal={"src_ip": "192.0.2.55", "protocol": "QUIC"},
            assessment={"containment_recommended": True, "blocked": False, "containment_verified": False},
            score=95, threat_level="critical", mitre_ttp="T1071", decision_status="assessed",
            containment_verified=False,
        )
        db.add(finding)
        await db.flush()
        attempt = ThreatContainmentAttempt(
            id=action_id, org_id="test-tenant", finding_id=finding_id, device_id=device_id,
            idempotency_key=f"containment:{finding_id}", status="awaiting_verification", version=2,
            platform_action_id=action_id, platform_run_id=run_id, platform_execution_id=execution_id,
            platform_state="completed", platform_evidence_ids=[str(uuid4())],
            audit_event_ids=[str(uuid4())], verification_evidence_ids=[],
            reason_code="awaiting_independent_evidence",
        )
        db.add(attempt)
        await db.commit()
    return {
        "attempt_id": action_id, "finding_id": finding_id, "device_id": device_id,
        "action_id": action_id, "execution_id": execution_id, "run_id": run_id,
    }


def _signed_request(payload, secret, *, nonce="nonce-containment-000001", timestamp=None, signature_override=None):
    timestamp = str(timestamp or int(time.time()))
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    message = timestamp.encode("ascii") + b"\n" + nonce.encode("ascii") + b"\n" + body
    signature = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    headers = {
        "X-Aurontra-Timestamp": timestamp,
        "X-Aurontra-Nonce": nonce,
        "X-Aurontra-Signature": signature_override or f"sha256={signature}",
        "Content-Type": "application/json",
    }
    return body, headers


@pytest.mark.asyncio
async def test_signed_control_plane_evidence_verifies_containment(monkeypatch):
    ids = await _seed_completed_attempt()
    secret = "s" * 48
    monkeypatch.setattr(settings, "THREAT_VERIFIER_INTEGRATION_CONFIG_JSON", json.dumps({
        "firewall-prod": {
            "tenant_id": "test-tenant", "key_id": "key-2026-01",
            "secret": secret, "source_type": "network_control_plane",
        }
    }))
    monkeypatch.setattr(settings, "THREAT_VERIFIER_MAX_SKEW_SECONDS", 60)
    payload = {
        "source_id": "firewall-prod", "key_id": "key-2026-01", "tenant_id": "test-tenant",
        "attempt_id": ids["attempt_id"], "finding_id": ids["finding_id"], "device_id": ids["device_id"],
        "action_id": ids["action_id"], "execution_id": ids["execution_id"],
        "source_type": "network_control_plane", "evidence_id": "fw-evidence-0001",
        "isolation_active": True, "reason_code": "isolation_confirmed",
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
    body, headers = _signed_request(payload, secret)
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/integrations/v1/containment-verification", content=body, headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["attempt"]["status"] == "contained"
    assert response.json()["attempt"]["containment_verified"] is True
    assert response.json()["finding"]["containment_verified"] is True
    assert response.json()["finding"]["assessment"]["blocked"] is True
    async with AsyncSessionLocal() as db:
        evidence = await db.get(ContainmentVerificationEvidence, response.json()["verification_evidence_id"])
        assert evidence.signature_valid is True
        assert evidence.payload_sha256 == hashlib.sha256(body).hexdigest()


@pytest.mark.asyncio
async def test_invalid_hmac_cannot_create_verification_evidence(monkeypatch):
    ids = await _seed_completed_attempt()
    secret = "t" * 48
    monkeypatch.setattr(settings, "THREAT_VERIFIER_INTEGRATION_CONFIG_JSON", json.dumps({
        "firewall-prod": {
            "tenant_id": "test-tenant", "key_id": "key-2026-01",
            "secret": secret, "source_type": "network_control_plane",
        }
    }))
    payload = {
        "source_id": "firewall-prod", "key_id": "key-2026-01", "tenant_id": "test-tenant",
        "attempt_id": ids["attempt_id"], "finding_id": ids["finding_id"], "device_id": ids["device_id"],
        "action_id": ids["action_id"], "execution_id": ids["execution_id"],
        "source_type": "network_control_plane", "evidence_id": "fw-evidence-invalid",
        "isolation_active": True, "reason_code": "isolation_confirmed",
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
    body, headers = _signed_request(payload, secret, signature_override="sha256=" + "0" * 64)
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/integrations/v1/containment-verification", content=body, headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "verifier_signature_invalid"
    async with AsyncSessionLocal() as db:
        rows = (await db.scalars(select(ContainmentVerificationEvidence))).all()
        assert rows == []


@pytest.mark.asyncio
async def test_signed_but_stale_control_plane_evidence_never_marks_contained(monkeypatch):
    ids = await _seed_completed_attempt()
    secret = "u" * 48
    monkeypatch.setattr(settings, "THREAT_VERIFIER_INTEGRATION_CONFIG_JSON", json.dumps({
        "firewall-prod": {
            "tenant_id": "test-tenant", "key_id": "key-2026-01",
            "secret": secret, "source_type": "network_control_plane",
        }
    }))
    payload = {
        "source_id": "firewall-prod", "key_id": "key-2026-01", "tenant_id": "test-tenant",
        "attempt_id": ids["attempt_id"], "finding_id": ids["finding_id"], "device_id": ids["device_id"],
        "action_id": ids["action_id"], "execution_id": ids["execution_id"],
        "source_type": "network_control_plane", "evidence_id": "fw-evidence-stale",
        "isolation_active": True, "reason_code": "isolation_confirmed",
        "observed_at": (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(),
    }
    body, headers = _signed_request(payload, secret)
    from main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/integrations/v1/containment-verification", content=body, headers=headers)
    assert response.status_code == 409
    assert response.json()["attempt"]["status"] == "verification_failed"
    assert response.json()["finding"]["containment_verified"] is False
    assert response.json()["finding"]["assessment"]["blocked"] is False
