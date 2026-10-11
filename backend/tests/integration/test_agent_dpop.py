"""Cryptographic endpoint-agent protocol integration tests."""
import base64
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from core import agent_auth
from core.config import settings
from core.database import AsyncSessionLocal
from models.agent_request_replay import AgentRequestReplay
from models.device import Device
from models.durable_job import OutboxEvent
from models.organization import Organization
from models.telemetry_record import TelemetryRecord


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwk(private_key):
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64(numbers.x.to_bytes(32, "big")),
        "y": _b64(numbers.y.to_bytes(32, "big")),
    }


def _telemetry_payload(*, event_id=None, observed_at=None, **metrics):
    return {
        "event_id": str(event_id or uuid.uuid4()),
        "schema_version": "1",
        "timestamp": (observed_at or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z"),
        **metrics,
    }


def _headers(monkeypatch, *, device_id, tenant_id, scope, path, body, device_key=None, issuer_key=None):
    issuer_key = issuer_key or ec.generate_private_key(ec.SECP256R1())
    client_key = device_key or ec.generate_private_key(ec.SECP256R1())
    jwk = _jwk(client_key)
    thumbprint = agent_auth.jwk_thumbprint(jwk)
    monkeypatch.setattr(settings, "AGENT_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "AGENT_JWKS_URL", "https://identity.example.invalid/jwks")
    monkeypatch.setattr(settings, "AGENT_JWT_ISSUER", "https://identity.example.invalid/")
    monkeypatch.setattr(settings, "AGENT_JWT_AUDIENCE", "aurontra-agent")
    monkeypatch.setattr(settings, "AGENT_PUBLIC_ORIGIN", "")
    monkeypatch.setattr(settings, "AGENT_DPOP_MAX_AGE_SECONDS", 60)
    monkeypatch.setattr(settings, "AGENT_CLOCK_SKEW_SECONDS", 30)
    monkeypatch.setattr(settings, "AGENT_ACCESS_TOKEN_MAX_TTL_SECONDS", 600)
    monkeypatch.setattr(settings, "AGENT_REPLAY_RETENTION_SECONDS", 300)
    monkeypatch.setattr(settings, "AUTH_MODE", "disabled")
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", True)
    monkeypatch.setattr(settings, "ENVIRONMENT", "test")
    monkeypatch.setattr(
        agent_auth,
        "_agent_jwks_client",
        lambda: SimpleNamespace(
            get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=issuer_key.public_key())
        ),
    )
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": "https://identity.example.invalid/",
            "aud": "aurontra-agent",
            "sub": device_id,
            "tenant_id": tenant_id,
            "scope": scope,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 300,
            "cnf": {"jkt": thumbprint},
        },
        issuer_key,
        algorithm="ES256",
        headers={"kid": "issuer-test"},
    )
    proof = jwt.encode(
        {
            "htm": "POST",
            "htu": "https://test" + path,
            "iat": now,
            "jti": str(uuid.uuid4()),
            "ath": _b64(__import__("hashlib").sha256(token.encode("ascii")).digest()),
            "bht": _b64(__import__("hashlib").sha256(body).digest()),
        },
        client_key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )
    return {
        "Authorization": f"DPoP {token}",
        "DPoP": proof,
        "Content-Type": "application/json",
    }, thumbprint


def _body(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


async def _client():
    from main import app
    return AsyncClient(transport=ASGITransport(app=app), base_url="https://test")


@pytest.mark.asyncio
async def test_platform_bound_agent_enrollment_activates_only_provisioned_device(monkeypatch):
    device_id = "agent-enroll-01"
    async with AsyncSessionLocal() as db:
        db.add(Device(id=device_id, org_id="test-tenant", name="endpoint agent", is_active=False))
        await db.commit()

    payload = {"agent_version": "1.2.3"}
    body = _body(payload)
    headers, thumbprint = _headers(
        monkeypatch,
        device_id=device_id,
        tenant_id="test-tenant",
        scope="aurontra:agent:enroll",
        path="/agent/v1/enroll",
        body=body,
    )
    async with await _client() as client:
        response = await client.post("/agent/v1/enroll", content=body, headers=headers)

    assert response.status_code == 200
    assert response.json()["lifecycle_state"] == "enrolled"
    async with AsyncSessionLocal() as db:
        device = await db.get(Device, device_id)
        assert device.is_active is True
        assert device.enrolled_at is not None
        assert device.agent_key_thumbprint == thumbprint
        assert device.agent_version == "1.2.3"
        events = (await db.scalars(__import__("sqlalchemy").select(OutboxEvent).where(OutboxEvent.aggregate_id == device_id))).all()
        assert [event.event_type for event in events] == ["agent.enrolled"]


@pytest.mark.asyncio
async def test_dpop_telemetry_accepts_enrolled_device_and_rejects_replayed_proof(monkeypatch):
    device_id = "agent-telemetry-01"
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = _jwk(key)
    thumbprint = agent_auth.jwk_thumbprint(jwk)
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="telemetry endpoint",
            is_active=True, enrolled_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            agent_key_thumbprint=thumbprint, agent_version="2.0.0",
        ))
        await db.commit()

    payload = _telemetry_payload(cpu_percent=24.0, memory_percent=48.0, disk_percent=55.0)
    body = _body(payload)
    headers, _ = _headers(
        monkeypatch,
        device_id=device_id,
        tenant_id="test-tenant",
        scope="aurontra:telemetry:write",
        path="/agent/v1/telemetry",
        body=body,
        device_key=key,
    )
    async with await _client() as client:
        first = await client.post("/agent/v1/telemetry", content=body, headers=headers)
        replay = await client.post("/agent/v1/telemetry", content=body, headers=headers)

    assert first.status_code == 200
    assert first.json()["stored"] is True
    assert replay.status_code == 401
    assert "already been used" in replay.json()["detail"]


@pytest.mark.asyncio
async def test_dpop_proof_is_bound_to_exact_body(monkeypatch):
    device_id = "agent-body-binding"
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="body binding endpoint",
            is_active=True, enrolled_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        ))
        await db.commit()

    signed_body = _body(_telemetry_payload(cpu_percent=20.0))
    headers, thumbprint = _headers(
        monkeypatch,
        device_id=device_id,
        tenant_id="test-tenant",
        scope="aurontra:telemetry:write",
        path="/agent/v1/telemetry",
        body=signed_body,
    )
    async with AsyncSessionLocal() as db:
        device = await db.get(Device, device_id)
        device.agent_key_thumbprint = thumbprint
        await db.commit()

    async with await _client() as client:
        response = await client.post(
            "/agent/v1/telemetry",
            content=_body(_telemetry_payload(cpu_percent=99.0)),
            headers=headers,
        )

    assert response.status_code == 401
    assert "DPoP" in response.json()["detail"] or "Invalid agent identity" in response.json()["detail"]


@pytest.mark.asyncio
async def test_agent_scope_and_tenant_binding_are_enforced(monkeypatch):
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = _jwk(key)
    thumbprint = agent_auth.jwk_thumbprint(jwk)
    async with AsyncSessionLocal() as db:
        db.add(Organization(id="other-tenant", name="Other Tenant", status="active"))
        await db.flush()
        db.add(Device(
            id="other-tenant-device", org_id="other-tenant", name="foreign device",
            is_active=True, enrolled_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            agent_key_thumbprint=thumbprint,
        ))
        await db.commit()

    payload = _telemetry_payload(cpu_percent=12.0)
    body = _body(payload)
    headers, _ = _headers(
        monkeypatch, device_id="other-tenant-device", tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=body, device_key=key,
    )
    async with await _client() as client:
        cross_tenant = await client.post("/agent/v1/telemetry", content=body, headers=headers)

    assert cross_tenant.status_code == 404


@pytest.mark.asyncio
async def test_agent_scope_is_required_for_telemetry(monkeypatch):
    device_id = "agent-wrong-scope"
    key = ec.generate_private_key(ec.SECP256R1())
    thumbprint = agent_auth.jwk_thumbprint(_jwk(key))
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="scope test device",
            is_active=True, enrolled_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            agent_key_thumbprint=thumbprint,
        ))
        await db.commit()

    body = _body(_telemetry_payload(cpu_percent=18.0))
    headers, _ = _headers(
        monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:agent:enroll", path="/agent/v1/telemetry", body=body, device_key=key,
    )
    async with await _client() as client:
        response = await client.post("/agent/v1/telemetry", content=body, headers=headers)

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_platform_scoped_key_rotation_rebinds_device_and_rejects_old_key(monkeypatch):
    device_id = "agent-key-rotation"
    old_key = ec.generate_private_key(ec.SECP256R1())
    old_thumbprint = agent_auth.jwk_thumbprint(_jwk(old_key))
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="rotation device",
            is_active=True, enrolled_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            agent_key_thumbprint=old_thumbprint, agent_version="1.0.0",
        ))
        await db.commit()

    new_key = ec.generate_private_key(ec.SECP256R1())
    rotation_body = _body({"agent_version": "1.1.0"})
    rotation_headers, new_thumbprint = _headers(
        monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:agent:key:rotate", path="/agent/v1/rotate-key",
        body=rotation_body, device_key=new_key,
    )
    async with await _client() as client:
        rotated = await client.post("/agent/v1/rotate-key", content=rotation_body, headers=rotation_headers)

    assert rotated.status_code == 200
    assert rotated.json()["lifecycle_state"] == "key_rotated"
    assert new_thumbprint != old_thumbprint
    async with AsyncSessionLocal() as db:
        device = await db.get(Device, device_id)
        assert device.agent_key_thumbprint == new_thumbprint
        assert device.agent_key_rotated_at is not None
        assert device.agent_version == "1.1.0"

    telemetry_body = _body(_telemetry_payload(cpu_percent=10.0))
    old_headers, _ = _headers(
        monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry",
        body=telemetry_body, device_key=old_key,
    )
    async with await _client() as client:
        old_key_response = await client.post("/agent/v1/telemetry", content=telemetry_body, headers=old_headers)

    assert old_key_response.status_code == 404



@pytest.mark.asyncio
async def test_telemetry_persists_provenance_and_duplicate_event_is_idempotent(monkeypatch):
    device_id = "telemetry-durable-01"
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    thumbprint = agent_auth.jwk_thumbprint(_jwk(key))
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="durable telemetry endpoint",
            is_active=True, enrolled_at=datetime.now(timezone.utc),
            agent_key_thumbprint=thumbprint, agent_version="3.1.0",
        ))
        await db.commit()

    payload = _telemetry_payload(cpu_percent=22.0, memory_percent=41.0, disk_percent=58.0, process_count=12, platform="Linux")
    body = _body(payload)
    headers1, _ = _headers(monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=body, device_key=key, issuer_key=issuer_key)
    headers2, _ = _headers(monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=body, device_key=key, issuer_key=issuer_key)
    async with await _client() as client:
        first = await client.post("/agent/v1/telemetry", content=body, headers=headers1)
        duplicate = await client.post("/agent/v1/telemetry", content=body, headers=headers2)

    assert first.status_code == 200, first.text
    assert first.json()["persistence"] == "telemetry_evidence_recorded"
    assert first.json()["duplicate"] is False
    assert duplicate.status_code == 200, duplicate.text
    assert duplicate.json()["duplicate"] is True
    assert duplicate.json()["telemetry_id"] == first.json()["telemetry_id"]
    async with AsyncSessionLocal() as db:
        rows = list((await db.scalars(select(TelemetryRecord).where(
            TelemetryRecord.org_id == "test-tenant", TelemetryRecord.device_id == device_id
        ))).all())
        events = list((await db.scalars(select(OutboxEvent).where(
            OutboxEvent.org_id == "test-tenant", OutboxEvent.event_type == "telemetry.accepted"
        ))).all())
        assert len(rows) == 1
        assert rows[0].key_thumbprint == thumbprint
        assert rows[0].agent_version == "3.1.0"
        assert rows[0].request_hash
        assert rows[0].payload_hash
        assert rows[0].proof_jti
        assert rows[0].retention_expires_at > rows[0].received_at
        assert len(events) == 1


@pytest.mark.asyncio
async def test_same_telemetry_event_id_with_changed_content_returns_409_and_consumes_proof(monkeypatch):
    device_id = "telemetry-conflict-01"
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    thumbprint = agent_auth.jwk_thumbprint(_jwk(key))
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="conflict telemetry endpoint",
            is_active=True, enrolled_at=datetime.now(timezone.utc),
            agent_key_thumbprint=thumbprint,
        ))
        await db.commit()
    event_id = uuid.uuid4()
    timestamp = datetime.now(timezone.utc)
    body1 = _body(_telemetry_payload(event_id=event_id, observed_at=timestamp, cpu_percent=10.0))
    body2 = _body(_telemetry_payload(event_id=event_id, observed_at=timestamp, cpu_percent=99.0))
    headers1, _ = _headers(monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=body1, device_key=key, issuer_key=issuer_key)
    headers2, _ = _headers(monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=body2, device_key=key, issuer_key=issuer_key)
    async with await _client() as client:
        first = await client.post("/agent/v1/telemetry", content=body1, headers=headers1)
        conflict = await client.post("/agent/v1/telemetry", content=body2, headers=headers2)
    assert first.status_code == 200, first.text
    assert conflict.status_code == 409
    async with AsyncSessionLocal() as db:
        rows = list((await db.scalars(select(TelemetryRecord).where(
            TelemetryRecord.org_id == "test-tenant", TelemetryRecord.device_id == device_id
        ))).all())
        replays = list((await db.scalars(select(AgentRequestReplay).where(
            AgentRequestReplay.org_id == "test-tenant", AgentRequestReplay.device_id == device_id
        ))).all())
        assert len(rows) == 1
        assert len(replays) == 2


@pytest.mark.asyncio
async def test_stale_and_future_telemetry_timestamps_are_rejected(monkeypatch):
    device_id = "telemetry-time-boundary"
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    thumbprint = agent_auth.jwk_thumbprint(_jwk(key))
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="timestamp boundary device",
            is_active=True, enrolled_at=datetime.now(timezone.utc),
            agent_key_thumbprint=thumbprint,
        ))
        await db.commit()

    bodies = [
        _body(_telemetry_payload(observed_at=datetime.now(timezone.utc) - timedelta(seconds=settings.TELEMETRY_MAX_AGE_SECONDS + 10), cpu_percent=10.0)),
        _body(_telemetry_payload(observed_at=datetime.now(timezone.utc) + timedelta(seconds=settings.TELEMETRY_FUTURE_SKEW_SECONDS + 10), cpu_percent=10.0)),
    ]
    responses = []
    async with await _client() as client:
        for body in bodies:
            headers, _ = _headers(monkeypatch, device_id=device_id, tenant_id="test-tenant",
                scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=body, device_key=key, issuer_key=issuer_key)
            responses.append(await client.post("/agent/v1/telemetry", content=body, headers=headers))
    assert [response.status_code for response in responses] == [422, 422]
    async with AsyncSessionLocal() as db:
        assert await db.scalar(select(TelemetryRecord.id).where(TelemetryRecord.device_id == device_id)) is None


@pytest.mark.asyncio
async def test_out_of_order_telemetry_is_stored_but_does_not_overwrite_current_score(monkeypatch):
    device_id = "telemetry-out-of-order"
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    thumbprint = agent_auth.jwk_thumbprint(_jwk(key))
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="out-of-order device",
            is_active=True, enrolled_at=datetime.now(timezone.utc),
            agent_key_thumbprint=thumbprint,
        ))
        await db.commit()
    now = datetime.now(timezone.utc)
    first_body = _body(_telemetry_payload(observed_at=now - timedelta(seconds=10), cpu_percent=10.0, memory_percent=20.0, disk_percent=30.0))
    older_body = _body(_telemetry_payload(observed_at=now - timedelta(seconds=20), cpu_percent=98.0, memory_percent=99.0, disk_percent=99.0))
    headers1, _ = _headers(monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=first_body, device_key=key, issuer_key=issuer_key)
    headers2, _ = _headers(monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=older_body, device_key=key, issuer_key=issuer_key)
    async with await _client() as client:
        first = await client.post("/agent/v1/telemetry", content=first_body, headers=headers1)
        older = await client.post("/agent/v1/telemetry", content=older_body, headers=headers2)
    assert first.status_code == 200, first.text
    assert first.json()["current_state_updated"] is True
    assert older.status_code == 200, older.text
    assert older.json()["current_state_updated"] is False
    assert "out_of_order" in older.json()["quality_flags"]
    async with AsyncSessionLocal() as db:
        device = await db.get(Device, device_id)
        rows = list((await db.scalars(select(TelemetryRecord).where(
            TelemetryRecord.org_id == "test-tenant", TelemetryRecord.device_id == device_id
        ))).all())
        assert len(rows) == 2
        assert device.resilience_score == first.json()["resilience"]["score"]


@pytest.mark.asyncio
async def test_agent_endpoints_fail_closed_when_agent_auth_is_disabled(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_AUTH_ENABLED", False)
    monkeypatch.setattr(settings, "DATA_PLANE_ENABLED", True)
    async with await _client() as client:
        response = await client.post("/agent/v1/telemetry", content=b"{}", headers={"Content-Type": "application/json"})
    assert response.status_code == 503
    assert response.json()["code"] == "AGENT_AUTH_DISABLED"


@pytest.mark.asyncio
async def test_revoked_agent_cannot_send_telemetry(monkeypatch):
    device_id = "agent-revoked"
    key = ec.generate_private_key(ec.SECP256R1())
    thumbprint = agent_auth.jwk_thumbprint(_jwk(key))
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="revoked endpoint",
            is_active=False, enrolled_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            revoked_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            agent_key_thumbprint=thumbprint,
        ))
        await db.commit()

    body = _body(_telemetry_payload(cpu_percent=14.0))
    headers, _ = _headers(
        monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=body, device_key=key,
    )
    async with await _client() as client:
        response = await client.post("/agent/v1/telemetry", content=body, headers=headers)

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_partial_telemetry_is_evidence_only_and_cannot_overwrite_resilience_score(monkeypatch):
    device_id = "telemetry-partial-score"
    key = ec.generate_private_key(ec.SECP256R1())
    thumbprint = agent_auth.jwk_thumbprint(_jwk(key))
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="partial telemetry endpoint",
            is_active=True, enrolled_at=datetime.now(timezone.utc),
            agent_key_thumbprint=thumbprint, resilience_score=73,
        ))
        await db.commit()

    body = _body(_telemetry_payload(cpu_percent=99.0))
    headers, _ = _headers(
        monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=body, device_key=key,
    )
    async with await _client() as client:
        response = await client.post("/agent/v1/telemetry", content=body, headers=headers)

    assert response.status_code == 200, response.text
    assert response.json()["current_state_updated"] is False
    assert response.json()["resilience"]["score"] is None
    assert response.json()["resilience"]["status"] == "insufficient_data"
    assert "memory_percent" in response.json()["missing_metrics"]
    assert "disk_percent" in response.json()["missing_metrics"]

    async with AsyncSessionLocal() as db:
        device = await db.get(Device, device_id)
        record = await db.scalar(select(TelemetryRecord).where(TelemetryRecord.device_id == device_id))
        assert device.resilience_score == 73
        assert record.computed_score is None
        assert record.score_status == "insufficient_data"
        assert set(record.missing_metrics) == {"memory_percent", "disk_percent"}


@pytest.mark.asyncio
async def test_telemetry_rate_limit_bounds_device_ingestion_and_consumes_rejected_proof(monkeypatch):
    device_id = "telemetry-rate-limited"
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    thumbprint = agent_auth.jwk_thumbprint(_jwk(key))
    monkeypatch.setattr(settings, "TELEMETRY_MAX_EVENTS_PER_MINUTE", 1)
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="rate-limited endpoint",
            is_active=True, enrolled_at=datetime.now(timezone.utc),
            agent_key_thumbprint=thumbprint,
        ))
        await db.commit()

    body1 = _body(_telemetry_payload(cpu_percent=20.0, memory_percent=30.0, disk_percent=40.0))
    body2 = _body(_telemetry_payload(cpu_percent=21.0, memory_percent=31.0, disk_percent=41.0))
    headers1, _ = _headers(monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=body1, device_key=key, issuer_key=issuer_key)
    headers2, _ = _headers(monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=body2, device_key=key, issuer_key=issuer_key)
    async with await _client() as client:
        first = await client.post("/agent/v1/telemetry", content=body1, headers=headers1)
        limited = await client.post("/agent/v1/telemetry", content=body2, headers=headers2)

    assert first.status_code == 200, first.text
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"
    assert limited.json()["code"] == "TELEMETRY_RATE_LIMITED"
    async with AsyncSessionLocal() as db:
        rows = list((await db.scalars(select(TelemetryRecord).where(
            TelemetryRecord.device_id == device_id
        ))).all())
        proofs = list((await db.scalars(select(AgentRequestReplay).where(
            AgentRequestReplay.device_id == device_id
        ))).all())
    assert len(rows) == 1
    assert len(proofs) == 2


@pytest.mark.asyncio
async def test_payload_device_id_is_only_a_hint_and_must_match_authenticated_identity(monkeypatch):
    device_id = "telemetry-bound-device"
    key = ec.generate_private_key(ec.SECP256R1())
    thumbprint = agent_auth.jwk_thumbprint(_jwk(key))
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="identity-bound endpoint",
            is_active=True, enrolled_at=datetime.now(timezone.utc),
            agent_key_thumbprint=thumbprint,
        ))
        await db.commit()

    body = _body(_telemetry_payload(
        device_id="attacker-selected-device",
        cpu_percent=20.0,
        memory_percent=30.0,
        disk_percent=40.0,
    ))
    headers, _ = _headers(
        monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write", path="/agent/v1/telemetry", body=body, device_key=key,
    )
    async with await _client() as client:
        response = await client.post("/agent/v1/telemetry", content=body, headers=headers)

    assert response.status_code == 403
    async with AsyncSessionLocal() as db:
        assert await db.scalar(select(TelemetryRecord.id).where(
            TelemetryRecord.device_id == device_id
        )) is None


@pytest.mark.asyncio
async def test_schema_v2_network_signals_create_trusted_tenant_bound_findings(monkeypatch):
    from models.threat_finding import ThreatFinding

    device_id = "agent-network-signals-01"
    key = ec.generate_private_key(ec.SECP256R1())
    thumbprint = agent_auth.jwk_thumbprint(_jwk(key))
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="network telemetry endpoint",
            is_active=True, enrolled_at=datetime.now(timezone.utc),
            agent_key_thumbprint=thumbprint, agent_version="2.1.0",
        ))
        await db.commit()

    payload = _telemetry_payload(
        schema_version="2",
        cpu_percent=20.0,
        memory_percent=45.0,
        disk_percent=60.0,
        network_signals=[{
            "src_ip": "203.0.113.10",
            "protocol": "QUIC",
            "entropy": 7.8,
            "z_score": 12.0,
            "beacon_interval": 30,
            "jitter": 0.1,
        }],
    )
    body = _body(payload)
    headers, _ = _headers(
        monkeypatch,
        device_id=device_id,
        tenant_id="test-tenant",
        scope="aurontra:telemetry:write aurontra:threat:write",
        path="/agent/v1/telemetry",
        body=body,
        device_key=key,
    )
    async with await _client() as client:
        response = await client.post("/agent/v1/telemetry", content=body, headers=headers)

    assert response.status_code == 200, response.text
    finding_result = response.json()["threat_findings"]
    assert len(finding_result) == 1
    async with AsyncSessionLocal() as db:
        finding = await db.get(ThreatFinding, finding_result[0]["id"])
        record = await db.get(TelemetryRecord, response.json()["telemetry_id"])
        assert finding.source == "endpoint_agent"
        assert finding.device_id == device_id
        assert finding.telemetry_record_id == record.id
        assert finding.containment_verified is False
        assert finding.assessment["blocked"] is False
        assert record.metrics["network_signals"][0]["protocol"] == "QUIC"


@pytest.mark.asyncio
async def test_network_signal_ingestion_requires_v2_and_explicit_scope(monkeypatch):
    device_id = "agent-network-scope-01"
    key = ec.generate_private_key(ec.SECP256R1())
    thumbprint = agent_auth.jwk_thumbprint(_jwk(key))
    async with AsyncSessionLocal() as db:
        db.add(Device(
            id=device_id, org_id="test-tenant", name="network scope endpoint",
            is_active=True, enrolled_at=datetime.now(timezone.utc),
            agent_key_thumbprint=thumbprint, agent_version="2.1.0",
        ))
        await db.commit()

    invalid_v1 = _telemetry_payload(
        schema_version="1", cpu_percent=20.0, memory_percent=45.0, disk_percent=60.0,
        network_signals=[{"src_ip": "203.0.113.11", "protocol": "QUIC", "entropy": 7.2}],
    )
    body = _body(invalid_v1)
    headers, _ = _headers(
        monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write aurontra:threat:write",
        path="/agent/v1/telemetry", body=body, device_key=key,
    )
    async with await _client() as client:
        version_response = await client.post("/agent/v1/telemetry", content=body, headers=headers)
    assert version_response.status_code == 422

    valid_v2 = _telemetry_payload(
        schema_version="2", cpu_percent=20.0, memory_percent=45.0, disk_percent=60.0,
        network_signals=[{"src_ip": "203.0.113.11", "protocol": "QUIC", "entropy": 7.2}],
    )
    body2 = _body(valid_v2)
    headers2, _ = _headers(
        monkeypatch, device_id=device_id, tenant_id="test-tenant",
        scope="aurontra:telemetry:write",
        path="/agent/v1/telemetry", body=body2, device_key=key,
    )
    async with await _client() as client:
        scope_response = await client.post("/agent/v1/telemetry", content=body2, headers=headers2)
    assert scope_response.status_code == 403
