"""Fail-closed HTTP client for versioned Tinlance ecosystem integrations.

Only preconfigured service origins are accepted. Production calls require HTTPS
and a per-service bearer credential. Retries are limited to safe methods or
requests carrying an explicit idempotency key.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from core.config import settings
from core.tsic_contracts import TSICIdentityContext, validate_event_envelope

logger = logging.getLogger(__name__)
CONTRACT_VERSION = "1.0.0"
_TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_CORRELATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MAX_RESPONSE_BYTES = 1_048_576
RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


class EcosystemIntegrationError(RuntimeError):
    """Sanitized integration failure; never embeds URLs, credentials, or bodies."""

    def __init__(self, code: str, status_code: int = 503) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass
class _Circuit:
    failures: int = 0
    opened_at: float | None = None
    lock: asyncio.Lock | None = None
    probe_in_flight: bool = False


_CIRCUITS: dict[str, _Circuit] = {}


def reset_circuits_for_tests() -> None:
    """Reset process-local circuit state. Intended for deterministic tests only."""
    _CIRCUITS.clear()


def _config() -> dict[str, str]:
    try:
        raw = json.loads(settings.BRIDGE_AUTH_TOKENS_JSON or "{}")
    except (TypeError, ValueError):
        raise EcosystemIntegrationError("bridge_credentials_configuration_invalid", 503) from None
    if not isinstance(raw, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in raw.items()
    ):
        raise EcosystemIntegrationError("bridge_credentials_configuration_invalid", 503)
    return raw


_SERVICE_ORIGIN_SETTINGS = {
    "threatfade": "THREATFADE_URL",
    "fusionops": "FUSIONOPS_URL",
}


def _validate_origin(service: str, base_url: str) -> str:
    if not isinstance(service, str) or service not in _SERVICE_ORIGIN_SETTINGS:
        raise EcosystemIntegrationError("bridge_service_invalid", 503)
    if not isinstance(base_url, str) or not base_url:
        raise EcosystemIntegrationError("bridge_not_configured", 503)
    configured_url = getattr(settings, _SERVICE_ORIGIN_SETTINGS[service], "")
    if not isinstance(configured_url, str) or not configured_url:
        raise EcosystemIntegrationError("bridge_not_configured", 503)
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise EcosystemIntegrationError("bridge_origin_invalid", 503)
    if parsed.scheme != "https" and (
        settings.ENVIRONMENT.lower() == "production" or not settings.BRIDGE_ALLOW_INSECURE_HTTP
    ):
        raise EcosystemIntegrationError("bridge_https_required", 503)
    if parsed.path not in {"", "/"}:
        raise EcosystemIntegrationError("bridge_origin_must_not_include_path", 503)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    configured = urlsplit(configured_url)
    configured_origin = (
        f"{configured.scheme}://{configured.netloc}"
        if configured.scheme and configured.netloc else ""
    )
    if origin != configured_origin:
        raise EcosystemIntegrationError("bridge_origin_not_allowlisted", 403)
    return origin


def _circuit(service: str) -> _Circuit:
    circuit = _CIRCUITS.get(service)
    if circuit is None:
        circuit = _Circuit(lock=asyncio.Lock())
        _CIRCUITS[service] = circuit
    return circuit


async def request_json(
    *,
    service: str,
    base_url: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
    traceparent: str | None = None,
    correlation_id: str | None = None,
    identity_context: TSICIdentityContext | None = None,
    timeout_seconds: float | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Any:
    """Call a configured service with auth, bounded retry, and a circuit breaker.

    Tenant-scoped calls require identity_context built from verified server-side
    authentication state; never populate it from caller-controlled request data.
    """
    method = method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise EcosystemIntegrationError("bridge_method_not_allowed", 405)
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or ".." in path.split("/"):
        raise EcosystemIntegrationError("bridge_path_invalid", 400)

    origin = _validate_origin(service, base_url)
    tokens = _config()
    token = tokens.get(service, "")
    if not token or len(token) < 24:
        raise EcosystemIntegrationError("bridge_credentials_missing", 503)

    verified_context: TSICIdentityContext | None = None
    if identity_context is not None:
        if not isinstance(identity_context, TSICIdentityContext):
            raise EcosystemIntegrationError("bridge_identity_context_invalid", 400)
        verified_context = identity_context
    elif path not in {"/health", "/health/live"}:
        raise EcosystemIntegrationError("bridge_identity_context_missing", 503)

    if path.rstrip("/").endswith("/events") and payload is not None:
        if verified_context is None:
            raise EcosystemIntegrationError("bridge_identity_context_missing", 503)
        try:
            validate_event_envelope(payload, verified_context)
        except ValidationError:
            raise EcosystemIntegrationError("bridge_event_envelope_invalid", 400) from None
        except ValueError:
            raise EcosystemIntegrationError("bridge_event_context_mismatch", 403) from None
    if idempotency_key is not None and (
        not isinstance(idempotency_key, str) or not _IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key)
    ):
        raise EcosystemIntegrationError("bridge_idempotency_key_invalid", 400)
    retry_safe = method in {"GET", "PUT", "DELETE"} or (
        method in {"POST", "PATCH"} and isinstance(idempotency_key, str)
        and 1 <= len(idempotency_key) <= 128
    )
    request_id = __import__("uuid").uuid4().hex
    if correlation_id is not None and (
        not isinstance(correlation_id, str) or not _CORRELATION_ID_RE.fullmatch(correlation_id)
    ):
        raise EcosystemIntegrationError("bridge_correlation_id_invalid", 400)
    if verified_context is not None and correlation_id is not None and correlation_id != verified_context.correlation_id:
        raise EcosystemIntegrationError("bridge_identity_context_mismatch", 403)

    if traceparent is None:
        trace_id = verified_context.trace_id if verified_context is not None else __import__("uuid").uuid4().hex
        span_id = __import__("uuid").uuid4().hex[:16]
        traceparent = f"00-{trace_id}-{span_id}-01"
    else:
        match = _TRACEPARENT_RE.fullmatch(traceparent) if isinstance(traceparent, str) else None
        if match is None or match.group(1) == "0" * 32 or match.group(2) == "0" * 16:
            raise EcosystemIntegrationError("bridge_trace_context_invalid", 400)
        trace_id, span_id = match.group(1), match.group(2)
        if verified_context is not None and trace_id != verified_context.trace_id:
            raise EcosystemIntegrationError("bridge_identity_context_mismatch", 403)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "X-Tinlance-Contract-Version": CONTRACT_VERSION,
        "X-Request-ID": request_id,
        "X-Correlation-ID": verified_context.correlation_id if verified_context is not None else (correlation_id or request_id),
        "traceparent": traceparent,
        "X-Trace-ID": trace_id,
        "X-Span-ID": span_id,
    }
    if verified_context is not None:
        headers.update({
            "X-Tinlance-Tenant-ID": verified_context.tenant_id,
            "X-Tinlance-Organization-ID": verified_context.organization_id,
            "X-Tinlance-Workspace-ID": verified_context.workspace_id,
            "X-Tinlance-Actor-ID": verified_context.actor_id,
            "X-Tinlance-Execution-ID": verified_context.execution_id,
        })
        if verified_context.agent_id:
            headers["X-Tinlance-Agent-ID"] = verified_context.agent_id
        if verified_context.service_id:
            headers["X-Tinlance-Service-ID"] = verified_context.service_id
        if verified_context.causation_id:
            headers["X-Tinlance-Causation-ID"] = verified_context.causation_id

    if idempotency_key and retry_safe:
        headers["Idempotency-Key"] = idempotency_key

    circuit = _circuit(service)
    async with circuit.lock:
        if circuit.opened_at is not None:
            if time.monotonic() - circuit.opened_at < 30:
                raise EcosystemIntegrationError("bridge_circuit_open", 503)
            if circuit.probe_in_flight:
                raise EcosystemIntegrationError("bridge_circuit_half_open", 503)
            circuit.probe_in_flight = True
            circuit.failures = 0
        # When closed, requests remain concurrent. Only state transitions are locked.

    attempts = 3 if retry_safe else 1
    timeout = max(0.1, min(float(timeout_seconds or settings.BRIDGE_TIMEOUT), 30.0))
    try:
        for attempt in range(attempts):
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(timeout), transport=transport, follow_redirects=False,
                    limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
                ) as client:
                    async with client.stream(
                        method, f"{origin}{path}", json=payload, params=params, headers=headers,
                    ) as response:
                        if response.status_code in RETRYABLE_STATUS:
                            raise EcosystemIntegrationError("bridge_upstream_retryable", 503)
                        if response.status_code < 200 or response.status_code >= 300:
                            # A valid 4xx is a contract/auth/business rejection, not evidence
                            # that the service is unhealthy; don't trip the circuit breaker.
                            raise EcosystemIntegrationError("bridge_upstream_rejected", 502)
                        body = bytearray()
                        async for chunk in response.aiter_bytes(chunk_size=64 * 1024):
                            if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                                raise EcosystemIntegrationError("bridge_response_too_large", 502)
                            body.extend(chunk)
                try:
                    result = json.loads(body)
                except (ValueError, json.JSONDecodeError):
                    raise EcosystemIntegrationError("bridge_response_invalid_json", 502) from None
                async with circuit.lock:
                    circuit.failures = 0
                    circuit.opened_at = None
                    circuit.probe_in_flight = False
                return result
            except EcosystemIntegrationError as exc:
                if exc.code == "bridge_upstream_rejected":
                    # An upstream HTTP response proves reachability, even when it
                    # rejects the business request. Close a half-open circuit.
                    async with circuit.lock:
                        circuit.failures = 0
                        circuit.opened_at = None
                        circuit.probe_in_flight = False
                    raise
                if exc.code == "bridge_response_too_large":
                    async with circuit.lock:
                        was_probe = circuit.probe_in_flight
                        circuit.failures += 1
                        circuit.probe_in_flight = False
                        if was_probe or circuit.failures >= 5:
                            circuit.opened_at = time.monotonic()
                    raise
                if exc.code not in {"bridge_upstream_retryable", "bridge_response_invalid_json"}:
                    async with circuit.lock:
                        circuit.probe_in_flight = False
                    raise
                if attempt + 1 >= attempts:
                    async with circuit.lock:
                        was_probe = circuit.probe_in_flight
                        circuit.failures += 1
                        circuit.probe_in_flight = False
                        if was_probe or circuit.failures >= 5:
                            circuit.opened_at = time.monotonic()
                    raise
            except (httpx.TimeoutException, httpx.TransportError):
                if attempt + 1 >= attempts:
                    async with circuit.lock:
                        was_probe = circuit.probe_in_flight
                        circuit.failures += 1
                        circuit.probe_in_flight = False
                        if was_probe or circuit.failures >= 5:
                            circuit.opened_at = time.monotonic()
                    raise EcosystemIntegrationError("bridge_transport_failure", 503) from None
            await asyncio.sleep(0.05 * (attempt + 1))
    finally:
        async with circuit.lock:
            # If an exception escaped without a recorded terminal failure, release
            # a half-open probe so the circuit cannot become permanently wedged.
            circuit.probe_in_flight = False
    raise EcosystemIntegrationError("bridge_transport_failure", 503)
