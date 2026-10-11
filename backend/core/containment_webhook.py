"""HMAC verification for authenticated tenant-bound control-plane webhooks."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from typing import Any

from core.config import settings

_SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
_ALLOWED_SOURCES = {"network_control_plane", "cloud_control_plane"}


class ContainmentWebhookAuthError(ValueError):
    def __init__(self, code: str, status_code: int = 401) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def configured_source(source_id: str) -> dict[str, Any]:
    if not isinstance(source_id, str) or not _SOURCE_RE.fullmatch(source_id):
        raise ContainmentWebhookAuthError("invalid_source_id")
    if not 1 <= settings.THREAT_VERIFIER_MAX_SKEW_SECONDS <= 300:
        raise ContainmentWebhookAuthError("verifier_clock_skew_configuration_invalid", 503)
    try:
        config = json.loads(settings.THREAT_VERIFIER_HMAC_KEYS_JSON or "{}")
    except (TypeError, json.JSONDecodeError):
        raise ContainmentWebhookAuthError("verifier_key_configuration_invalid", 503) from None
    if not isinstance(config, dict):
        raise ContainmentWebhookAuthError("verifier_key_configuration_invalid", 503)
    entry = config.get(source_id)
    if not isinstance(entry, dict):
        raise ContainmentWebhookAuthError("unknown_verifier_source")
    tenant_id = entry.get("tenant_id")
    key_id = entry.get("key_id")
    secret = entry.get("secret")
    source_type = entry.get("source_type")
    if (
        not isinstance(tenant_id, str) or not tenant_id
        or not isinstance(key_id, str) or not _SOURCE_RE.fullmatch(key_id)
        or not isinstance(secret, str) or len(secret.encode("utf-8")) < 32
        or source_type not in _ALLOWED_SOURCES
    ):
        raise ContainmentWebhookAuthError("verifier_key_configuration_invalid", 503)
    return {
        "source_id": source_id,
        "tenant_id": tenant_id,
        "key_id": key_id,
        "secret": secret.encode("utf-8"),
        "source_type": source_type,
    }


def verify_signature(
    *,
    raw_body: bytes,
    timestamp_header: str | None,
    nonce: str | None,
    signature_header: str | None,
    source: dict[str, Any],
    request_tenant_id: str,
) -> tuple[str, str]:
    if source["tenant_id"] != request_tenant_id:
        raise ContainmentWebhookAuthError("verifier_tenant_mismatch", 403)
    if not timestamp_header or not timestamp_header.isdigit():
        raise ContainmentWebhookAuthError("verifier_timestamp_invalid")
    if not nonce or not _NONCE_RE.fullmatch(nonce):
        raise ContainmentWebhookAuthError("verifier_nonce_invalid")
    if not signature_header:
        raise ContainmentWebhookAuthError("verifier_signature_missing")
    timestamp = int(timestamp_header)
    if abs(int(time.time()) - timestamp) > settings.THREAT_VERIFIER_MAX_SKEW_SECONDS:
        raise ContainmentWebhookAuthError("verifier_timestamp_out_of_window")
    signature = signature_header.removeprefix("sha256=").strip()
    if not _HEX_RE.fullmatch(signature):
        raise ContainmentWebhookAuthError("verifier_signature_invalid")
    message = timestamp_header.encode("ascii") + b"\n" + nonce.encode("ascii") + b"\n" + raw_body
    expected = hmac.new(source["secret"], message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature.lower()):
        raise ContainmentWebhookAuthError("verifier_signature_invalid")
    return nonce, hashlib.sha256(raw_body).hexdigest()
