"""
Hash-chained audit log — every action produces an immutable record.
Each entry hashes the previous entry's hash (chain integrity).
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def make_audit_entry(
    action: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    payload: dict,
    previous_hash: Optional[str] = None,
) -> dict:
    """
    Build a signed, hash-chained audit entry.

    Args:
        action:        e.g. 'ticket.resolved', 'threat.blocked', 'device.scored'
        actor_id:      user ID or 'system' for automated actions
        resource_type: 'ticket' | 'device' | 'threat' | 'playbook'
        resource_id:   UUID of the affected resource
        payload:       arbitrary dict of event data
        previous_hash: last entry's hash (None for first entry)

    Returns:
        Audit dict ready to persist to DB or emit to SIEM.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    body = {
        "timestamp": timestamp,
        "action": action,
        "actor_id": actor_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "payload": payload,
        "previous_hash": previous_hash or "GENESIS",
    }
    body["hash"] = _sha256(json.dumps(body, sort_keys=True))
    return body


def verify_chain(entries: list[dict]) -> bool:
    """
    Verify a list of audit entries form a valid hash chain.
    Returns True if chain is intact, False if tampered.
    """
    if not entries:
        return True

    for i, entry in enumerate(entries):
        # Verify each entry's own hash
        body = {k: v for k, v in entry.items() if k != "hash"}
        expected = _sha256(json.dumps(body, sort_keys=True))
        if entry.get("hash") != expected:
            return False

        # Verify chain link
        if i > 0:
            expected_prev = entries[i - 1]["hash"]
            if entry.get("previous_hash") != expected_prev:
                return False

    return True
