"""
Unit tests for hash-chained audit log.
RED → GREEN cycle.
"""
import pytest
from core.audit import make_audit_entry, verify_chain


class TestAuditEntry:
    def test_entry_has_all_fields(self):
        entry = make_audit_entry(
            action="ticket.resolved",
            actor_id="system",
            resource_type="ticket",
            resource_id="tkt-001",
            payload={"resolution": "Password reset applied"},
        )
        assert entry["action"] == "ticket.resolved"
        assert entry["actor_id"] == "system"
        assert entry["resource_type"] == "ticket"
        assert entry["resource_id"] == "tkt-001"
        assert "timestamp" in entry
        assert "hash" in entry

    def test_entry_hash_is_deterministic(self):
        """Same input should not produce same hash — timestamps differ."""
        e1 = make_audit_entry("x", "sys", "t", "1", {})
        e2 = make_audit_entry("x", "sys", "t", "1", {})
        # Timestamps will differ — hashes should too
        # But each entry's own hash must match its body
        import hashlib, json
        body = {k: v for k, v in e1.items() if k != "hash"}
        assert e1["hash"] == hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

    def test_genesis_entry_has_genesis_previous_hash(self):
        entry = make_audit_entry("start", "sys", "system", "0", {})
        assert entry["previous_hash"] == "GENESIS"

    def test_chained_entry_carries_previous_hash(self):
        e1 = make_audit_entry("first", "sys", "t", "1", {})
        e2 = make_audit_entry("second", "sys", "t", "2", {}, previous_hash=e1["hash"])
        assert e2["previous_hash"] == e1["hash"]


class TestVerifyChain:
    def test_empty_chain_is_valid(self):
        assert verify_chain([]) is True

    def test_single_entry_chain_is_valid(self):
        e = make_audit_entry("act", "sys", "t", "1", {})
        assert verify_chain([e]) is True

    def test_valid_two_entry_chain(self):
        e1 = make_audit_entry("first", "sys", "t", "1", {})
        e2 = make_audit_entry("second", "sys", "t", "2", {}, previous_hash=e1["hash"])
        assert verify_chain([e1, e2]) is True

    def test_tampered_entry_fails_verification(self):
        e1 = make_audit_entry("first", "sys", "t", "1", {})
        e2 = make_audit_entry("second", "sys", "t", "2", {}, previous_hash=e1["hash"])
        # Tamper with e1's payload after the fact
        e1["payload"]["injected"] = "malicious"
        assert verify_chain([e1, e2]) is False

    def test_broken_chain_link_fails_verification(self):
        e1 = make_audit_entry("first", "sys", "t", "1", {})
        e2 = make_audit_entry("second", "sys", "t", "2", {}, previous_hash="wrong-hash")
        assert verify_chain([e1, e2]) is False

    def test_five_entry_chain_is_valid(self):
        chain = []
        prev_hash = None
        for i in range(5):
            e = make_audit_entry(f"action_{i}", "sys", "t", str(i), {"i": i}, previous_hash=prev_hash)
            chain.append(e)
            prev_hash = e["hash"]
        assert verify_chain(chain) is True
