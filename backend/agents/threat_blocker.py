"""
Aurontra threat assessment and SIEM serialization.

Signal scoring produces a risk assessment and optional containment
recommendation only. It does not enforce network or endpoint controls.
A containment claim is valid only when an independent enforcement adapter
reports success and a postcondition check verifies the resulting state.
"""
import ipaddress
import math
import re
import uuid
from datetime import datetime, timezone
from numbers import Real
from typing import Optional
import bridges.threatfade as threatfade_bridge

# ── MITRE ATT&CK TTP mapping table ────────────────────────────────────
_PROTOCOL_TTP_MAP = {
    "QUIC":  "T1071.001",  # Application Layer Protocol: Web Protocols
    "DNS":   "T1071.004",  # Application Layer Protocol: DNS
    "ICMP":  "T1095",      # Non-Application Layer Protocol
    "SMB":   "T1021.002",  # Remote Services: SMB/Windows Admin Shares
    "RDP":   "T1021.001",  # Remote Services: Remote Desktop Protocol
    "SSH":   "T1021.004",  # Remote Services: SSH
    "HTTP":  "T1071.001",
    "HTTPS": "T1071.001",
}

_TAG_TTP_MAP = {
    "lateral_movement": "T1021",
    "obfuscation":      "T1027",
    "exfiltration":     "T1041",
    "persistence":      "T1053",
    "privilege_esc":    "T1068",
    "c2":               "T1071",
    "discovery":        "T1082",
}

# Thresholds
_CONTAINMENT_RECOMMENDATION_SCORE = 65  # Recommendation threshold; never executes a block
_HIGH_THREAT_SCORE = 60     # Score at or above this → high threat level
_MEDIUM_THREAT_SCORE = 35   # Score at or above this → medium


def map_mitre_ttp(
    protocol: str = "",
    entropy: float = 0.0,
    z_score: float = 0.0,
    tags: list[str] | None = None,
) -> str:
    """
    Map signal characteristics to the most relevant MITRE ATT&CK TTP.
    Returns a TTP string like 'T1071.001'.
    """
    protocol = str(protocol or "").upper()
    tags = tags or []

    # Tag-based mapping takes priority
    for tag in tags:
        if tag in _TAG_TTP_MAP:
            return _TAG_TTP_MAP[tag]

    # High z-score + high entropy → C2 Application Layer Protocol
    if z_score >= 5.0 or entropy >= 6.5:
        return _PROTOCOL_TTP_MAP.get(protocol.upper(), "T1071.001")

    # Protocol-based fallback
    if protocol.upper() in _PROTOCOL_TTP_MAP:
        return _PROTOCOL_TTP_MAP[protocol.upper()]

    # Generic catch-all
    return "T1071"


def _score_components(signal: dict) -> dict[str, int]:
    """Return deterministic component points without mutating caller-owned evidence."""
    z = float(signal.get("z_score", 0))
    if z >= 10.0:
        z_points = 40
    elif z >= 5.0:
        z_points = 25
    elif z >= 2.0:
        z_points = 12
    elif z >= 1.0:
        z_points = 5
    else:
        z_points = 0

    entropy = float(signal.get("entropy", 0))
    if entropy >= 7.5:
        entropy_points = 35
    elif entropy >= 6.5:
        entropy_points = 25
    elif entropy >= 5.0:
        entropy_points = 12
    elif entropy >= 3.5:
        entropy_points = 5
    else:
        entropy_points = 0

    protocol = str(signal.get("protocol", "")).upper()
    protocol_points = {"QUIC": 15, "ICMP": 12, "DNS": 8, "SMB": 10, "RDP": 10}.get(protocol, 0)

    periodicity_points = 0
    if "beacon_interval" in signal and "jitter" in signal:
        jitter = float(signal.get("jitter", 1.0))
        if jitter < 0.2:
            periodicity_points = 10
        elif jitter < 0.5:
            periodicity_points = 5

    return {
        "z_score_points": z_points,
        "entropy_points": entropy_points,
        "protocol_risk_points": protocol_points,
        "periodicity_points": periodicity_points,
    }


def _compute_score(signal: dict) -> int:
    """Compute the legacy 0-100 heuristic score. It is not a probability."""
    return min(100, sum(_score_components(signal).values()))

def _normalize_signal(signal: dict) -> dict:
    """Validate and canonicalize supported evidence fields before scoring."""
    if not isinstance(signal, dict):
        raise ValueError("Signal must be an object.")
    allowed = {"src_ip", "dst_port", "protocol", "bytes_out", "entropy", "z_score", "beacon_interval", "jitter"}
    unknown = set(signal) - allowed
    if unknown:
        raise ValueError("Signal contains unsupported fields.")
    normalized = dict(signal)

    if normalized.get("src_ip") is not None:
        try:
            normalized["src_ip"] = str(ipaddress.ip_address(str(normalized["src_ip"])))
        except ValueError as exc:
            raise ValueError("src_ip must be a valid IPv4 or IPv6 address.") from exc

    if normalized.get("protocol") is not None:
        protocol = str(normalized["protocol"]).strip().upper()
        if len(protocol) > 16 or (protocol and not re.fullmatch(r"[A-Z0-9._-]+", protocol)):
            raise ValueError("protocol must be a short protocol token.")
        normalized["protocol"] = protocol

    bounds = {
        "entropy": (0.0, 8.0),
        "z_score": (-20.0, 100.0),
        "jitter": (0.0, 1.0),
    }
    for key, (minimum, maximum) in bounds.items():
        if key not in normalized:
            continue
        if normalized[key] is None:
            normalized.pop(key)
            continue
        value = normalized[key]
        if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(float(value)):
            raise ValueError(f"{key} must be a finite number.")
        if not minimum <= float(value) <= maximum:
            raise ValueError(f"{key} is outside the supported range.")
        normalized[key] = float(value)

    integer_bounds = {
        "dst_port": (1, 65535),
        "bytes_out": (0, 9223372036854775807),
        "beacon_interval": (1, 86400),
    }
    for key, (minimum, maximum) in integer_bounds.items():
        if key not in normalized:
            continue
        if normalized[key] is None:
            normalized.pop(key)
            continue
        value = normalized[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{key} must be an integer.")
        if not minimum <= value <= maximum:
            raise ValueError(f"{key} is outside the supported range.")
    return normalized


def analyse_signal(signal: dict) -> dict:
    """
    Analyse a raw network/telemetry signal and return a threat assessment.

    Args:
        signal: dict with any of: src_ip, protocol, entropy, z_score,
                beacon_interval, jitter, bytes_out

    Returns:
        dict: threat_level, score, mitre_ttp, containment_recommended, reason
    """
    if not signal:
        return {
            "threat_level": "info",
            "score": 0,
            "score_components": {
                "z_score_points": 0,
                "entropy_points": 0,
                "protocol_risk_points": 0,
                "periodicity_points": 0,
            },
            "detector_version": "heuristic-threat-score.v2",
            "score_semantics": "heuristic_0_to_100_not_probability",
            "periodic_pattern": False,
            "mitre_ttp": "T1071",
            "auto_block": False,
            "containment_recommended": False,
            "reason": "No signal data provided",
        }

    signal = _normalize_signal(signal)
    score_components = _score_components(signal)
    score = min(100, sum(score_components.values()))
    periodic_pattern = (
        "beacon_interval" in signal
        and "jitter" in signal
        and float(signal.get("jitter", 1.0)) < 0.2
    )

    # A periodic pattern may lower the recommendation threshold, but does not
    # confirm C2 and never authorizes an enforcement action by itself.
    recommendation_threshold = 55 if periodic_pattern else _CONTAINMENT_RECOMMENDATION_SCORE
    if score >= _HIGH_THREAT_SCORE:
        threat_level = "critical" if score >= 80 else "high"
    elif score >= _MEDIUM_THREAT_SCORE:
        threat_level = "medium"
    elif score > 0:
        threat_level = "low"
    else:
        threat_level = "info"

    containment_recommended = score >= recommendation_threshold

    ttp = map_mitre_ttp(
        protocol=signal.get("protocol", ""),
        entropy=float(signal.get("entropy", 0)),
        z_score=float(signal.get("z_score", 0)),
    )

    reasons = []
    if signal.get("z_score", 0) >= 5.0:
        reasons.append(f"Z-score {signal['z_score']:.2f} exceeds C2 threshold")
    if signal.get("entropy", 0) >= 6.5:
        reasons.append(f"Entropy {signal['entropy']:.2f} indicates obfuscation")
    if str(signal.get("protocol") or "").upper() == "QUIC":
        reasons.append("QUIC protocol observed; protocol alone is not evidence of malicious activity")
    if "beacon_interval" in signal:
        reasons.append("Regular beacon interval detected")
    if not reasons:
        reasons.append("Signal within normal parameters")

    return {
        "threat_level": threat_level,
        "score": score,
        "score_components": score_components,
        "detector_version": "heuristic-threat-score.v2",
        "score_semantics": "heuristic_0_to_100_not_probability",
        "periodic_pattern": periodic_pattern,
        "mitre_ttp": ttp,
        # Keep the legacy field false so clients cannot confuse a score with an action.
        "auto_block": False,
        "containment_recommended": containment_recommended,
        "reason": "; ".join(reasons),
    }


async def block_threat(
    event_id: str,
    src_ip: str,
    scenario: str,
    org_id: str,
    additional_context: dict | None = None,
) -> dict:
    """Create a threat assessment; never claim enforcement without an adapter.

    This compatibility function is decision-only. A score or ThreatFade verdict
    is not evidence that a firewall, network control, or endpoint actually
    blocked the traffic. Verified containment will be implemented by a separate
    enforcement adapter with acknowledgements and postcondition checks.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    base = {
        "event_id": event_id,
        "src_ip": src_ip,
        "scenario": scenario,
        "org_id": org_id,
        "timestamp": timestamp,
        "blocked": False,
        "action_taken": "monitor",
        "status": "analysis_pending",
        "enforcement_verified": False,
        "threat_level": "info",
        "score": 0,
        "mitre_ttp": "T1071",
    }

    try:
        tf_result = await threatfade_bridge.detect_scenario(scenario)
    except Exception:
        # Do not return internal bridge errors or misrepresent a failed
        # dependency call as a successful detection/containment.
        base.update({
            "status": "analysis_unavailable",
            "action_taken": "monitor",
            "blocked": False,
            "enforcement_verified": False,
            # Stable error code only; never echo exception text or provider details.
            "error": "bridge_unavailable",
        })
        return base

    signal = {
        "src_ip": src_ip,
        "protocol": tf_result.get("protocol", "HTTPS"),
        "z_score": tf_result.get("z_score", 0),
        "entropy": tf_result.get("entropy", 0),
        **(additional_context or {}),
    }
    assessment = analyse_signal(signal)
    tf_level = tf_result.get("threat_level", "info")
    level_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    final_level = (
        tf_level
        if level_rank.get(tf_level, 0) >= level_rank.get(assessment["threat_level"], 0)
        else assessment["threat_level"]
    )
    should_request_containment = assessment["containment_recommended"] or final_level in ("high", "critical")
    base.update({
        "blocked": False,
        "action_taken": "containment_pending" if should_request_containment else "monitor",
        "status": "containment_pending" if should_request_containment else "assessed",
        "requested_action": "block" if should_request_containment else None,
        "enforcement_verified": False,
        "threat_level": final_level,
        "score": assessment["score"],
        "mitre_ttp": map_mitre_ttp(
            protocol=signal.get("protocol", ""),
            entropy=signal.get("entropy", 0),
            z_score=signal.get("z_score", 0),
        ),
        "reason": assessment["reason"],
        "threatfade_verdict": tf_result,
    })
    return base

def export_siem(event: dict, fmt: str = "json") -> dict:
    """
    Export a threat event in the requested SIEM format.

    Supported formats: json | splunk_hec | cef

    Args:
        event: threat event dict (from block_threat or analyse_signal)
        fmt:   target SIEM format

    Returns:
        dict with 'format' and 'payload' keys

    Raises:
        ValueError: if format is not supported
    """
    supported = ("json", "splunk_hec", "cef")
    if fmt not in supported:
        raise ValueError(f"Unsupported SIEM format '{fmt}'. Supported: {supported}")

    # Never serialize caller-supplied "blocked": true as proof of containment.
    # Only a trusted internal record with explicit enforcement verification may
    # carry a positive containment claim. Public route input cannot set this flag.
    event = dict(event)
    enforcement_verified = event.get("enforcement_verified") is True
    caller_claimed_containment = (
        event.get("blocked") is True
        or event.get("requested_action") == "block"
        or event.get("status") in {"blocked", "contained", "quarantined"}
        or event.get("action_taken") in {"blocked", "contained", "quarantined"}
    )
    verified_block = caller_claimed_containment and enforcement_verified
    event["enforcement_verified"] = enforcement_verified
    event["blocked"] = verified_block
    event["containment_verified"] = verified_block
    if verified_block:
        event["status"] = "contained"
        event["action_taken"] = "blocked"
    elif caller_claimed_containment:
        event["status"] = "containment_pending"
        event["action_taken"] = "containment_pending"
    else:
        # Untrusted event input cannot preserve a false "contained" status or
        # blocked action label when there is no verified enforcement record.
        if event.get("status") in {"blocked", "contained", "quarantined"}:
            event["status"] = "assessed"
        if event.get("action_taken") in {"blocked", "contained", "quarantined"}:
            event["action_taken"] = "monitor"
        event.setdefault("status", "assessed")
        event.setdefault("action_taken", "monitor")

    if fmt == "json":
        return {"format": "json", "payload": event}

    if fmt == "splunk_hec":
        return {
            "format": "splunk_hec",
            "payload": {
                "time": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "host": event.get("src_ip", "unknown"),
                "source": "aurontra",
                "sourcetype": "aurontra:threat",
                "index": "security",
                "event": event,
            },
        }

    if fmt == "cef":
        severity_map = {"info": 0, "low": 3, "medium": 5, "high": 7, "critical": 10}
        sev = severity_map.get(event.get("threat_level", "info"), 0)
        cef_str = (
            f"CEF:0|Tinlance|Aurontra|0.1.0|{event.get('mitre_ttp', 'T1071')}|"
            f"Threat {event.get('threat_level', 'info')}|{sev}|"
            f"src={event.get('src_ip', 'unknown')} "
            f"act={event.get('action_taken', 'monitor')} "
            f"msg={event.get('reason', 'Threat assessment')} "
            f"externalId={event.get('event_id', 'unknown')}"
        )
        return {"format": "cef", "payload": cef_str}
