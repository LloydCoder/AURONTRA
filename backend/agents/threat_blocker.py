"""
Threat Blocking Agent — Sprint 3 core deliverable.

Pipeline:
  1. map_mitre_ttp()   — maps signal characteristics to MITRE ATT&CK TTPs
  2. analyse_signal()  — scores raw signal, decides auto_block threshold
  3. block_threat()    — calls ThreatFade bridge, executes block decision
  4. export_siem()     — emits event in JSON / Splunk HEC / CEF format

ThreatFade bridge is the detection oracle (Z-score 14.76, 0% FPR).
ResilientAI adds the blocking decision layer + SIEM export on top.
"""
import uuid
from datetime import datetime, timezone
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
_AUTO_BLOCK_SCORE = 65      # Score at or above this → auto block
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


def _compute_score(signal: dict) -> int:
    """
    Compute a 0-100 threat score from raw signal data.
    Weights: z_score (40%), entropy (35%), protocol risk (15%), beacon pattern (10%)
    """
    score = 0

    # Z-score contribution (0-40 pts)
    z = float(signal.get("z_score", 0))
    if z >= 10.0:
        score += 40
    elif z >= 5.0:
        score += 25
    elif z >= 2.0:
        score += 12
    elif z >= 1.0:
        score += 5

    # Entropy contribution (0-35 pts) — high entropy = obfuscated/encrypted C2
    e = float(signal.get("entropy", 0))
    if e >= 7.5:
        score += 35
    elif e >= 6.5:
        score += 25
    elif e >= 5.0:
        score += 12
    elif e >= 3.5:
        score += 5

    # Protocol risk (0-15 pts)
    proto = signal.get("protocol", "").upper()
    proto_risk = {"QUIC": 15, "ICMP": 12, "DNS": 8, "SMB": 10, "RDP": 10}
    score += proto_risk.get(proto, 0)

    # Beacon pattern (0-10 pts) — regular interval + low jitter = C2 beacon
    if "beacon_interval" in signal and "jitter" in signal:
        jitter = float(signal.get("jitter", 1.0))
        if jitter < 0.2:
            score += 10
        elif jitter < 0.5:
            score += 5

    # Beacon confirmed → lower auto-block threshold applies (handled in analyse_signal)
    signal["_beacon_confirmed"] = (
        "beacon_interval" in signal and
        float(signal.get("jitter", 1.0)) < 0.2
    )

    return min(100, score)


def analyse_signal(signal: dict) -> dict:
    """
    Analyse a raw network/telemetry signal and return a threat assessment.

    Args:
        signal: dict with any of: src_ip, protocol, entropy, z_score,
                beacon_interval, jitter, bytes_out

    Returns:
        dict: threat_level, score, mitre_ttp, auto_block, reason
    """
    if not signal:
        return {
            "threat_level": "info",
            "score": 0,
            "mitre_ttp": "T1071",
            "auto_block": False,
            "reason": "No signal data provided",
        }

    score = _compute_score(signal)

    # Beacon-confirmed C2 gets a lower auto-block threshold (55 vs 65)
    beacon_confirmed = signal.get("_beacon_confirmed", False)
    effective_auto_block_threshold = 55 if beacon_confirmed else _AUTO_BLOCK_SCORE
    if score >= _HIGH_THREAT_SCORE:
        threat_level = "critical" if score >= 80 else "high"
    elif score >= _MEDIUM_THREAT_SCORE:
        threat_level = "medium"
    elif score > 0:
        threat_level = "low"
    else:
        threat_level = "info"

    auto_block = score >= effective_auto_block_threshold

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
    if signal.get("protocol", "").upper() == "QUIC":
        reasons.append("QUIC protocol — common C2 evasion vector")
    if "beacon_interval" in signal:
        reasons.append("Regular beacon interval detected")
    if not reasons:
        reasons.append("Signal within normal parameters")

    return {
        "threat_level": threat_level,
        "score": score,
        "mitre_ttp": ttp,
        "auto_block": auto_block,
        "reason": "; ".join(reasons),
    }


async def block_threat(
    event_id: str,
    src_ip: str,
    scenario: str,
    org_id: str,
    additional_context: dict | None = None,
) -> dict:
    """
    Execute threat blocking decision via ThreatFade bridge.

    Flow:
      1. Call ThreatFade /detect/scenario for oracle verdict
      2. Score locally with analyse_signal()
      3. Execute block if score >= threshold
      4. Return full event record for SIEM export

    Args:
        event_id:  unique event identifier
        src_ip:    source IP address of the suspicious traffic
        scenario:  ThreatFade scenario name (e.g. 'c2_beacon')
        org_id:    organisation ID for multi-tenant isolation
        additional_context: optional extra signal data

    Returns:
        Standardised threat event dict
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
        "threat_level": "info",
        "score": 0,
        "mitre_ttp": "T1071",
    }

    # ── Call ThreatFade oracle ─────────────────────────────────────────
    try:
        tf_result = await threatfade_bridge.detect_scenario(scenario)
    except Exception as e:
        base["error"] = str(e)
        base["action_taken"] = "monitor"
        return base

    # ── Local analysis on top of ThreatFade verdict ────────────────────
    signal = {
        "src_ip": src_ip,
        "protocol": tf_result.get("protocol", "HTTPS"),
        "z_score": tf_result.get("z_score", 0),
        "entropy": tf_result.get("entropy", 0),
        **(additional_context or {}),
    }
    assessment = analyse_signal(signal)

    # Override with ThreatFade's own threat level if it's stronger
    tf_level = tf_result.get("threat_level", "info")
    level_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    final_level = (
        tf_level
        if level_rank.get(tf_level, 0) >= level_rank.get(assessment["threat_level"], 0)
        else assessment["threat_level"]
    )

    ttp = map_mitre_ttp(
        protocol=signal.get("protocol", ""),
        entropy=signal.get("entropy", 0),
        z_score=signal.get("z_score", 0),
    )

    # ── Block decision ─────────────────────────────────────────────────
    should_block = (
        assessment["auto_block"] or
        final_level in ("high", "critical")
    )

    action = "blocked" if should_block else "monitor"

    base.update({
        "blocked": should_block,
        "action_taken": action,
        "threat_level": final_level,
        "score": assessment["score"],
        "mitre_ttp": ttp,
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

    if fmt == "json":
        return {"format": "json", "payload": event}

    if fmt == "splunk_hec":
        return {
            "format": "splunk_hec",
            "payload": {
                "time": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "host": event.get("src_ip", "unknown"),
                "source": "resilientai",
                "sourcetype": "resilientai:threat",
                "index": "security",
                "event": event,
            },
        }

    if fmt == "cef":
        severity_map = {"info": 0, "low": 3, "medium": 5, "high": 7, "critical": 10}
        sev = severity_map.get(event.get("threat_level", "info"), 0)
        cef_str = (
            f"CEF:0|Tinlance|ResilientAI|1.0|{event.get('mitre_ttp', 'T1071')}|"
            f"Threat {event.get('threat_level', 'info')}|{sev}|"
            f"src={event.get('src_ip', 'unknown')} "
            f"act={event.get('action_taken', 'monitor')} "
            f"msg={event.get('reason', 'Threat detected')} "
            f"externalId={event.get('event_id', 'unknown')}"
        )
        return {"format": "cef", "payload": cef_str}
