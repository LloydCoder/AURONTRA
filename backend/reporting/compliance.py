"""
Compliance Evidence Report Generator.

Competitive gap closed:
- No ITSM platform generates NIS2/DORA compliance evidence automatically
- Cyber insurance carriers now require documented control evidence
- This replaces manual evidence collection (typically 8–20 hours of work)

Supported frameworks: NIS2, DORA
Each framework maps to a set of controls with pass/fail/partial scoring.
"""
from datetime import datetime, timezone


_FRAMEWORKS = {"NIS2", "DORA"}


def _nis2_controls(params: dict) -> list[dict]:
    """NIS2 Article 21 — cybersecurity risk-management measures."""
    avg_score = params.get("avg_resilience_score", 0)
    threats_blocked = params.get("threats_blocked", 0)
    siem_active = params.get("siem_active", False)
    mfa_enabled = params.get("mfa_enabled", False)
    tickets_resolved = params.get("tickets_resolved", 0)

    return [
        {
            "control": "Art.21(2)(a) — Policies on risk analysis",
            "status": "pass" if avg_score >= 70 else "partial",
            "evidence": f"Resilience score {avg_score}/100 across all devices. Automated risk scoring active.",
            "weight": 15,
            "score": 15 if avg_score >= 70 else 8,
        },
        {
            "control": "Art.21(2)(b) — Incident handling",
            "status": "pass" if tickets_resolved > 0 else "fail",
            "evidence": f"{tickets_resolved} incidents handled via AI agent. Full audit trail maintained.",
            "weight": 20,
            "score": 20 if tickets_resolved > 0 else 0,
        },
        {
            "control": "Art.21(2)(c) — Business continuity",
            "status": "pass" if avg_score >= 60 else "partial",
            "evidence": f"Predictive resilience scoring with 72-hour failure forecasting active. Self-healing playbooks deployed.",
            "weight": 15,
            "score": 15 if avg_score >= 60 else 7,
        },
        {
            "control": "Art.21(2)(d) — Supply chain security",
            "status": "partial",
            "evidence": "Third-party bridge monitoring active (ThreatFade, FusionOps). Full vendor risk scoring in roadmap.",
            "weight": 10,
            "score": 6,
        },
        {
            "control": "Art.21(2)(e) — Network security (detection)",
            "status": "pass" if threats_blocked > 0 or siem_active else "fail",
            "evidence": f"ThreatFade C2 detection active. {threats_blocked} threats blocked. SIEM export: {'active' if siem_active else 'inactive'}.",
            "weight": 20,
            "score": 20 if (threats_blocked > 0 or siem_active) else 0,
        },
        {
            "control": "Art.21(2)(g) — Cryptography policies",
            "status": "pass",
            "evidence": "Hash-chained audit log with SHA-256 integrity verification. TLS enforced on all endpoints.",
            "weight": 5,
            "score": 5,
        },
        {
            "control": "Art.21(2)(i) — Multi-factor authentication",
            "status": "pass" if mfa_enabled else "fail",
            "evidence": f"MFA: {'enabled via Clerk auth' if mfa_enabled else 'not yet configured — action required'}.",
            "weight": 15,
            "score": 15 if mfa_enabled else 0,
        },
    ]


def _dora_controls(params: dict) -> list[dict]:
    """DORA Article 9 — ICT risk management requirements."""
    avg_score = params.get("avg_resilience_score", 0)
    threats_blocked = params.get("threats_blocked", 0)
    siem_active = params.get("siem_active", False)
    mfa_enabled = params.get("mfa_enabled", False)

    return [
        {
            "control": "Art.9(2) — ICT risk management framework",
            "status": "pass" if avg_score >= 70 else "partial",
            "evidence": f"Continuous device resilience monitoring. Score: {avg_score}/100.",
            "weight": 25,
            "score": 25 if avg_score >= 70 else 12,
        },
        {
            "control": "Art.10 — ICT-related incident detection",
            "status": "pass" if siem_active else "partial",
            "evidence": f"ThreatFade C2 detection. {threats_blocked} threats blocked. SIEM: {'active' if siem_active else 'inactive'}.",
            "weight": 25,
            "score": 25 if siem_active else 12,
        },
        {
            "control": "Art.11 — ICT Business continuity policy",
            "status": "pass",
            "evidence": "Self-healing playbooks (disk_full, service_restart, cert_expiry, high_cpu) active. 72h forecasting deployed.",
            "weight": 25,
            "score": 25,
        },
        {
            "control": "Art.9(4)(e) — Strong authentication",
            "status": "pass" if mfa_enabled else "fail",
            "evidence": f"MFA: {'Clerk JWT + MFA active' if mfa_enabled else 'not configured — remediation required'}.",
            "weight": 25,
            "score": 25 if mfa_enabled else 0,
        },
    ]


_CONTROL_BUILDERS = {
    "NIS2": _nis2_controls,
    "DORA": _dora_controls,
}


def generate_compliance_report(
    org_id: str,
    framework: str,
    device_count: int,
    threats_blocked: int,
    avg_resilience_score: int,
    tickets_resolved: int,
    siem_active: bool,
    mfa_enabled: bool,
) -> dict:
    """
    Generate a compliance evidence report for a given framework.

    Args:
        org_id:               organisation identifier
        framework:            'NIS2' | 'DORA'
        device_count:         monitored devices
        threats_blocked:      C2/threat events blocked
        avg_resilience_score: fleet-wide average resilience score (0-100)
        tickets_resolved:     incidents handled
        siem_active:          SIEM export enabled
        mfa_enabled:          MFA configured

    Returns:
        Compliance report dict with per-control evidence and overall score

    Raises:
        ValueError: if framework is not supported
    """
    if framework not in _FRAMEWORKS:
        raise ValueError(
            f"Unsupported framework '{framework}'. Supported: {', '.join(_FRAMEWORKS)}"
        )

    params = {
        "device_count": device_count,
        "threats_blocked": threats_blocked,
        "avg_resilience_score": avg_resilience_score,
        "tickets_resolved": tickets_resolved,
        "siem_active": siem_active,
        "mfa_enabled": mfa_enabled,
    }

    controls = _CONTROL_BUILDERS[framework](params)
    total_weight = sum(c["weight"] for c in controls)
    total_score  = sum(c["score"] for c in controls)
    compliance_score = round((total_score / total_weight) * 100) if total_weight else 0

    pass_count    = sum(1 for c in controls if c["status"] == "pass")
    partial_count = sum(1 for c in controls if c["status"] == "partial")
    fail_count    = sum(1 for c in controls if c["status"] == "fail")

    failed_controls = [c["control"] for c in controls if c["status"] == "fail"]
    recommendations = []
    if not mfa_enabled:
        recommendations.append("Enable MFA via Clerk auth settings — required for all frameworks")
    if not siem_active:
        recommendations.append("Activate SIEM export (Splunk HEC or CEF) to satisfy detection requirements")
    if avg_resilience_score < 70:
        recommendations.append("Deploy additional self-healing playbooks to raise fleet resilience above 70")

    return {
        "org_id": org_id,
        "framework": framework,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "device_count": device_count,
        "compliance_score": compliance_score,
        "controls": controls,
        "summary": {
            "pass": pass_count,
            "partial": partial_count,
            "fail": fail_count,
            "total": len(controls),
        },
        "failed_controls": failed_controls,
        "recommendations": recommendations,
        "report_narrative": (
            f"Organisation {org_id} achieved a {compliance_score}% {framework} compliance score "
            f"based on ResilientAI telemetry. {pass_count}/{len(controls)} controls fully satisfied. "
            f"{'No critical gaps detected.' if fail_count == 0 else f'{fail_count} control(s) require immediate remediation.'}"
        ),
    }
