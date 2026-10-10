"""Keep the security threat model and its critical risk register present in CI."""
from pathlib import Path

MODEL = Path(__file__).resolve().parents[2] / "docs" / "THREAT_MODEL.md"


def test_threat_model_has_required_boundaries_and_risk_register():
    assert MODEL.is_file()
    content = MODEL.read_text(encoding="utf-8")
    required = [
        "System context and trust boundaries",
        "Threat register",
        "T-01",
        "T-18",
        "Attack scenarios and required controls",
        "Required verification matrix",
        "External references",
        "Not production-ready",
        "https://owasp.org/www-project-api-security/",
        "https://www.postgresql.org/docs/current/ddl-rowsecurity.html",
    ]
    for phrase in required:
        assert phrase in content, f"Threat model is missing required section/reference: {phrase}"
