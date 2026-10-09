"""
Sprint 3 — Threat Blocking Agent tests.
RED phase: all tests written before implementation.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock


class TestThreatAnalyser:
    """Tests for signal analysis and threat scoring."""

    def test_analyse_returns_required_keys(self):
        from agents.threat_blocker import analyse_signal
        result = analyse_signal({
            "src_ip": "185.220.101.47",
            "dst_port": 443,
            "protocol": "QUIC",
            "bytes_out": 48200,
            "entropy": 7.82,
        })
        assert "threat_level" in result
        assert "score" in result
        assert "mitre_ttp" in result
        assert "auto_block" in result
        assert "reason" in result

    def test_high_entropy_quic_is_high_threat(self):
        from agents.threat_blocker import analyse_signal
        result = analyse_signal({
            "src_ip": "185.220.101.47",
            "protocol": "QUIC",
            "entropy": 7.82,
            "z_score": 14.76,
        })
        assert result["threat_level"] in ("high", "critical")
        assert result["score"] >= 70

    def test_low_entropy_known_ip_is_low_threat(self):
        from agents.threat_blocker import analyse_signal
        result = analyse_signal({
            "src_ip": "192.168.1.1",
            "protocol": "HTTPS",
            "entropy": 3.2,
            "z_score": 0.4,
        })
        assert result["threat_level"] in ("low", "info")
        assert result["score"] < 40

    def test_cobalt_strike_pattern_is_critical(self):
        from agents.threat_blocker import analyse_signal
        result = analyse_signal({
            "src_ip": "10.0.2.15",
            "protocol": "HTTPS",
            "entropy": 6.9,
            "z_score": 7.01,
            "beacon_interval": 60,
            "jitter": 0.1,
        })
        assert result["threat_level"] in ("high", "critical")
        assert result["auto_block"] is True

    def test_mitre_ttp_mapped_for_c2(self):
        from agents.threat_blocker import analyse_signal
        result = analyse_signal({
            "src_ip": "185.220.101.47",
            "protocol": "QUIC",
            "entropy": 7.82,
            "z_score": 14.76,
        })
        assert result["mitre_ttp"] is not None
        assert "T1" in result["mitre_ttp"]

    def test_auto_block_false_for_low_threat(self):
        from agents.threat_blocker import analyse_signal
        result = analyse_signal({
            "src_ip": "8.8.8.8",
            "protocol": "DNS",
            "entropy": 2.1,
            "z_score": 0.2,
        })
        assert result["auto_block"] is False

    def test_score_is_in_valid_range(self):
        from agents.threat_blocker import analyse_signal
        for z in [0.1, 1.5, 5.0, 14.76]:
            result = analyse_signal({"z_score": z, "entropy": z * 0.5})
            assert 0 <= result["score"] <= 100

    def test_empty_signal_returns_info_level(self):
        from agents.threat_blocker import analyse_signal
        result = analyse_signal({})
        assert result["threat_level"] == "info"
        assert result["auto_block"] is False


class TestThreatBlockerAgent:
    """Tests for the automated blocking decision and action layer."""

    @pytest.mark.asyncio
    async def test_block_returns_result_dict(self):
        from agents.threat_blocker import block_threat
        mock_tf = {"threat_level": "high", "z_score": 14.76, "c2_type": "merlin_quic"}
        with patch("agents.threat_blocker.threatfade_bridge") as mock_bridge:
            mock_bridge.detect_scenario = AsyncMock(return_value=mock_tf)
            result = await block_threat(
                event_id="evt-001",
                src_ip="185.220.101.47",
                scenario="c2_beacon",
                org_id="org-001",
            )
        assert "event_id" in result
        assert "blocked" in result
        assert "threat_level" in result
        assert "action_taken" in result
        assert "mitre_ttp" in result

    @pytest.mark.asyncio
    async def test_high_confidence_triggers_block(self):
        from agents.threat_blocker import block_threat
        mock_tf = {"threat_level": "critical", "z_score": 14.76}
        with patch("agents.threat_blocker.threatfade_bridge") as mock_bridge:
            mock_bridge.detect_scenario = AsyncMock(return_value=mock_tf)
            result = await block_threat(
                event_id="evt-002",
                src_ip="185.220.101.47",
                scenario="c2_beacon",
                org_id="org-001",
            )
        assert result["blocked"] is True
        assert result["action_taken"] in ("blocked", "quarantined")

    @pytest.mark.asyncio
    async def test_low_confidence_does_not_auto_block(self):
        from agents.threat_blocker import block_threat
        mock_tf = {"threat_level": "low", "z_score": 0.5}
        with patch("agents.threat_blocker.threatfade_bridge") as mock_bridge:
            mock_bridge.detect_scenario = AsyncMock(return_value=mock_tf)
            result = await block_threat(
                event_id="evt-003",
                src_ip="192.168.1.100",
                scenario="normal_traffic",
                org_id="org-001",
            )
        assert result["blocked"] is False
        assert result["action_taken"] == "monitor"

    @pytest.mark.asyncio
    async def test_block_event_includes_correct_event_id(self):
        from agents.threat_blocker import block_threat
        with patch("agents.threat_blocker.threatfade_bridge") as mock_bridge:
            mock_bridge.detect_scenario = AsyncMock(return_value={"threat_level": "high", "z_score": 8.0})
            result = await block_threat(
                event_id="evt-specific-777",
                src_ip="10.0.0.1",
                scenario="lateral_movement",
                org_id="org-001",
            )
        assert result["event_id"] == "evt-specific-777"

    @pytest.mark.asyncio
    async def test_threatfade_bridge_failure_degrades_gracefully(self):
        from agents.threat_blocker import block_threat
        with patch("agents.threat_blocker.threatfade_bridge") as mock_bridge:
            mock_bridge.detect_scenario = AsyncMock(side_effect=Exception("Bridge unreachable"))
            result = await block_threat(
                event_id="evt-004",
                src_ip="1.2.3.4",
                scenario="unknown",
                org_id="org-001",
            )
        assert "event_id" in result
        assert result["blocked"] is False
        assert "error" in result


class TestSIEMExporter:
    """Tests for SIEM export formats — JSON, Splunk HEC, CEF."""

    def test_export_json_format(self):
        from agents.threat_blocker import export_siem
        event = {
            "event_id": "evt-001",
            "src_ip": "185.220.101.47",
            "threat_level": "critical",
            "mitre_ttp": "T1071.001",
            "blocked": True,
            "timestamp": "2026-06-20T12:00:00Z",
        }
        result = export_siem(event, fmt="json")
        assert result["format"] == "json"
        assert "payload" in result
        assert result["payload"]["event_id"] == "evt-001"

    def test_export_splunk_hec_format(self):
        from agents.threat_blocker import export_siem
        event = {
            "event_id": "evt-002",
            "src_ip": "10.0.2.15",
            "threat_level": "high",
            "mitre_ttp": "T1059",
            "blocked": True,
            "timestamp": "2026-06-20T12:01:00Z",
        }
        result = export_siem(event, fmt="splunk_hec")
        assert result["format"] == "splunk_hec"
        assert "payload" in result
        assert "event" in result["payload"]
        assert "sourcetype" in result["payload"]

    def test_export_cef_format(self):
        from agents.threat_blocker import export_siem
        event = {
            "event_id": "evt-003",
            "src_ip": "5.5.5.5",
            "threat_level": "high",
            "mitre_ttp": "T1027",
            "blocked": False,
            "timestamp": "2026-06-20T12:02:00Z",
        }
        result = export_siem(event, fmt="cef")
        assert result["format"] == "cef"
        assert "payload" in result
        cef_str = result["payload"]
        assert cef_str.startswith("CEF:")

    def test_export_unknown_format_raises(self):
        from agents.threat_blocker import export_siem
        with pytest.raises(ValueError):
            export_siem({"event_id": "x"}, fmt="xml")

    def test_export_json_includes_mitre_ttp(self):
        from agents.threat_blocker import export_siem
        event = {"event_id": "e1", "mitre_ttp": "T1027", "threat_level": "high",
                 "src_ip": "1.1.1.1", "blocked": True, "timestamp": "2026-01-01T00:00:00Z"}
        result = export_siem(event, fmt="json")
        assert result["payload"]["mitre_ttp"] == "T1027"

    def test_splunk_hec_has_correct_sourcetype(self):
        from agents.threat_blocker import export_siem
        event = {"event_id": "e2", "mitre_ttp": "T1071", "threat_level": "critical",
                 "src_ip": "2.2.2.2", "blocked": True, "timestamp": "2026-01-01T00:00:00Z"}
        result = export_siem(event, fmt="splunk_hec")
        assert result["payload"]["sourcetype"] == "resilientai:threat"


class TestMITREMapper:
    """Tests for MITRE ATT&CK TTP mapping."""

    def test_quic_maps_to_t1071(self):
        from agents.threat_blocker import map_mitre_ttp
        ttp = map_mitre_ttp(protocol="QUIC", entropy=7.82, z_score=14.76)
        assert "T1071" in ttp

    def test_lateral_movement_maps_to_t1021(self):
        from agents.threat_blocker import map_mitre_ttp
        ttp = map_mitre_ttp(protocol="SMB", entropy=4.5, z_score=3.2,
                            tags=["lateral_movement"])
        assert "T1021" in ttp or "T1570" in ttp

    def test_obfuscation_maps_to_t1027(self):
        from agents.threat_blocker import map_mitre_ttp
        ttp = map_mitre_ttp(protocol="HTTPS", entropy=7.9, z_score=5.0,
                            tags=["obfuscation"])
        assert "T1027" in ttp

    def test_unknown_returns_generic_ttp(self):
        from agents.threat_blocker import map_mitre_ttp
        ttp = map_mitre_ttp(protocol="UDP", entropy=2.0, z_score=0.3)
        assert ttp is not None
        assert len(ttp) > 0

    def test_high_z_score_maps_to_c2_ttp(self):
        from agents.threat_blocker import map_mitre_ttp
        ttp = map_mitre_ttp(protocol="HTTPS", entropy=6.5, z_score=9.0)
        assert "T1071" in ttp or "T1095" in ttp
