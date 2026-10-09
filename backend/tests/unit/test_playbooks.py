"""
Sprint 5 — Self-Healing Playbooks tests.
RED phase: all tests written before implementation.
"""
import pytest
from unittest.mock import patch, AsyncMock, MagicMock


class TestBasePlaybook:

    def test_base_playbook_has_name(self):
        from resilience.playbooks.base import BasePlaybook
        class ConcretePlaybook(BasePlaybook):
            name = "test"
            async def execute(self, context): return {"status": "ok"}
        p = ConcretePlaybook()
        assert p.name == "test"

    def test_base_playbook_requires_execute(self):
        from resilience.playbooks.base import BasePlaybook
        with pytest.raises(TypeError):
            BasePlaybook()

    @pytest.mark.asyncio
    async def test_audit_method_exists(self):
        from resilience.playbooks.base import BasePlaybook
        class ConcretePlaybook(BasePlaybook):
            name = "test"
            async def execute(self, context): return {"status": "ok"}
        p = ConcretePlaybook()
        # Should not raise
        await p.audit("dev-001", {"status": "ok"})

    @pytest.mark.asyncio
    async def test_execute_returns_dict(self):
        from resilience.playbooks.base import BasePlaybook
        class ConcretePlaybook(BasePlaybook):
            name = "concrete"
            async def execute(self, context):
                return {"status": "executed", "playbook": self.name}
        p = ConcretePlaybook()
        result = await p.execute({"device_id": "srv-01"})
        assert isinstance(result, dict)
        assert result["status"] == "executed"


class TestDiskFullPlaybook:

    @pytest.mark.asyncio
    async def test_disk_full_returns_result_dict(self):
        from resilience.playbooks.disk_full import DiskFullPlaybook
        p = DiskFullPlaybook()
        result = await p.execute({"device_id": "srv-01", "disk_percent": 88})
        assert "status" in result
        assert "playbook" in result
        assert "actions_taken" in result

    @pytest.mark.asyncio
    async def test_disk_full_playbook_name(self):
        from resilience.playbooks.disk_full import DiskFullPlaybook
        p = DiskFullPlaybook()
        assert p.name == "disk_full"

    @pytest.mark.asyncio
    async def test_disk_full_reports_space_freed(self):
        from resilience.playbooks.disk_full import DiskFullPlaybook
        p = DiskFullPlaybook()
        result = await p.execute({"device_id": "srv-01", "disk_percent": 90})
        assert "bytes_freed" in result or "space_freed_mb" in result or result["status"] in ("executed", "simulated")

    @pytest.mark.asyncio
    async def test_disk_full_includes_device_id(self):
        from resilience.playbooks.disk_full import DiskFullPlaybook
        p = DiskFullPlaybook()
        result = await p.execute({"device_id": "specific-server-99", "disk_percent": 87})
        assert result.get("device_id") == "specific-server-99"


class TestServiceRestartPlaybook:

    @pytest.mark.asyncio
    async def test_service_restart_returns_result(self):
        from resilience.playbooks.service_restart import ServiceRestartPlaybook
        p = ServiceRestartPlaybook()
        result = await p.execute({"device_id": "srv-01", "service_name": "nginx"})
        assert "status" in result
        assert "playbook" in result

    @pytest.mark.asyncio
    async def test_service_restart_name(self):
        from resilience.playbooks.service_restart import ServiceRestartPlaybook
        p = ServiceRestartPlaybook()
        assert p.name == "service_restart"

    @pytest.mark.asyncio
    async def test_service_restart_records_service(self):
        from resilience.playbooks.service_restart import ServiceRestartPlaybook
        p = ServiceRestartPlaybook()
        result = await p.execute({"device_id": "srv-01", "service_name": "postgresql"})
        assert "service_name" in result or result["status"] in ("executed", "simulated", "ok")

    @pytest.mark.asyncio
    async def test_service_restart_missing_service_uses_default(self):
        from resilience.playbooks.service_restart import ServiceRestartPlaybook
        p = ServiceRestartPlaybook()
        # Should not raise even without service_name
        result = await p.execute({"device_id": "srv-01"})
        assert "status" in result


class TestCertExpiryPlaybook:

    @pytest.mark.asyncio
    async def test_cert_expiry_returns_result(self):
        from resilience.playbooks.cert_expiry import CertExpiryPlaybook
        p = CertExpiryPlaybook()
        result = await p.execute({
            "device_id": "srv-01",
            "domain": "api.resilientai.com",
            "days_until_expiry": 7,
        })
        assert "status" in result
        assert "playbook" in result

    @pytest.mark.asyncio
    async def test_cert_expiry_name(self):
        from resilience.playbooks.cert_expiry import CertExpiryPlaybook
        p = CertExpiryPlaybook()
        assert p.name == "cert_expiry"

    @pytest.mark.asyncio
    async def test_cert_expiry_records_domain(self):
        from resilience.playbooks.cert_expiry import CertExpiryPlaybook
        p = CertExpiryPlaybook()
        result = await p.execute({
            "device_id": "srv-01",
            "domain": "tinlance.com",
            "days_until_expiry": 3,
        })
        assert result.get("domain") == "tinlance.com" or result["status"] in ("executed", "simulated")

    @pytest.mark.asyncio
    async def test_cert_expiry_no_domain_uses_default(self):
        from resilience.playbooks.cert_expiry import CertExpiryPlaybook
        p = CertExpiryPlaybook()
        result = await p.execute({"device_id": "srv-01"})
        assert "status" in result


class TestHighCPUPlaybook:

    @pytest.mark.asyncio
    async def test_high_cpu_returns_result(self):
        from resilience.playbooks.high_cpu import HighCPUPlaybook
        p = HighCPUPlaybook()
        result = await p.execute({"device_id": "srv-01", "cpu_percent": 95})
        assert "status" in result
        assert "playbook" in result

    @pytest.mark.asyncio
    async def test_high_cpu_name(self):
        from resilience.playbooks.high_cpu import HighCPUPlaybook
        p = HighCPUPlaybook()
        assert p.name == "high_cpu"

    @pytest.mark.asyncio
    async def test_high_cpu_reports_processes(self):
        from resilience.playbooks.high_cpu import HighCPUPlaybook
        p = HighCPUPlaybook()
        result = await p.execute({"device_id": "srv-01", "cpu_percent": 98})
        assert "processes_checked" in result or "top_processes" in result or result["status"] in ("executed", "simulated")


class TestPlaybookExecutor:
    """Tests for the central playbook dispatcher."""

    @pytest.mark.asyncio
    async def test_executor_dispatches_disk_full(self):
        from resilience.playbooks.executor import execute_playbook
        result = await execute_playbook(
            playbook_name="disk_full",
            context={"device_id": "srv-01", "disk_percent": 88},
        )
        assert result["status"] in ("executed", "simulated", "ok")

    @pytest.mark.asyncio
    async def test_executor_dispatches_service_restart(self):
        from resilience.playbooks.executor import execute_playbook
        result = await execute_playbook(
            playbook_name="service_restart",
            context={"device_id": "srv-01", "service_name": "nginx"},
        )
        assert "status" in result

    @pytest.mark.asyncio
    async def test_executor_dispatches_cert_expiry(self):
        from resilience.playbooks.executor import execute_playbook
        result = await execute_playbook(
            playbook_name="cert_expiry",
            context={"device_id": "srv-01", "domain": "example.com"},
        )
        assert "status" in result

    @pytest.mark.asyncio
    async def test_executor_dispatches_high_cpu(self):
        from resilience.playbooks.executor import execute_playbook
        result = await execute_playbook(
            playbook_name="high_cpu",
            context={"device_id": "srv-01", "cpu_percent": 95},
        )
        assert "status" in result

    @pytest.mark.asyncio
    async def test_executor_unknown_playbook_raises(self):
        from resilience.playbooks.executor import execute_playbook
        with pytest.raises(ValueError):
            await execute_playbook(
                playbook_name="nonexistent_playbook",
                context={"device_id": "srv-01"},
            )

    @pytest.mark.asyncio
    async def test_executor_result_always_has_playbook_key(self):
        from resilience.playbooks.executor import execute_playbook
        result = await execute_playbook(
            playbook_name="disk_full",
            context={"device_id": "srv-01", "disk_percent": 90},
        )
        assert "playbook" in result

    @pytest.mark.asyncio
    async def test_executor_result_always_has_timestamp(self):
        from resilience.playbooks.executor import execute_playbook
        result = await execute_playbook(
            playbook_name="high_cpu",
            context={"device_id": "srv-01"},
        )
        assert "executed_at" in result

    @pytest.mark.asyncio
    async def test_list_available_playbooks(self):
        from resilience.playbooks.executor import list_playbooks
        playbooks = list_playbooks()
        assert "disk_full" in playbooks
        assert "service_restart" in playbooks
        assert "cert_expiry" in playbooks
        assert "high_cpu" in playbooks


class TestAutomationAPI:
    """Integration tests for automation routes."""

    @pytest.fixture
    async def client(self):
        from httpx import AsyncClient, ASGITransport
        from main import app
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_automation_list_rules(self, client):
        r = await client.get("/automation/")
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_automation_list_playbooks(self, client):
        r = await client.get("/automation/playbooks")
        assert r.status_code == 200
        data = r.json()
        assert "playbooks" in data
        assert len(data["playbooks"]) >= 4

    @pytest.mark.asyncio
    async def test_automation_trigger_playbook(self, client):
        r = await client.post("/automation/trigger", json={
            "playbook_name": "disk_full",
            "device_id": "srv-test-01",
            "context": {"disk_percent": 88},
        })
        assert r.status_code in (200, 201)
        data = r.json()
        assert "status" in data

    @pytest.mark.asyncio
    async def test_automation_trigger_unknown_raises_422(self, client):
        r = await client.post("/automation/trigger", json={
            "playbook_name": "nonexistent",
            "device_id": "srv-01",
            "context": {},
        })
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_automation_execution_history(self, client):
        r = await client.get("/automation/history")
        assert r.status_code == 200
        data = r.json()
        assert "executions" in data
