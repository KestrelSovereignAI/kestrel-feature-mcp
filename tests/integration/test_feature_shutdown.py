"""Real Docker processes cannot outlive a feature's settled shutdown."""

import asyncio
import uuid

import docker
import pytest

from kestrel_feature_mcp.feature import MCPAgent
from kestrel_feature_mcp.manager import MCPToolManager, container_name_for_image
from kestrel_sdk.tools.result import ToolResultStatus
from tests.integration.test_mcp_tools_e2e import build_test_image, check_docker
from tests.unit.test_remote_mcp import RegistryHost

pytestmark = [pytest.mark.docker, pytest.mark.timeout(60)]


def assert_container_absent(name):
    client = docker.from_env()
    try:
        with pytest.raises(docker.errors.NotFound):
            client.containers.get(name)
    finally:
        client.close()


@pytest.mark.parametrize("stage", ["acquire", "connected"])
async def test_shutdown_drains_a_real_container_load_before_releasing_custody(build_test_image, monkeypatch, stage):
    host = RegistryHost(f"did:test:shutdown-{uuid.uuid4().hex}")
    feature = MCPAgent(host)
    await feature.initialize()
    entered, release = asyncio.Event(), asyncio.Event()
    original_create, original_connect = MCPToolManager.create, MCPToolManager.connect_to_tool
    managers = []

    async def create(**kwargs):
        if stage == "acquire":
            entered.set()
            await release.wait()
        manager = await original_create(**kwargs)
        managers.append(manager)
        return manager

    async def connect(manager, name):
        tools = await original_connect(manager, name)
        if stage == "connected":
            entered.set()
            await release.wait()
        return tools

    monkeypatch.setattr(MCPToolManager, "create", create)
    monkeypatch.setattr(MCPToolManager, "connect_to_tool", connect)
    loading = asyncio.create_task(feature.load_tool(build_test_image))
    stopping = None
    name = container_name_for_image(build_test_image, host.agent_id)
    try:
        await asyncio.wait_for(entered.wait(), 20)
        stopping = asyncio.create_task(feature.shutdown())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not stopping.done(), "feature released custody before its real Docker start settled"
        release.set()
        result = await loading
        await stopping
        assert result.status is ToolResultStatus.ERROR, result.to_dict()
        assert "shutting down" in result.error
        assert not host.registered and not host.saved
        assert managers and all(not m.owned_containers and m.docker_client is None for m in managers)
        await asyncio.to_thread(assert_container_absent, name)
    finally:
        release.set()
        await asyncio.gather(*(t for t in (loading, stopping) if t is not None), return_exceptions=True)
        await feature.shutdown()


async def test_real_container_cleanup_retries_then_reenable_executes_a_fresh_connection(build_test_image, monkeypatch):
    host = RegistryHost(f"did:test:removal-retry-{uuid.uuid4().hex}")
    feature = MCPAgent(host)
    await feature.initialize()
    name = container_name_for_image(build_test_image, host.agent_id)
    try:
        loaded = await feature.load_tool(build_test_image)
        assert loaded.status is ToolResultStatus.OK, loaded.to_dict()
        old_manager = feature.manager
        container = old_manager.owned_containers[name]["container"]
        original_remove = container.remove
        attempts = []

        def remove(**kwargs):
            attempts.append(kwargs)
            if len(attempts) == 1:
                raise docker.errors.APIError("removal of container is already in progress")
            return original_remove(**kwargs)

        monkeypatch.setattr(container, "remove", remove)
        with pytest.raises(docker.errors.APIError, match="removal of container"):
            await feature.shutdown()
        assert old_manager.owned_containers[name]["container"] is container
        assert old_manager.docker_client is not None
        assert not host.registered
        await feature.initialize()
        assert len(attempts) == 2
        assert not old_manager.owned_containers and old_manager.docker_client is None
        assert feature.manager is None
        await asyncio.to_thread(assert_container_absent, name)
        loaded = await feature.load_tool(build_test_image)
        assert loaded.status is ToolResultStatus.OK, loaded.to_dict()
        assert feature.manager is not old_manager
        owner = f"mcp:container:{name}"
        echo = next(tool for tool in host.registered[owner] if tool._real_name == "echo")
        result = await echo.execute(text="fresh-after-failed-cleanup")
        assert result["status"] == "ok"
        assert result["confirmation"] == "Echo: fresh-after-failed-cleanup"
    finally:
        await feature.shutdown()
    await asyncio.to_thread(assert_container_absent, name)
