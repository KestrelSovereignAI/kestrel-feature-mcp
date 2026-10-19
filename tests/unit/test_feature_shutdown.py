"""A settled feature cannot acquire new resources through any Docker producer."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from docker.errors import APIError, NotFound

from kestrel_feature_mcp import feature as feature_module
from kestrel_feature_mcp.feature import MCPAgent
from kestrel_feature_mcp.manager import MCPToolManager
from kestrel_feature_mcp.manager import container_name_for_image
from kestrel_sdk.tools.result import ToolResultStatus
from tests.unit.test_remote_mcp import RegistryHost


@pytest.mark.parametrize("producer", ["container", "gateway", "gateway-add"])
async def test_settled_shutdown_refuses_every_docker_producer_before_io(monkeypatch, producer):
    host = RegistryHost()
    feature = MCPAgent(host)
    await feature.initialize()
    await feature.shutdown()
    acquire = AsyncMock(side_effect=AssertionError("closed feature acquired Docker"))
    check = MagicMock(side_effect=AssertionError("closed feature probed Docker"))
    monkeypatch.setattr(MCPToolManager, "create", acquire)
    monkeypatch.setattr(feature_module, "check_docker_mcp_available", check)
    if producer == "container":
        result = await feature.load_tool("custom:latest")
    elif producer == "gateway":
        result = await feature.gateway_start("time")
    else:
        result = await feature._load_via_gateway("time")
    assert result.status is ToolResultStatus.ERROR
    assert "shutting down" in result.error
    acquire.assert_not_awaited()
    check.assert_not_called()
    assert not host.registered and not host.saved
    assert feature.manager is None and feature.gateway_manager is None


async def test_shutdown_joins_inflight_container_acquisition_before_releasing_custody(monkeypatch):
    host = RegistryHost()
    feature = MCPAgent(host)
    await feature.initialize()
    entered, release = asyncio.Event(), asyncio.Event()
    manager = SimpleNamespace(owner_did=host.agent_id, owned_containers={},
                              aclose=AsyncMock(), start_tool_container=AsyncMock())

    async def create(**kwargs):
        entered.set()
        await release.wait()
        return manager

    monkeypatch.setattr(MCPToolManager, "create", create)
    loading = asyncio.create_task(feature.load_tool("custom:latest"))
    stopping = None
    try:
        await asyncio.wait_for(entered.wait(), 1)
        stopping = asyncio.create_task(feature.shutdown())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not stopping.done(), "shutdown released custody while Docker acquisition was in flight"
        release.set()
        result = await loading
        await stopping
        assert result.status is ToolResultStatus.ERROR
        assert "shutting down" in result.error
        manager.start_tool_container.assert_not_awaited()
        manager.aclose.assert_awaited_once()
        assert not host.registered and not host.saved
    finally:
        release.set()
        await asyncio.gather(*(t for t in (loading, stopping) if t is not None), return_exceptions=True)
        await feature.shutdown()


async def test_shutdown_joins_restore_manager_acquisition_before_its_cleanup_snapshot(monkeypatch):
    from kestrel_feature_mcp.feature import MCPFeatureClosingError

    host = RegistryHost()
    name = container_name_for_image("custom:latest", host.agent_id)
    host.saved[name] = {"name": name, "state": "enabled", "metadata": {"mode": "container", "image": "custom:latest"}}
    feature = MCPAgent(host)
    await feature.initialize()
    entered, release = asyncio.Event(), asyncio.Event()
    manager = SimpleNamespace(owned_containers={}, aclose=AsyncMock())

    async def create(**kwargs):
        entered.set()
        await release.wait()
        return manager

    monkeypatch.setattr(MCPToolManager, "create", create)
    restoring = asyncio.create_task(feature.post_all_features_loaded())
    stopping = None
    try:
        await asyncio.wait_for(entered.wait(), 1)
        stopping = asyncio.create_task(feature.shutdown())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not stopping.done(), "shutdown missed the restore path's in-flight manager acquisition"
        release.set()
        with pytest.raises(MCPFeatureClosingError, match="shutting down"):
            await restoring
        await stopping
        manager.aclose.assert_awaited_once()
        assert not host.registered
        assert set(host.saved) == {name}
    finally:
        release.set()
        await asyncio.gather(*(t for t in (restoring, stopping) if t is not None), return_exceptions=True)
        await feature.shutdown()


async def test_shutdown_joins_gateway_start_before_releasing_custody(monkeypatch):
    from kestrel_feature_mcp import manager as manager_module

    host = RegistryHost()
    feature = MCPAgent(host)
    await feature.initialize()
    entered, release = asyncio.Event(), asyncio.Event()
    gateway = SimpleNamespace(stop=AsyncMock(), tools={}, is_connected=False)

    async def start(servers):
        entered.set()
        await release.wait()
        return []

    gateway.start = start
    monkeypatch.setattr(feature_module, "check_docker_mcp_available", lambda: True)
    monkeypatch.setattr(manager_module, "MCPGatewayManager", lambda: gateway)
    monkeypatch.setattr(feature, "_reject_unknown_servers", AsyncMock(return_value=None))
    loading = asyncio.create_task(feature.gateway_start("time"))
    stopping = None
    try:
        await asyncio.wait_for(entered.wait(), 1)
        stopping = asyncio.create_task(feature.shutdown())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not stopping.done(), "shutdown released custody while gateway start was in flight"
        release.set()
        result = await loading
        await stopping
        assert result.status is ToolResultStatus.ERROR
        assert "shutting down" in result.error
        gateway.stop.assert_awaited_once()
        assert feature.gateway_manager is None
        assert not host.registered and not host.saved
    finally:
        release.set()
        await asyncio.gather(*(t for t in (loading, stopping) if t is not None), return_exceptions=True)
        await feature.shutdown()


async def test_failed_container_cleanup_retains_its_client_and_reenable_retries_the_real_removal():
    client = MagicMock()
    client.containers.get.side_effect = NotFound("removed")
    container = MagicMock()
    container.remove.side_effect = [APIError("removal already in progress"), None]
    manager = MCPToolManager(owner_did="did:test:cleanup-retry", docker_client=client)
    manager._retain_container("owned", container)
    feature = MCPAgent(RegistryHost(manager.owner_did))
    await feature.initialize()
    feature.manager = manager
    with pytest.raises(APIError, match="removal already in progress"):
        await feature.shutdown()
    assert feature._closing and feature.manager is manager
    assert "owned" in manager.owned_containers
    assert manager.docker_client is client, "failed cleanup closed the client its retry needs"
    client.close.assert_not_called()
    await feature.initialize()
    assert not manager.owned_containers
    assert container.remove.call_count == 2
    client.close.assert_called_once()
    assert feature.manager is None and not feature._closing


async def test_same_instance_container_reenable_discards_only_the_successfully_closed_manager(monkeypatch):
    host = RegistryHost()
    feature = MCPAgent(host)
    await feature.initialize()
    old = SimpleNamespace(owned_containers={}, aclose=AsyncMock())
    new = SimpleNamespace(owned_containers={}, aclose=AsyncMock())
    create = AsyncMock(return_value=new)
    monkeypatch.setattr(MCPToolManager, "create", create)
    feature.manager = old
    await feature.initialize()
    assert feature.manager is old
    old.aclose.assert_not_awaited()
    await feature.shutdown()
    assert feature.manager is old
    await feature.initialize()
    assert feature.manager is None
    assert await feature._ensure_container_manager()
    assert feature.manager is new
    create.assert_awaited_once_with(owner_did=host.agent_id)
    await feature.shutdown()


async def test_route_lookup_from_before_disable_cannot_acquire_in_a_new_generation(monkeypatch):
    feature = MCPAgent(RegistryHost())
    await feature.initialize()
    entered, release = asyncio.Event(), asyncio.Event()
    async def route(server):
        entered.set()
        await release.wait()
        return "container", "custom:latest"
    acquire = AsyncMock(side_effect=AssertionError("stale request acquired a new-generation manager"))
    monkeypatch.setattr(feature, "_resolve_load_route", route)
    monkeypatch.setattr(MCPToolManager, "create", acquire)
    loading = asyncio.create_task(feature.load_tool("custom:latest"))
    try:
        await asyncio.wait_for(entered.wait(), 1)
        await feature.shutdown()
        await feature.initialize()
        release.set()
        result = await loading
        assert result.status is ToolResultStatus.ERROR
        assert "shutting down" in result.error
        acquire.assert_not_awaited()
    finally:
        release.set()
        await asyncio.gather(loading, return_exceptions=True)
        await feature.shutdown()


async def test_gateway_unload_does_not_need_an_unrelated_container_manager(monkeypatch):
    feature = MCPAgent(RegistryHost())
    await feature.initialize()
    feature.gateway_manager = SimpleNamespace(
        is_connected=True, gateway=SimpleNamespace(requested_servers={"time"}), stop=AsyncMock())
    gateway = feature.gateway_manager
    monkeypatch.setattr(feature, "_resolve_load_route", AsyncMock(return_value=("gateway", "time")))
    result = await feature.unload_tool("time")
    assert result.status is ToolResultStatus.OK, result.to_dict()
    gateway.stop.assert_awaited_once()
    assert feature.manager is None and feature.gateway_manager is None


@pytest.mark.parametrize("operation", ["stop", "unload"])
async def test_explicit_gateway_cleanup_joins_a_start_and_removes_its_saved_intent(monkeypatch, operation):
    from kestrel_feature_mcp import manager as manager_module

    host = RegistryHost()
    feature = MCPAgent(host)
    await feature.initialize()
    entered, release = asyncio.Event(), asyncio.Event()
    gateway = SimpleNamespace(stop=AsyncMock(), tools={}, is_connected=True,
                              gateway=SimpleNamespace(requested_servers={"time"}),
                              get_all_tools=lambda: [], tool_caller=lambda: AsyncMock())
    async def start(servers):
        entered.set()
        await release.wait()
        return []
    gateway.start = start
    monkeypatch.setattr(manager_module, "MCPGatewayManager", lambda: gateway)
    monkeypatch.setattr(feature_module, "check_docker_mcp_available", lambda: True)
    monkeypatch.setattr(feature, "_reject_unknown_servers", AsyncMock(return_value=None))
    monkeypatch.setattr(feature, "_resolve_load_route", AsyncMock(return_value=("gateway", "time")))
    loading = asyncio.create_task(feature.gateway_start("time"))
    stopping = None
    try:
        await asyncio.wait_for(entered.wait(), 1)
        stopping = asyncio.create_task(feature.gateway_stop() if operation == "stop" else feature.unload_tool("time"))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not stopping.done(), "explicit cleanup overtook an admitted gateway start"
        release.set()
        assert (await loading).status is ToolResultStatus.PARTIAL
        assert (await stopping).status is ToolResultStatus.OK
        gateway.stop.assert_awaited_once()
        assert feature.gateway_manager is None
        assert not host.registered and not host.saved
    finally:
        release.set()
        await asyncio.gather(*(t for t in (loading, stopping) if t is not None), return_exceptions=True)
        await feature.shutdown()
