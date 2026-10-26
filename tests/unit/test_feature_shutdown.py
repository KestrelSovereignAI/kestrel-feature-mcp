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


@pytest.mark.parametrize("producer,stage", [
    ("container", "create"), ("container", "discover"), ("container", "persist"),
    ("gateway", "start"), ("gateway", "persist"),
    ("gateway-add", "start"), ("gateway-add", "persist"),
])
async def test_shutdown_rechecks_each_docker_producer_await_and_discloses_saved_intent(monkeypatch, producer, stage):
    from mcp import types
    from kestrel_feature_mcp import manager as manager_module

    host = RegistryHost()
    feature = MCPAgent(host)
    await feature.initialize()
    entered, release = asyncio.Event(), asyncio.Event()
    name = container_name_for_image("custom:latest", host.agent_id)
    advertised = [types.Tool(name="echo", description="", inputSchema={"type": "object", "properties": {}})]
    writes, mounted, removed, discoveries = [], [], [], []

    async def checkpoint(current):
        if stage == current:
            entered.set()
            await release.wait()

    async def start_container(*args, **kwargs):
        manager.owned_containers[name] = {"tools": advertised}
        await checkpoint("create")
        return name

    async def discover(*args):
        discoveries.append(args[0])
        await checkpoint("discover")
        return advertised

    async def stop_container(container):
        removed.append(container)
        del manager.owned_containers[container]
        return True

    manager = SimpleNamespace(
        owner_did=host.agent_id, owned_containers={}, aclose=AsyncMock(),
        start_tool_container=start_container, connect_to_tool=discover, stop_tool=stop_container,
        get_all_tools=lambda: [{"container": name, "name": "echo", "description": "", "inputSchema": {"type": "object"}}],
        tool_caller=lambda container: AsyncMock(),
    )
    monkeypatch.setattr(MCPToolManager, "create", AsyncMock(return_value=manager))
    gateway = SimpleNamespace(tools={}, is_connected=producer == "gateway-add", stop=AsyncMock(),
                              get_all_tools=lambda: [{"name": "echo", "description": "", "inputSchema": {"type": "object"}}],
                              tool_caller=lambda: AsyncMock())

    async def start_gateway(*args):
        await checkpoint("start")
        return advertised

    gateway.start = gateway.enable_server = start_gateway
    monkeypatch.setattr(manager_module, "MCPGatewayManager", lambda: gateway)
    monkeypatch.setattr(feature_module, "check_docker_mcp_available", lambda: True)
    monkeypatch.setattr(feature, "_reject_unknown_servers", AsyncMock(return_value=None))
    if producer == "gateway-add":
        feature.gateway_manager = gateway
    original_persist = feature._persist_server

    async def persist(*args, **kwargs):
        outcome = await original_persist(*args, **kwargs)
        writes.append(args[0])
        await checkpoint("persist")
        return outcome

    monkeypatch.setattr(feature, "_persist_server", persist)
    original_mount = host.register_dynamic_tools

    def mount(*args, on_registered=None, **kwargs):
        mounted.append(args[0])
        return original_mount(*args, on_registered=on_registered, **kwargs)

    monkeypatch.setattr(host, "register_dynamic_tools", mount)
    if producer == "container":
        operation = feature.load_tool("custom:latest")
    elif producer == "gateway":
        operation = feature.gateway_start("time")
    else:
        operation = feature._load_via_gateway("time")
    loading = asyncio.create_task(operation)
    stopping = None
    try:
        await asyncio.wait_for(entered.wait(), 1)
        stopping = asyncio.create_task(feature.shutdown())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert feature._closing and not stopping.done()
        release.set()
        result = await loading
        await stopping
        assert result.status is ToolResultStatus.ERROR
        assert "shutting down" in result.error
        assert not mounted, "a closing producer published callable tools"
        assert not host.registered
        if producer == "container":
            assert removed == [name] and not manager.owned_containers
            manager.aclose.assert_awaited_once()
            assert discoveries == ([] if stage == "create" else [name])
        else:
            gateway.stop.assert_awaited_once()
        if stage == "persist":
            assert writes and all(row["state"] == "enabled" for row in host.saved.values())
            assert "remains saved" in result.error, result.to_dict()
            assert "Unload" in result.error
            if producer == "gateway":
                assert "server set was replaced" in result.error
        else:
            assert not writes and not host.saved, "a retired producer persisted enablement"
            assert "remains saved" not in result.error
    finally:
        release.set()
        await asyncio.gather(*(task for task in (loading, stopping) if task is not None), return_exceptions=True)
        await feature.shutdown()


async def test_queued_start_rechecks_closing_before_probes_catalog_or_gateway_retirement(monkeypatch):
    host = RegistryHost()
    feature = MCPAgent(host)
    await feature.initialize()
    check = MagicMock(return_value=True)
    catalog = AsyncMock(return_value=None)
    retired_by = []

    async def retire():
        retired_by.append(asyncio.current_task())

    feature.gateway_manager = SimpleNamespace(stop=retire)
    monkeypatch.setattr(feature_module, "check_docker_mcp_available", check)
    monkeypatch.setattr(feature, "_known_catalog_servers", catalog)
    await feature._docker_operations.acquire()
    released = False
    queued = asyncio.create_task(feature.gateway_start("time"))
    stopping = None
    try:
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not queued.done() and not feature._closing
        stopping = asyncio.create_task(feature.shutdown())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert feature._closing and not stopping.done()
        feature._docker_operations.release()
        released = True
        result = await queued
        await stopping
        assert result.status is ToolResultStatus.ERROR
        check.assert_not_called()
        catalog.assert_not_awaited()
        assert retired_by == [stopping], "the queued start retired a live gateway"
        assert not host.saved and not host.registered
    finally:
        if not released:
            feature._docker_operations.release()
        await asyncio.gather(*(task for task in (queued, stopping) if task is not None), return_exceptions=True)
        await feature.shutdown()


async def test_settled_shutdown_restore_cannot_acquire_a_container_manager(monkeypatch):
    from kestrel_feature_mcp.feature import MCPFeatureClosingError

    host = RegistryHost()
    name = container_name_for_image("custom:latest", host.agent_id)
    host.saved[name] = {"name": name, "state": "enabled", "metadata": {"mode": "container", "image": "custom:latest"}}
    feature = MCPAgent(host)
    await feature.initialize()
    await feature.shutdown()
    create = AsyncMock(side_effect=AssertionError("settled feature acquired a Docker client"))
    monkeypatch.setattr(MCPToolManager, "create", create)
    with pytest.raises(MCPFeatureClosingError, match="shutting down"):
        await feature.post_all_features_loaded()
    create.assert_not_awaited()
    assert feature.manager is None and not host.registered
    assert set(host.saved) == {name}


async def test_explicit_gateway_unload_remains_available_while_feature_is_closing(monkeypatch):
    host = RegistryHost()
    host.saved["time"] = {"name": "time", "state": "enabled", "metadata": {"mode": "gateway"}}
    feature = MCPAgent(host)
    await feature.initialize()
    gateway = SimpleNamespace(is_connected=True, gateway=SimpleNamespace(requested_servers={"time"}), stop=AsyncMock())
    feature.gateway_manager = gateway
    monkeypatch.setattr(feature, "_resolve_load_route", AsyncMock(return_value=("gateway", "time")))
    feature._closing = True
    result = await feature.unload_tool("time")
    assert result.status is ToolResultStatus.OK, result.to_dict()
    gateway.stop.assert_awaited_once()
    assert not host.saved and feature.gateway_manager is None


async def test_already_closing_start_is_refused_without_waiting_for_docker_cleanup():
    feature = MCPAgent(RegistryHost())
    await feature.initialize()
    feature._closing = True
    try:
        async with feature._docker_operations:
            result = await asyncio.wait_for(feature.gateway_start("time"), 1)
            assert result.status is ToolResultStatus.ERROR
            assert "shutting down" in result.error
    finally:
        await feature.shutdown()
