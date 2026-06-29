"""Routing tests for the unified mcp_load_server (#12).

`_gateway_target` decides whether a load goes through the gateway (stdio /
catalog servers) or the per-container path (native-HTTP images), and the
load/unload verbs delegate accordingly. No Docker here — we drive the pure
routing + the gateway delegation against a fake gateway manager.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from kestrel_sdk.tools.result import ToolResultStatus
from kestrel_feature_mcp.feature import MCPAgent, _GATEWAY_OWNER


class _FakeHost:
    def __init__(self):
        self.registered: dict = {}

    def register_dynamic_tools(self, owner, tools, *, pin=False):
        self.registered[owner] = list(tools)
        return len(self.registered[owner])

    def unregister_dynamic_tools(self, owner):
        return len(self.registered.pop(owner, []))


def _feature(*, manager=None, gateway=None) -> MCPAgent:
    feat = MCPAgent(_FakeHost())
    feat.manager = manager
    feat.gateway_manager = gateway
    return feat


# --- pure routing -----------------------------------------------------------

@pytest.mark.asyncio
async def test_stdio_catalog_name_routes_to_gateway():
    feat = _feature()
    assert await feat._resolve_load_route("time") == ("gateway", "time")
    assert await feat._resolve_load_route("sequentialthinking") == ("gateway", "sequentialthinking")


@pytest.mark.asyncio
async def test_native_sse_catalog_name_routes_to_container_image():
    # test-server is the catalog's only native-SSE image; a name load must run
    # its REAL image, not the bare name (codex P2).
    feat = _feature()
    route, target = await feat._resolve_load_route("test-server")
    assert route == "container"
    assert target == "kestrel-mcp-test-server:latest"


@pytest.mark.asyncio
async def test_image_ref_matching_stdio_entry_routes_to_gateway():
    feat = _feature()
    assert await feat._resolve_load_route("mcp/time:latest") == ("gateway", "time")


@pytest.mark.asyncio
async def test_untagged_stdio_image_ref_still_matches_gateway():
    # `mcp/time` (no :latest) must match the catalog's `mcp/time:latest` (codex P2).
    feat = _feature()
    assert await feat._resolve_load_route("mcp/time") == ("gateway", "time")


@pytest.mark.asyncio
async def test_unknown_image_ref_routes_to_container_as_given():
    feat = _feature()
    assert await feat._resolve_load_route("acme/private-thing:v3") == ("container", "acme/private-thing:v3")


@pytest.mark.asyncio
async def test_bare_name_known_to_catalog_routes_to_gateway():
    feat = _feature()
    feat._known_catalog_servers = AsyncMock(return_value={"postgres", "redis"})
    assert await feat._resolve_load_route("postgres") == ("gateway", "postgres")


@pytest.mark.asyncio
async def test_bare_name_unknown_to_catalog_routes_to_container():
    # Back-compat: a bare local/custom image the catalog doesn't know must NOT
    # be misrouted to the gateway (codex P2).
    feat = _feature()
    feat._known_catalog_servers = AsyncMock(return_value={"postgres"})
    assert await feat._resolve_load_route("my-native-mcp") == ("container", "my-native-mcp")


@pytest.mark.asyncio
async def test_bare_name_unverifiable_catalog_defaults_to_container():
    feat = _feature()
    feat._known_catalog_servers = AsyncMock(return_value=None)  # offline / unverifiable
    assert await feat._resolve_load_route("anything") == ("container", "anything")


# --- load delegation --------------------------------------------------------

@pytest.mark.asyncio
async def test_load_stdio_server_delegates_to_gateway(monkeypatch):
    monkeypatch.setattr("kestrel_feature_mcp.feature.check_docker_mcp_available", lambda: True)
    feat = _feature(manager=MagicMock())
    # No gateway yet -> start() path; bypass catalog validation (offline).
    feat._reject_unknown_servers = AsyncMock(return_value=None)

    started = {}

    class _FakeGatewayMgr:
        def __init__(self):
            self.is_connected = False
            self.tools = {}
            self.gateway = SimpleNamespace(enabled_servers={"time"})

        async def start(self, servers):
            started["servers"] = servers
            self.is_connected = True
            return [SimpleNamespace(name="get_current_time"), SimpleNamespace(name="convert_time")]

        def get_all_tools(self):
            return [
                {"name": "get_current_time", "description": "d", "inputSchema": {}},
                {"name": "convert_time", "description": "d", "inputSchema": {}},
            ]

    monkeypatch.setattr("kestrel_feature_mcp.manager.MCPGatewayManager", _FakeGatewayMgr)

    res = await feat.load_tool("time")
    assert res.status is ToolResultStatus.OK
    assert started["servers"] == ["time"]
    assert "via" in res.data and res.data["via"] == "gateway"
    assert sorted(res.data["new_tools"]) == ["convert_time", "get_current_time"]
    # Aggregate gateway owner is mounted.
    assert _GATEWAY_OWNER in feat.agent.registered


@pytest.mark.asyncio
async def test_load_native_image_uses_container_path(monkeypatch):
    feat = _feature(manager=MagicMock())
    feat._load_via_container = AsyncMock()
    feat._load_via_gateway = AsyncMock()
    await feat.load_tool("acme/native-http-image:latest")
    feat._load_via_container.assert_awaited_once()
    feat._load_via_gateway.assert_not_awaited()


# --- unload symmetry --------------------------------------------------------

@pytest.mark.asyncio
async def test_unload_routes_gateway_server_to_gateway_disable():
    gw = MagicMock()
    gw.is_connected = True
    gw.gateway = SimpleNamespace(enabled_servers={"time", "fetch"})
    gw.disable_server = AsyncMock()
    feat = _feature(manager=MagicMock(), gateway=gw)
    feat._mount_gateway_tools = MagicMock(return_value=3)
    feat._forget_server = AsyncMock()

    res = await feat.unload_tool("time")
    assert res.status is ToolResultStatus.OK
    gw.disable_server.assert_awaited_once_with("time")
    feat._forget_server.assert_awaited_once_with("time")


@pytest.mark.asyncio
async def test_call_tool_routes_gateway_owner_to_gateway():
    # Tools listed as container="gateway" must be callable via mcp_call_tool.
    gw = MagicMock()
    gw.is_connected = True
    gw.call_tool = AsyncMock(return_value=SimpleNamespace(
        content=[SimpleNamespace(text="17:24 UTC")], isError=False))
    feat = _feature(manager=MagicMock(), gateway=gw)
    res = await feat.call_tool("gateway", "get_current_time", {"timezone": "UTC"})
    assert res.status is ToolResultStatus.OK
    gw.call_tool.assert_awaited_once_with("get_current_time", {"timezone": "UTC"})


@pytest.mark.asyncio
async def test_load_via_gateway_does_not_persist_failed_enable(monkeypatch):
    # enable_server reconnects to prior servers (returns their tools) but the
    # requested server never lands in enabled_servers -> must fail, not persist.
    monkeypatch.setattr("kestrel_feature_mcp.feature.check_docker_mcp_available", lambda: True)
    gw = MagicMock()
    gw.is_connected = True
    gw.tools = {"fetch": object()}
    gw.gateway = SimpleNamespace(enabled_servers={"fetch"})  # 'broken' never added
    gw.enable_server = AsyncMock(return_value=[SimpleNamespace(name="fetch")])
    gw.get_all_tools = MagicMock(return_value=[{"name": "fetch", "description": "", "inputSchema": {}}])
    feat = _feature(manager=MagicMock(), gateway=gw)
    feat._reject_unknown_servers = AsyncMock(return_value=None)
    feat._persist_server = AsyncMock()

    res = await feat._load_via_gateway("broken")
    assert res.status is ToolResultStatus.ERROR
    feat._persist_server.assert_not_awaited()


@pytest.mark.asyncio
async def test_unload_accepts_image_alias_for_gateway_server():
    # Loaded as `mcp/time` (-> catalog `time`); unloading by the same image
    # alias must hit the gateway server, not fall through to container unload.
    gw = MagicMock()
    gw.is_connected = True
    gw.gateway = SimpleNamespace(enabled_servers={"time", "fetch"})
    gw.disable_server = AsyncMock()
    feat = _feature(manager=MagicMock(), gateway=gw)
    feat._mount_gateway_tools = MagicMock(return_value=2)
    feat._forget_server = AsyncMock()

    res = await feat.unload_tool("mcp/time")
    assert res.status is ToolResultStatus.OK
    gw.disable_server.assert_awaited_once_with("time")
    feat._forget_server.assert_awaited_once_with("time")


@pytest.mark.asyncio
async def test_unload_last_gateway_server_stops_gateway():
    gw = MagicMock()
    gw.is_connected = True
    gw.gateway = SimpleNamespace(enabled_servers={"time"})
    gw.stop = AsyncMock()
    feat = _feature(manager=MagicMock(), gateway=gw)
    feat._forget_server = AsyncMock()

    res = await feat.unload_tool("time")
    assert res.status is ToolResultStatus.OK
    gw.stop.assert_awaited_once()
    assert feat.gateway_manager is None
