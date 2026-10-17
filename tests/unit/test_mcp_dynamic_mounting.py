"""Dynamic-mounting tests (#1979 PR3): MCP tools become first-class LLM tools.

No Docker / no real gateway: a fake host records what gets mounted so we can
introspect the wrappers and prove execution routes back to the manager.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from kestrel_sdk.tools.result import ToolResult, ToolResultStatus
from kestrel_feature_mcp.dynamic_tools import (
    MCPToolWrapper,
    _MCPToolSchema,
    build_wrappers,
    extract_mcp_result,
)
from kestrel_feature_mcp.feature import MCPAgent, _GATEWAY_OWNER, _container_owner


def _result(text="ok", *, is_error=False, blocks=None):
    content = blocks if blocks is not None else [SimpleNamespace(text=text)]
    return SimpleNamespace(content=content, is_error=is_error)


class _FakeHost:
    """Minimal host exposing the PR2 dynamic-tool registry, recording mounts."""

    def __init__(self):
        self.registered: dict = {}

    def register_dynamic_tools(self, owner, tools, *, pin=False):
        self.registered[owner] = list(tools)
        return len(self.registered[owner])

    def unregister_dynamic_tools(self, owner):
        return len(self.registered.pop(owner, []))


def _feature(host=None, *, manager=None, gateway=None) -> MCPAgent:
    feat = MCPAgent(host if host is not None else _FakeHost())
    feat.manager = manager
    feat.gateway_manager = gateway
    return feat


# ---------------------------------------------------------------------------
# Wrapper + schema
# ---------------------------------------------------------------------------
class TestWrapper:
    @pytest.mark.asyncio
    async def test_execute_returns_dict_envelope_ok(self):
        # execute() must return the ToolResult dict envelope (to_dict()), NOT a
        # raw ToolResult — that is the contract for objects in the host's
        # _direct_tools, and the host infers a2a_tool_dispatches status from the
        # dict's "status" key. (Regression: a raw ToolResult records as error
        # because infer_tool_result_status reads the .failed classmethod.)
        caller = AsyncMock(return_value=_result("hello"))
        w = MCPToolWrapper(handle_name="mcp__fetch__fetch", real_name="fetch",
                           description="d", input_schema=None, caller=caller)
        res = await w.execute(url="x")
        assert isinstance(res, dict) and res["status"] == "ok"
        assert "hello" in res["confirmation"]
        caller.assert_awaited_once_with("fetch", {"url": "x"})

    @pytest.mark.asyncio
    async def test_execute_iserror_is_failed(self):
        caller = AsyncMock(return_value=_result("boom", is_error=True))
        w = MCPToolWrapper(handle_name="h", real_name="fetch",
                           description="", input_schema=None, caller=caller)
        res = await w.execute()
        assert isinstance(res, dict) and res["status"] == "error" and "boom" in res["error"]

    @pytest.mark.asyncio
    async def test_execute_exception_is_failed(self):
        caller = AsyncMock(side_effect=RuntimeError("transport down"))
        w = MCPToolWrapper(handle_name="h", real_name="fetch",
                           description="", input_schema=None, caller=caller)
        res = await w.execute()
        assert isinstance(res, dict) and res["status"] == "error" and "transport down" in res["error"]

    def test_schema_uses_input_schema_as_parameters(self):
        schema = {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}
        s = _MCPToolSchema("mcp__fetch__fetch", "Fetch a URL", schema)
        fmt = s.to_openai_format()
        assert fmt["type"] == "function"
        assert fmt["function"]["name"] == "mcp__fetch__fetch"
        assert fmt["function"]["parameters"] == schema
        assert s.is_concurrency_safe is False

    def test_schema_defaults_to_open_object(self):
        s = _MCPToolSchema("h", "", None)
        assert s.to_openai_format()["function"]["parameters"] == {"type": "object", "properties": {}}

    def test_extract_multi_block(self):
        text, err = extract_mcp_result(_result(blocks=[SimpleNamespace(text="a"), SimpleNamespace(text="b")]))
        assert text == "a\nb" and err is False

    def test_build_wrappers_maps_handles_and_real_names(self):
        ws = build_wrappers("fetch", [{"name": "fetch", "description": "d", "inputSchema": {}}], AsyncMock())
        assert ws[0].name == "mcp__fetch__fetch"
        assert ws[0]._real_name == "fetch"


# ---------------------------------------------------------------------------
# Mount / unmount wiring
# ---------------------------------------------------------------------------
class TestMounting:
    def test_host_without_registry_degrades(self):
        feat = _feature(MagicMock(spec=[]))  # no register_dynamic_tools attr
        assert feat._host_supports_dynamic_tools() is False
        assert feat._mount_tools("mcp:x", "x", [{"name": "t"}], AsyncMock()) == 0

    def test_mount_refreshes_then_registers(self):
        host = _FakeHost()
        feat = _feature(host)
        n = feat._mount_tools("mcp:srv", "srv",
                              [{"name": "a", "inputSchema": {}}, {"name": "b", "inputSchema": {}}],
                              AsyncMock())
        assert n == 2
        assert {w._real_name for w in host.registered["mcp:srv"]} == {"a", "b"}

    @pytest.mark.asyncio
    async def test_mounted_gateway_tool_routes_to_manager(self):
        host = _FakeHost()
        gw = MagicMock()
        gw.is_connected = True
        gw.get_all_tools.return_value = [{"name": "fetch", "description": "d", "inputSchema": {}}]
        gw.call_tool = AsyncMock(return_value=_result("page"))
        feat = _feature(host, gateway=gw)

        mounted = feat._mount_gateway_tools()
        assert mounted == 1
        wrapper = host.registered[_GATEWAY_OWNER][0]
        # Executing the mounted wrapper proxies to the gateway's real tool name.
        res = await wrapper.execute(url="x")
        assert isinstance(res, dict) and res["status"] == "ok" and "page" in res["confirmation"]
        gw.call_tool.assert_awaited_once_with("fetch", {"url": "x"})

    @pytest.mark.asyncio
    async def test_gateway_stop_unmounts(self):
        host = _FakeHost()
        host.registered[_GATEWAY_OWNER] = ["x"]  # pretend something is mounted
        gw = MagicMock()
        gw.is_connected = True
        gw.stop = AsyncMock()
        feat = _feature(host, gateway=gw)
        res = await feat.gateway_stop()
        assert res.status is ToolResultStatus.OK
        assert _GATEWAY_OWNER not in host.registered  # unmounted

    @pytest.mark.asyncio
    async def test_unload_container_unmounts(self):
        host = _FakeHost()
        owner = _container_owner("mcp_fetch_123")
        host.registered[owner] = ["x"]
        manager = MagicMock()
        manager.stop_tool = AsyncMock(return_value=True)
        feat = _feature(host, manager=manager)
        res = await feat.unload_tool("mcp_fetch_123")
        assert res.status is ToolResultStatus.OK
        assert owner not in host.registered

    @pytest.mark.asyncio
    async def test_unload_not_loaded_is_honest_failure(self):
        """#9 finding #4: unloading a container that was never loaded is a
        no-op and must report failure, not a confident 'Unloaded'."""
        host = _FakeHost()
        manager = MagicMock()
        manager.stop_tool = AsyncMock(return_value=False)
        feat = _feature(host, manager=manager)
        res = await feat.unload_tool("mcp-gateway-that-isnt-loaded")
        assert res.status is ToolResultStatus.ERROR
        assert "nothing to unload" in (res.error or "").lower()

    @pytest.mark.asyncio
    async def test_enable_rejects_unknown_server(self, monkeypatch):
        """#9 finding #2 (Critical): enabling a name absent from every
        catalog must FAIL, not report a phantom success."""
        gw = MagicMock()
        gw.is_connected = True
        gw.tools = {}
        gw.enable_server = AsyncMock()
        feat = _feature(gateway=gw)

        async def _known():
            return {"fetch", "sqlite"}
        monkeypatch.setattr(feat, "_known_catalog_servers", _known)

        res = await feat.gateway_enable("this-server-does-not-exist-xyz")
        assert res.status is ToolResultStatus.ERROR
        assert "unknown mcp server" in (res.error or "").lower()
        gw.enable_server.assert_not_called()

    @pytest.mark.asyncio
    async def test_enable_no_new_tools_is_partial(self, monkeypatch):
        """#9 finding #3: a real enable that contributes no NEW tools is a
        no-op to the caller — report PARTIAL, not a confident 'Enabled'."""
        gw = MagicMock()
        gw.is_connected = True
        gw.tools = {"fetch": object()}
        gw.enable_server = AsyncMock(return_value=[SimpleNamespace(name="fetch")])
        gw.get_all_tools = MagicMock(return_value=[])
        feat = _feature(gateway=gw)

        async def _known():
            return {"fetch", "sqlite"}
        monkeypatch.setattr(feat, "_known_catalog_servers", _known)

        res = await feat.gateway_enable("sqlite")
        assert res.status is ToolResultStatus.PARTIAL
        assert res.data["new_tools"] == []

    @pytest.mark.asyncio
    async def test_enable_with_new_tools_is_ok(self, monkeypatch):
        gw = MagicMock()
        gw.is_connected = True
        gw.tools = {"fetch": object()}
        gw.enable_server = AsyncMock(return_value=[
            SimpleNamespace(name="fetch"), SimpleNamespace(name="sqlite_query"),
        ])
        gw.get_all_tools = MagicMock(return_value=[])
        feat = _feature(gateway=gw)

        async def _known():
            return {"fetch", "sqlite"}
        monkeypatch.setattr(feat, "_known_catalog_servers", _known)

        res = await feat.gateway_enable("sqlite")
        assert res.status is ToolResultStatus.OK
        assert res.data["new_tools"] == ["sqlite_query"]

    @pytest.mark.asyncio
    async def test_unverifiable_catalog_does_not_false_reject(self, monkeypatch):
        """When no catalog is resolvable, validation must be SKIPPED (a
        false rejection is its own honesty violation)."""
        gw = MagicMock()
        gw.is_connected = True
        gw.tools = {}
        gw.enable_server = AsyncMock(return_value=[SimpleNamespace(name="x")])
        gw.get_all_tools = MagicMock(return_value=[])
        feat = _feature(gateway=gw)

        async def _known():
            return None
        monkeypatch.setattr(feat, "_known_catalog_servers", _known)

        res = await feat.gateway_enable("some-unverifiable-server")
        # Proceeds to enable (no FAILED on unknown name); honesty about
        # the result is then governed by the new-tools delta.
        gw.enable_server.assert_awaited_once()
        assert res.status is not ToolResultStatus.ERROR

    def test_generated_handles_are_provider_valid(self):
        # The host sanitises, but the proposed handles should already be tame.
        ws = build_wrappers("fetch", [{"name": "do_thing", "inputSchema": {}}], AsyncMock())
        assert re.fullmatch(r"[a-zA-Z0-9_-]+", ws[0].name)


@pytest.mark.asyncio
async def test_shutdown_attempts_every_resource_and_propagates_cleanup_errors():
    manager = MagicMock()
    manager.active_tools = {"a": {}, "b": {}}
    manager.stop_tool = AsyncMock(side_effect=[TimeoutError("a close failed"), True])
    manager.aclose = AsyncMock()
    gateway = MagicMock()
    gateway.is_connected = False
    gateway.stop = AsyncMock()
    feature = _feature(manager=manager, gateway=gateway)
    with pytest.raises(TimeoutError, match="a close failed"):
        await feature.shutdown()
    assert [call.args[0] for call in manager.stop_tool.await_args_list] == ["a", "b"]
    manager.aclose.assert_awaited_once()
    gateway.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_failed_container_unload_unpublishes_and_forgets_before_stopping():
    host = _FakeHost()
    owner = _container_owner("mcp_failed")
    host.registered[owner] = ["stale"]
    manager = MagicMock()
    feature = _feature(host, manager=manager)
    feature._forget_server = AsyncMock()

    async def fail_stop(name):
        assert owner not in host.registered
        feature._forget_server.assert_awaited_once_with(name)
        raise TimeoutError("close deadline exceeded")

    manager.stop_tool = AsyncMock(side_effect=fail_stop)
    result = await feature.unload_tool("mcp_failed")
    assert result.status is ToolResultStatus.ERROR
    assert "close deadline" in result.error
    assert owner not in host.registered


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["load", "enable", "unload"])
async def test_failed_gateway_reconfiguration_unpublishes_tools(operation, monkeypatch):
    monkeypatch.setattr("kestrel_feature_mcp.feature.check_docker_mcp_available", lambda: True)
    host = _FakeHost()
    host.registered[_GATEWAY_OWNER] = ["stale"]
    gateway = MagicMock()
    gateway.is_connected = True
    gateway.tools = {"fetch": object()}
    gateway.gateway = SimpleNamespace(requested_servers={"fetch", "time"})
    feature = _feature(host, manager=MagicMock(), gateway=gateway)
    feature._reject_unknown_servers = AsyncMock(return_value=None)
    feature._forget_server = AsyncMock()
    feature._persist_server = AsyncMock()

    async def fail_reconnect(name):
        assert _GATEWAY_OWNER not in host.registered
        if operation == "unload":
            feature._forget_server.assert_awaited_once_with(name)
        gateway.is_connected = False
        raise TimeoutError("reconnect deadline exceeded")

    gateway.enable_server = AsyncMock(side_effect=fail_reconnect)
    gateway.disable_server = AsyncMock(side_effect=fail_reconnect)
    if operation == "load":
        result = await feature._load_via_gateway("sqlite")
    elif operation == "enable":
        result = await feature.gateway_enable("sqlite")
    else:
        result = await feature.unload_tool("time")
    assert result.status is ToolResultStatus.ERROR
    assert _GATEWAY_OWNER not in host.registered
    feature._persist_server.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"discover_delay": 0}], indirect=True)
@pytest.mark.parametrize("failure", ["healthcheck", "handshake"])
async def test_failed_container_reload_withdraws_handles_and_retires_the_old_owner(mcp_http_server, failure, monkeypatch):
    from urllib.parse import urlsplit
    from kestrel_feature_mcp.manager import MCPToolManager

    monkeypatch.setattr("kestrel_feature_mcp.manager.SESSION_CONNECT_TIMEOUT_SHORT", 0.5)
    host = _FakeHost()
    manager = MCPToolManager(docker_client=MagicMock())
    feature = _feature(host, manager=manager)
    name = "mcp-acme-native-latest"
    owner = _container_owner(name)
    container = MagicMock()
    container.status = "running"
    container.ports = {"8000/tcp": [{"HostPort": str(urlsplit(mcp_http_server.url).port)}]}
    manager.docker_client.containers.get.return_value = container
    manager._wait_for_container_ready = AsyncMock()
    first = await feature._load_via_container("acme/native:latest")
    assert first.status is ToolResultStatus.OK
    assert host.registered[owner]
    previous = manager.active_tools[name]["connection"]

    def restarting():
        assert owner not in host.registered
        assert not manager.active_tools
        assert not previous.is_connected

    container.restart.side_effect = restarting
    if failure == "healthcheck":
        manager._wait_for_container_ready.side_effect = TimeoutError("reload healthcheck failed")
    else:
        mcp_http_server.settings["discover_delay"] = 2
    try:
        result = await feature._load_via_container("acme/native:latest")
        assert result.status is ToolResultStatus.ERROR
        expected_error = "healthcheck" if failure == "healthcheck" else "deadline"
        assert expected_error in result.error
        assert owner not in host.registered
        assert manager.active_tools == {}
        assert manager.get_all_tools() == []
        assert previous._task is None
        manager._wait_for_container_ready.side_effect = None
        mcp_http_server.settings["discover_delay"] = 0
        recovered = await feature._load_via_container("acme/native:latest")
        assert recovered.status is ToolResultStatus.OK
        assert host.registered[owner]
        assert (await manager.call_tool(name, "echo", {"text": "recovered"})).content[0].text == "recovered"
    finally:
        mcp_http_server.settings["discover_delay"] = 0
        if name in manager.active_tools:
            await manager._drop_connection(name)
        await manager.aclose()
