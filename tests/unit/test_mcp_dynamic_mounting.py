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
    return SimpleNamespace(content=content, isError=is_error)


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
        manager.stop_tool = AsyncMock()
        feat = _feature(host, manager=manager)
        res = await feat.unload_tool("mcp_fetch_123")
        assert res.status is ToolResultStatus.OK
        assert owner not in host.registered

    def test_generated_handles_are_provider_valid(self):
        # The host sanitises, but the proposed handles should already be tame.
        ws = build_wrappers("fetch", [{"name": "do_thing", "inputSchema": {}}], AsyncMock())
        assert re.fullmatch(r"[a-zA-Z0-9_-]+", ws[0].name)
