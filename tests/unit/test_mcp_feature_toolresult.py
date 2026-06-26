"""ToolResult contract tests for MCPAgent's agent-facing @tool methods (#1979 PR1).

Every mcp_* tool must return a ToolResult envelope (not a raw str) so that, once
the feature is explored and its tools mount into the host's dynamic registry,
each call produces an honest a2a_tool_dispatches row. These tests need neither
Docker nor a running gateway: the registry tools run against the bundled
catalog, and the Docker-gated tools are exercised with manager=None.
"""

from __future__ import annotations

import inspect
from typing import get_type_hints
from unittest.mock import MagicMock

import pytest

from kestrel_sdk.tools.result import ToolResult, ToolResultStatus
from kestrel_feature_mcp.feature import MCPAgent


def _make_feature(*, manager=None, gateway=None) -> MCPAgent:
    """Build an MCPAgent without running initialize() (which imports Docker)."""
    feat = MCPAgent(MagicMock())
    feat.manager = manager
    feat.gateway_manager = gateway
    return feat


# ---------------------------------------------------------------------------
# Contract: every @tool method annotates -> ToolResult
#
# Self-contained (no host-app import): mirrors the host's
# result_contract.find_violations so a backslide to a non-ToolResult return
# fails here too, but the package's tests stay runnable standalone.
# ---------------------------------------------------------------------------
def test_all_tools_return_tool_result_annotation():
    violations = []
    for name, method in inspect.getmembers(MCPAgent, predicate=inspect.isfunction):
        if not hasattr(method, "_tool_schema"):
            continue
        return_ann = get_type_hints(method).get("return", inspect.Parameter.empty)
        if return_ann is not ToolResult:
            violations.append(f"MCPAgent.{name}: return annotation is {return_ann!r}, expected ToolResult")
    assert violations == [], violations


# ---------------------------------------------------------------------------
# Registry tools (no Docker) return real ToolResult.ok / .failed
# ---------------------------------------------------------------------------
class TestRegistryTools:
    @pytest.mark.asyncio
    async def test_catalog_ok(self):
        result = await _make_feature().show_catalog()
        assert isinstance(result, ToolResult)
        assert result.status is ToolResultStatus.OK
        assert isinstance(result.data.get("servers"), list) and result.data["servers"]

    @pytest.mark.asyncio
    async def test_search_no_match_is_ok_empty(self):
        result = await _make_feature().search_servers("zzz-no-such-server-zzz")
        assert result.status is ToolResultStatus.OK
        assert result.data["matches"] == []

    @pytest.mark.asyncio
    async def test_search_match_is_ok(self):
        result = await _make_feature().search_servers("fetch")
        assert result.status is ToolResultStatus.OK
        assert "fetch" in result.data["matches"]

    @pytest.mark.asyncio
    async def test_server_info_unknown_is_failed(self):
        result = await _make_feature().server_info("zzz-no-such-server-zzz")
        assert result.status is ToolResultStatus.ERROR
        assert "not found" in (result.error or "")


# ---------------------------------------------------------------------------
# Docker-gated tools with manager unavailable return ToolResult.failed
# ---------------------------------------------------------------------------
class TestDockerUnavailableFails:
    @pytest.mark.asyncio
    async def test_load_tool_without_manager(self):
        result = await _make_feature(manager=None).load_tool("some/image")
        assert result.status is ToolResultStatus.ERROR
        assert "not available" in (result.error or "")

    @pytest.mark.asyncio
    async def test_list_tools_without_manager(self):
        result = await _make_feature(manager=None).list_tools()
        assert result.status is ToolResultStatus.ERROR

    @pytest.mark.asyncio
    async def test_call_tool_without_manager(self):
        result = await _make_feature(manager=None).call_tool("c", "t", {})
        assert result.status is ToolResultStatus.ERROR

    @pytest.mark.asyncio
    async def test_gateway_call_without_gateway(self):
        result = await _make_feature(gateway=None).gateway_call("fetch")
        assert result.status is ToolResultStatus.ERROR
        assert "not running" in (result.error or "")

    @pytest.mark.asyncio
    async def test_gateway_stop_when_idle_is_ok(self):
        # Stopping an already-stopped gateway is idempotent, not an error.
        result = await _make_feature(gateway=None).gateway_stop()
        assert result.status is ToolResultStatus.OK


# ---------------------------------------------------------------------------
# MCP tool-level failures (CallToolResult.isError=True) must surface as ERROR,
# not OK — MCP signals these without raising.
# ---------------------------------------------------------------------------
class TestIsErrorSurfacesAsFailed:
    @staticmethod
    def _error_result():
        from types import SimpleNamespace
        return SimpleNamespace(
            content=[SimpleNamespace(text="tool blew up")],
            isError=True,
        )

    @pytest.mark.asyncio
    async def test_legacy_call_tool_iserror_is_failed(self):
        from unittest.mock import AsyncMock
        manager = MagicMock()
        manager.call_tool = AsyncMock(return_value=self._error_result())
        result = await _make_feature(manager=manager).call_tool("c", "t", {})
        assert result.status is ToolResultStatus.ERROR
        assert "tool blew up" in (result.error or "")

    @pytest.mark.asyncio
    async def test_gateway_call_iserror_is_failed(self):
        from unittest.mock import AsyncMock
        gw = MagicMock()
        gw.is_connected = True
        gw.call_tool = AsyncMock(return_value=self._error_result())
        result = await _make_feature(gateway=gw).gateway_call("fetch", {})
        assert result.status is ToolResultStatus.ERROR
        assert "tool blew up" in (result.error or "")

    @pytest.mark.asyncio
    async def test_gateway_call_success_is_ok(self):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        ok_result = SimpleNamespace(content=[SimpleNamespace(text="hello")], isError=False)
        gw = MagicMock()
        gw.is_connected = True
        gw.call_tool = AsyncMock(return_value=ok_result)
        result = await _make_feature(gateway=gw).gateway_call("fetch", {})
        assert result.status is ToolResultStatus.OK
        assert "hello" in result.confirmation

    @pytest.mark.asyncio
    async def test_multi_block_content_is_preserved(self):
        """All content blocks must survive — not just the first."""
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        multi = SimpleNamespace(
            content=[SimpleNamespace(text="block-one"), SimpleNamespace(text="block-two")],
            isError=False,
        )
        gw = MagicMock()
        gw.is_connected = True
        gw.call_tool = AsyncMock(return_value=multi)
        result = await _make_feature(gateway=gw).gateway_call("fetch", {})
        assert result.status is ToolResultStatus.OK
        assert "block-one" in result.confirmation
        assert "block-two" in result.confirmation
