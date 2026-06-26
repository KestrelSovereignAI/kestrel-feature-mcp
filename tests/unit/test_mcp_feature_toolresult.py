"""ToolResult contract tests for MCPAgent's agent-facing @tool methods (#1979 PR1).

Every mcp_* tool must return a ToolResult envelope (not a raw str) so that, once
the feature is explored and its tools mount into the host's dynamic registry,
each call produces an honest a2a_tool_dispatches row. These tests need neither
Docker nor a running gateway: the registry tools run against the bundled
catalog, and the Docker-gated tools are exercised with manager=None.
"""

from __future__ import annotations

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
# ---------------------------------------------------------------------------
def test_all_tools_return_tool_result_annotation():
    """Pins the migration so a backslide to str fails registration."""
    from kestrel_sovereign.tools.result_contract import find_violations

    violations = find_violations(MCPAgent)
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
