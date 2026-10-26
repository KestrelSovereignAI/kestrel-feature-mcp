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
from unittest.mock import AsyncMock, MagicMock

import pytest

from kestrel_sdk.tools.result import ToolResult, ToolResultStatus
from kestrel_feature_mcp.feature import MCPAgent
from tests.unit.test_mcp_core_registry import CoreRegistryHost


def _make_feature(*, manager=None, gateway=None) -> MCPAgent:
    """Build an MCPAgent with explicit manager state."""
    host = CoreRegistryHost()
    host.agent_id = host.did
    feat = MCPAgent(host)
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
        result = await _make_feature().show_catalog(source="local")
        assert isinstance(result, ToolResult)
        assert result.status is ToolResultStatus.OK
        assert isinstance(result.data.get("servers"), list) and result.data["servers"]

    @pytest.mark.asyncio
    async def test_search_no_match_is_ok_empty(self):
        result = await _make_feature().search_servers("zzz-no-such-server-zzz", source="local")
        assert result.status is ToolResultStatus.OK
        assert result.data["matches"] == []

    @pytest.mark.asyncio
    async def test_search_match_is_ok(self):
        result = await _make_feature().search_servers("fetch", source="local")
        assert result.status is ToolResultStatus.OK
        assert "fetch" in result.data["matches"]

    @pytest.mark.asyncio
    async def test_server_info_unknown_is_failed(self):
        result = await _make_feature().server_info("zzz-no-such-server-zzz", source="local")
        assert result.status is ToolResultStatus.ERROR
        assert "not found" in (result.error or "")


# ---------------------------------------------------------------------------
# Docker-gated tools with manager unavailable return ToolResult.failed
# ---------------------------------------------------------------------------
class TestDockerUnavailableFails:
    @pytest.mark.asyncio
    async def test_load_tool_without_manager(self, monkeypatch):
        from kestrel_feature_mcp.manager import MCPToolManager, DockerDaemonUnavailableError
        create = AsyncMock(side_effect=DockerDaemonUnavailableError("test daemon unavailable"))
        monkeypatch.setattr(MCPToolManager, "create", create)
        feature = _make_feature(manager=None)
        feature.agent.did = feature.agent.agent_id = "did:test:unavailable"
        result = await feature.load_tool("some/image")
        create.assert_awaited_once_with(owner_did="did:test:unavailable")
        assert result.status is ToolResultStatus.ERROR
        assert "not available" in (result.error or "")

    @pytest.mark.asyncio
    async def test_list_tools_without_manager(self):
        result = await _make_feature(manager=None).list_tools()
        assert result.status is ToolResultStatus.OK
        assert result.data == {"tools": [], "containers": [], "remotes": []}

    @pytest.mark.asyncio
    async def test_gateway_stop_when_idle_is_ok(self):
        # Stopping an already-stopped gateway is idempotent, not an error.
        result = await _make_feature(gateway=None).gateway_stop()
        assert result.status is ToolResultStatus.OK
