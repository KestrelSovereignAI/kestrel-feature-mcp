"""F402: a wedged downstream MCP server must not hang the agent turn forever.

Both MCPToolManager.call_tool and MCPGatewayManager.call_tool bound
``session.call_tool`` with ``asyncio.wait_for(..., CALL_TOOL_TIMEOUT)``.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from kestrel_feature_mcp.manager import MCPGatewayManager, MCPToolManager


class _HangingSession:
    async def call_tool(self, name, args):
        await asyncio.sleep(30)  # never returns within the test's bound


@pytest.mark.asyncio
async def test_container_call_tool_times_out(monkeypatch):
    monkeypatch.setattr("kestrel_feature_mcp.manager.CALL_TOOL_TIMEOUT", 0.05)
    with patch("kestrel_feature_mcp.manager.docker"):
        manager = MCPToolManager(docker_client=MagicMock())
    manager.active_tools["c"] = {"session": _HangingSession()}

    with pytest.raises(asyncio.TimeoutError):
        await manager.call_tool("c", "some_tool", {})


@pytest.mark.asyncio
async def test_gateway_call_tool_times_out(monkeypatch):
    monkeypatch.setattr("kestrel_feature_mcp.manager.CALL_TOOL_TIMEOUT", 0.05)
    manager = MCPGatewayManager()
    manager.session = _HangingSession()
    manager.tools = {"some_tool": object()}

    with pytest.raises(asyncio.TimeoutError):
        await manager.call_tool("some_tool", {})
