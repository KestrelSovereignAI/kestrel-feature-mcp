"""F402: a wedged downstream MCP server must not hang the agent turn forever.

Both MCPToolManager.call_tool and MCPGatewayManager.call_tool bound
``session.call_tool`` with ``asyncio.wait_for(..., CALL_TOOL_TIMEOUT)``.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from kestrel_feature_mcp.manager import (
    DockerMCPGatewayError,
    MCPGatewayManager,
    MCPToolManager,
)


class _HangingSession:
    async def call_tool(self, name, args):
        await asyncio.sleep(30)  # never returns within the test's bound


class _HangingListSession:
    """Completes the connect handshake (session_future resolves) but wedges on
    tools/list — the P11 scenario."""
    async def list_tools(self):
        await asyncio.sleep(30)


@pytest.mark.asyncio
async def test_connect_to_tool_list_tools_times_out(monkeypatch):
    """P11: a server that finishes the SSE handshake but wedges on list_tools
    must not hang connect forever — list_tools is bounded by CALL_TOOL_TIMEOUT
    and surfaces as a connect TimeoutError."""
    monkeypatch.setattr("kestrel_feature_mcp.manager.CALL_TOOL_TIMEOUT", 0.05)
    with patch("kestrel_feature_mcp.manager.docker"):
        manager = MCPToolManager(docker_client=MagicMock())

    container = MagicMock()
    container.ports = {"8000/tcp": [{"HostPort": "9999"}]}
    manager.docker_client.containers.get = MagicMock(return_value=container)

    async def _fake_loop(url, fut):
        fut.set_result(_HangingListSession())  # handshake done
        await asyncio.sleep(30)                 # keep the loop task alive

    monkeypatch.setattr(manager, "_run_session_loop", _fake_loop)

    with pytest.raises(asyncio.TimeoutError):
        await manager.connect_to_tool("c")


@pytest.mark.asyncio
async def test_gateway_connect_clears_session_on_list_tools_timeout(monkeypatch):
    """P11 (codex round 2): when the gateway list_tools times out, self.session
    is already assigned — it must be cleared so is_connected() doesn't report the
    dead gateway as live."""
    monkeypatch.setattr("kestrel_feature_mcp.manager.CALL_TOOL_TIMEOUT", 0.05)
    manager = MCPGatewayManager()
    manager.gateway = MagicMock()
    manager.gateway.is_running = True
    manager.gateway.endpoint_url = "http://localhost:0/mcp"

    class _Transport:
        async def __aenter__(self):
            return (MagicMock(), MagicMock())
        async def __aexit__(self, *a):
            return False

    class _Sess:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def initialize(self):
            return None
        async def list_tools(self):
            await asyncio.sleep(30)  # wedge on tools/list

    monkeypatch.setattr(manager, "_open_transport", lambda url, headers: _Transport())
    monkeypatch.setattr(
        "kestrel_feature_mcp.manager.ClientSession", lambda r, w: _Sess()
    )

    with pytest.raises(DockerMCPGatewayError):
        await manager._connect("token")
    assert manager.session is None
    assert manager.is_connected is False  # @property — not a live gateway


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
