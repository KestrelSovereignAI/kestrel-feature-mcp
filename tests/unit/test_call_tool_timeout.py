"""F402: both managers use the connection's single whole-call deadline."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from kestrel_feature_mcp.connection import MCPConnection
from kestrel_feature_mcp.manager import MCPGatewayManager, MCPToolManager


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"tool_delay": 0.25}], indirect=True)
@pytest.mark.parametrize("kind", ["container", "gateway"])
async def test_call_timeout_uses_the_real_connection(kind, mcp_http_server):
    url = mcp_http_server.url
    connection = MCPConnection(url, call_timeout=0.05)
    try:
        await connection.connect()
        if kind == "container":
            manager = MCPToolManager(docker_client=MagicMock())
            manager.active_tools["test"] = {"connection": connection}
            call = manager.call_tool("test", "echo", {"text": "slow"})
        else:
            manager = MCPGatewayManager()
            manager.connection = connection
            manager.tools = {"echo": SimpleNamespace()}
            call = manager.call_tool("echo", {"text": "slow"})
        with pytest.raises(TimeoutError):
            await call
        assert connection.is_connected
    finally:
        await connection.close()
