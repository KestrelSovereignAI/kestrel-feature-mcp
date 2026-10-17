"""Container reconnect retires the old native connection before publishing another."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from kestrel_feature_mcp.manager import MCPToolManager, MCPGatewayManager
from docker.errors import APIError


@pytest.mark.asyncio
async def test_drop_connection_closes_owner_and_forgets_entry():
    manager = MCPToolManager(docker_client=MagicMock())
    connection = AsyncMock()
    manager.active_tools = {"old": {"connection": connection}, "other": {}}
    await manager._drop_connection("old")
    connection.close.assert_awaited_once()
    assert manager.active_tools == {"other": {}}


@pytest.mark.asyncio
async def test_drop_connection_is_noop_when_not_connected():
    manager = MCPToolManager(docker_client=MagicMock())
    await manager._drop_connection("missing")
    assert manager.active_tools == {}


@pytest.mark.asyncio
async def test_failed_teardown_preserves_entry_for_retry():
    manager = MCPToolManager(docker_client=MagicMock())
    connection = AsyncMock()
    connection.close.side_effect = OSError("close failed")
    manager.active_tools["old"] = {"connection": connection}
    with pytest.raises(OSError, match="close failed"):
        await manager._drop_connection("old")
    assert manager.active_tools["old"]["connection"] is connection


@pytest.mark.asyncio
async def test_stop_still_reclaims_container_when_connection_teardown_fails():
    manager = MCPToolManager(docker_client=MagicMock())
    connection = AsyncMock()
    connection.close.side_effect = OSError("close failed")
    container = MagicMock()
    manager.active_tools["test"] = {"connection": connection, "container": container, "tools": []}
    with pytest.raises(OSError, match="close failed"):
        await manager.stop_tool("test")
    container.stop.assert_called_once()
    container.remove.assert_called_once_with(force=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["stop", "remove"])
async def test_docker_cleanup_failure_is_explicit_and_preserves_retry(operation):
    manager = MCPToolManager(docker_client=MagicMock())
    connection = AsyncMock()
    container = MagicMock()
    getattr(container, operation).side_effect = APIError("daemon refused cleanup")
    manager.active_tools["test"] = {"connection": connection, "container": container, "tools": []}
    with pytest.raises(APIError, match="daemon refused cleanup"):
        await manager.stop_tool("test")
    assert manager.active_tools["test"]["connection"] is connection


@pytest.mark.asyncio
async def test_failed_gateway_disconnect_retains_owner_for_cleanup_retry():
    manager = MCPGatewayManager()
    connection = AsyncMock()
    connection.close.side_effect = OSError("close failed")
    manager.connection = connection
    manager.tools = {"echo": object()}
    with pytest.raises(OSError, match="close failed"):
        await manager._disconnect()
    assert manager.connection is connection
    assert manager.tools == {}
