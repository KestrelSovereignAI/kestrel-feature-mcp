"""Container reconnect retires the old native connection before publishing another."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from kestrel_feature_mcp.manager import MCPToolManager, MCPGatewayManager
from docker.errors import APIError, NotFound


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
    manager.docker_client.containers.get.side_effect = NotFound("removed")
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
    manager.docker_client.containers.get.side_effect = NotFound("removed")
    manager.active_tools["test"] = {"connection": connection, "container": container, "tools": []}
    with pytest.raises(APIError, match="daemon refused cleanup"):
        await manager.stop_tool("test")
    assert manager.active_tools["test"]["connection"] is connection
    container.remove.assert_called_once_with(force=True)


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


@pytest.mark.asyncio
@pytest.mark.parametrize("removed", [False, True])
async def test_removal_is_confirmed_before_reporting_unload(monkeypatch, removed):
    monkeypatch.setattr("kestrel_feature_mcp.manager.MCP_REMOVAL_ATTEMPTS", 2)
    monkeypatch.setattr("kestrel_feature_mcp.manager.MCP_REMOVAL_RETRY_DELAY", 0)
    manager = MCPToolManager(docker_client=MagicMock())
    container = MagicMock()
    manager.active_tools["test"] = {"connection": AsyncMock(), "container": container, "tools": []}
    manager.docker_client.containers.get.side_effect = [container, NotFound("removed")] if removed else [container, container]
    if removed:
        assert await manager.stop_tool("test")
        assert "test" not in manager.active_tools
    else:
        with pytest.raises(TimeoutError, match="still registered"):
            await manager.stop_tool("test")
        assert "test" in manager.active_tools
    assert manager.docker_client.containers.get.call_count == 2


@pytest.mark.parametrize("image,name", [("acme/native:latest", "mcp-acme-native-latest"), ("private.registry:5000/image:v2", "mcp-private.registry-5000-image-v2")])
def test_default_container_name_is_shared_with_load_planning(image, name):
    from kestrel_feature_mcp.manager import container_name_for_image
    assert container_name_for_image(image) == name


@pytest.mark.asyncio
async def test_failed_retirement_unpublishes_tools_and_prevents_container_restart():
    manager = MCPToolManager(docker_client=MagicMock())
    connection = AsyncMock()
    connection.close.side_effect = TimeoutError("retirement deadline exceeded")
    manager.active_tools["owned"] = {"connection": connection, "tools": [object()]}
    with pytest.raises(TimeoutError, match="retirement deadline"):
        await manager.start_tool_container("image", container_name="owned")
    assert manager.active_tools["owned"]["connection"] is connection
    assert manager.get_all_tools() == []
    manager.docker_client.containers.get.assert_not_called()
