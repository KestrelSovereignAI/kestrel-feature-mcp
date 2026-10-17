"""Container reconnect retires the old native connection before publishing another."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from kestrel_feature_mcp.manager import MCPToolManager, MCPGatewayManager
from docker.errors import APIError, NotFound


@pytest.mark.asyncio
async def test_drop_connection_closes_owner_and_retains_container_custody():
    manager = MCPToolManager(docker_client=MagicMock())
    connection = AsyncMock()
    container = object()
    manager.owned_containers = {"old": {"container": container, "connection": connection}, "other": {}}
    await manager._drop_connection("old")
    connection.close.assert_awaited_once()
    assert manager.owned_containers == {
        "old": {"container": container, "connection": None, "tools": None}, "other": {},
    }


@pytest.mark.asyncio
async def test_drop_connection_is_noop_when_not_connected():
    manager = MCPToolManager(docker_client=MagicMock())
    await manager._drop_connection("missing")
    assert manager.owned_containers == {}


@pytest.mark.asyncio
async def test_failed_teardown_preserves_entry_for_retry():
    manager = MCPToolManager(docker_client=MagicMock())
    connection = AsyncMock()
    connection.close.side_effect = OSError("close failed")
    manager.owned_containers["old"] = {"connection": connection}
    with pytest.raises(OSError, match="close failed"):
        await manager._drop_connection("old")
    assert manager.owned_containers["old"]["connection"] is connection


@pytest.mark.asyncio
async def test_stop_still_reclaims_container_when_connection_teardown_fails():
    manager = MCPToolManager(docker_client=MagicMock())
    connection = AsyncMock()
    connection.close.side_effect = OSError("close failed")
    container = MagicMock()
    manager.docker_client.containers.get.side_effect = NotFound("removed")
    manager.owned_containers["test"] = {"connection": connection, "container": container, "tools": []}
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
    manager.owned_containers["test"] = {"connection": connection, "container": container, "tools": []}
    with pytest.raises(APIError, match="daemon refused cleanup"):
        await manager.stop_tool("test")
    assert manager.owned_containers["test"]["connection"] is connection
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
    manager.owned_containers["test"] = {"connection": AsyncMock(), "container": container, "tools": []}
    manager.docker_client.containers.get.side_effect = [container, NotFound("removed")] if removed else [container, container]
    if removed:
        assert await manager.stop_tool("test")
        assert "test" not in manager.owned_containers
    else:
        with pytest.raises(TimeoutError, match="still registered"):
            await manager.stop_tool("test")
        assert "test" in manager.owned_containers
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
    manager.owned_containers["owned"] = {"connection": connection, "tools": [object()]}
    with pytest.raises(TimeoutError, match="retirement deadline"):
        await manager.start_tool_container("image", container_name="owned")
    assert manager.owned_containers["owned"]["connection"] is connection
    assert manager.get_all_tools() == []
    manager.docker_client.containers.get.assert_not_called()


@pytest.mark.asyncio
async def test_healthcheck_failure_keeps_the_container_owned_for_unload():
    manager = MCPToolManager(docker_client=MagicMock())
    container = MagicMock(status="running")
    manager.docker_client.containers.get.return_value = container
    manager._wait_for_container_ready = AsyncMock(side_effect=TimeoutError("healthcheck failed"))
    with pytest.raises(TimeoutError, match="healthcheck failed"):
        await manager.start_tool_container("image", container_name="owned")
    assert manager.owned_containers["owned"]["container"] is container
    assert manager.owned_containers["owned"]["connection"] is None
    manager.docker_client.containers.get.side_effect = NotFound("removed")
    assert await manager.stop_tool("owned")
    container.stop.assert_called_once()
    container.remove.assert_called_once_with(force=True)
    assert manager.owned_containers == {}


@pytest.mark.asyncio
async def test_docker_inspection_failure_does_not_lose_prior_container_custody():
    manager = MCPToolManager(docker_client=MagicMock())
    connection = AsyncMock()
    container = MagicMock()
    manager.owned_containers["owned"] = {"container": container, "connection": connection, "tools": []}
    manager.docker_client.containers.get.side_effect = APIError("inspection failed")
    with pytest.raises(APIError, match="inspection failed"):
        await manager.start_tool_container("image", container_name="owned")
    assert manager.owned_containers["owned"]["container"] is container
    assert manager.owned_containers["owned"]["connection"] is None
    connection.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_container_without_a_connection_is_not_callable_but_can_be_stopped():
    manager = MCPToolManager(docker_client=MagicMock())
    container = MagicMock()
    manager.owned_containers["owned"] = {"container": container, "connection": None, "tools": []}
    with pytest.raises(ValueError, match="not connected"):
        await manager.call_tool("owned", "echo", {})
    manager.docker_client.containers.get.side_effect = NotFound("removed")
    assert await manager.stop_tool("owned")
    assert manager.owned_containers == {}
