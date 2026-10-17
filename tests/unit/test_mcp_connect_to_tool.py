"""Container reconnect retires the old native connection before publishing another."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from kestrel_feature_mcp.manager import MCPToolManager


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
