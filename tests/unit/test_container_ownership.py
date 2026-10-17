"""Agent-bound Docker identities are checked before resource adoption or I/O."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from docker.errors import DockerException, NotFound
import pytest

from kestrel_feature_mcp import manager as manager_module
from kestrel_feature_mcp.feature import MCPAgent
from kestrel_feature_mcp.manager import (
    ContainerOwnershipError, MCPToolManager, MCP_OWNER_LABEL, MCP_IMAGE_LABEL,
    container_name_for_image,
)


@pytest.mark.parametrize("owner", [None, "", "agent", "did:"])
@pytest.mark.asyncio
async def test_invalid_owner_is_rejected_before_docker_acquisition(owner, monkeypatch):
    acquire = MagicMock(side_effect=AssertionError("invalid ownership reached Docker"))
    monkeypatch.setattr(manager_module.docker, "from_env", acquire)
    with pytest.raises(ValueError, match="agent DID"):
        await MCPToolManager.create(owner_did=owner)
    acquire.assert_not_called()


@pytest.mark.parametrize("labels", [
    None, {}, {MCP_OWNER_LABEL: "did:test:other", MCP_IMAGE_LABEL: "image"},
    {MCP_OWNER_LABEL: "did:test:owner", MCP_IMAGE_LABEL: "other-image"},
])
@pytest.mark.asyncio
async def test_foreign_or_mismatched_container_is_never_adopted_restarted_or_removed(labels):
    client = MagicMock()
    container = MagicMock(status="running", labels=labels)
    client.containers.get.return_value = container
    manager = MCPToolManager(owner_did="did:test:owner", docker_client=client)
    with pytest.raises(ContainerOwnershipError):
        await manager.start_tool_container("image", container_name="claimed-name")
    assert manager.owned_containers == {}
    container.restart.assert_not_called()
    container.stop.assert_not_called()
    container.remove.assert_not_called()
    client.containers.run.assert_not_called()


@pytest.mark.parametrize("labels", [None, {}, {MCP_OWNER_LABEL: "did:test:other"}])
@pytest.mark.asyncio
async def test_connect_cannot_acquire_another_agents_container(labels, monkeypatch):
    client = MagicMock()
    client.containers.get.return_value = MagicMock(labels=labels)
    manager = MCPToolManager(owner_did="did:test:owner", docker_client=client)
    connection = MagicMock(side_effect=AssertionError("foreign ownership reached MCP"))
    monkeypatch.setattr(manager_module, "MCPConnection", connection)
    with pytest.raises(ContainerOwnershipError):
        await manager.connect_to_tool("foreign")
    assert manager.owned_containers == {}
    connection.assert_not_called()


@pytest.mark.asyncio
async def test_same_agent_new_manager_adopts_its_labeled_connection():
    client = MagicMock()
    container = MagicMock(status="running", labels={MCP_OWNER_LABEL: "did:test:owner", MCP_IMAGE_LABEL: "image"})
    client.containers.get.return_value = container
    manager = MCPToolManager(owner_did="did:test:owner", docker_client=client)
    manager._wait_for_container_ready = AsyncMock()
    expected_name = container_name_for_image("image", manager.owner_did)
    assert await manager.start_tool_container("image") == expected_name
    assert manager.owned_containers[expected_name]["container"] is container
    container.restart.assert_called_once()
    assert manager.owned_containers[expected_name]["tools"] is None


@pytest.mark.asyncio
async def test_created_container_carries_agent_and_connection_identity():
    client = MagicMock()
    client.containers.get.side_effect = NotFound("absent")
    manager = MCPToolManager(owner_did="did:test:owner", docker_client=client)
    manager._wait_for_container_ready = AsyncMock()
    name = await manager.start_tool_container("image")
    assert client.containers.run.call_args.kwargs["labels"] == {
        MCP_OWNER_LABEL: manager.owner_did, MCP_IMAGE_LABEL: "image",
    }
    assert name == container_name_for_image("image", manager.owner_did)
    assert manager.owned_containers[name]["container"] is client.containers.run.return_value
    with pytest.raises(AttributeError):
        manager.owner_did = "did:test:other"


@pytest.mark.parametrize("failure", [DockerException("ping failed"), TypeError("bad client")])
@pytest.mark.asyncio
async def test_failed_ping_releases_client_and_preserves_unexpected_errors(failure, monkeypatch):
    client = MagicMock()
    client.ping.side_effect = failure
    monkeypatch.setattr(manager_module.docker, "from_env", MagicMock(return_value=client))
    error_type = RuntimeError if isinstance(failure, DockerException) else TypeError
    with pytest.raises(error_type):
        await MCPToolManager.create(owner_did="did:test:owner")
    client.close.assert_called_once()


@pytest.mark.asyncio
async def test_feature_initialization_binds_the_hosts_agent_identity(monkeypatch):
    manager = MagicMock()
    create = AsyncMock(return_value=manager)
    monkeypatch.setattr(MCPToolManager, "create", create)
    feature = MCPAgent(SimpleNamespace(agent_id="did:test:host-agent"))
    await feature.initialize()
    create.assert_awaited_once_with(owner_did="did:test:host-agent")
    assert feature.manager is manager


@pytest.mark.asyncio
async def test_feature_initialization_does_not_hide_an_invalid_agent():
    feature = MCPAgent(SimpleNamespace(agent_id=None))
    with pytest.raises(ValueError, match="agent DID"):
        await feature.initialize()
