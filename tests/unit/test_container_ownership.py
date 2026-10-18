"""Agent-bound Docker identities are checked before resource adoption or I/O."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
import asyncio
import threading
import builtins
import sys

from docker.errors import DockerException, NotFound
from requests.exceptions import ConnectionError as RequestsConnectionError, ReadTimeout, ChunkedEncodingError
import pytest

from kestrel_feature_mcp import manager as manager_module
from kestrel_feature_mcp.feature import MCPAgent
from kestrel_feature_mcp.manager import (
    ContainerOwnershipError, MCPToolManager, MCP_OWNER_LABEL, MCP_IMAGE_LABEL,
    container_name_for_image,
)


@pytest.mark.parametrize("owner", [None, "", "agent", "did:", "did:test:owner ", " did:test:owner", "did:test:owner\n", "did:te st:owner"])
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
    client.containers.create.assert_not_called()


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
    container = MagicMock(status="running", labels={MCP_OWNER_LABEL: "did:test:owner", MCP_IMAGE_LABEL: "image:latest"})
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
    assert client.containers.create.call_args.kwargs["labels"] == {
        MCP_OWNER_LABEL: manager.owner_did, MCP_IMAGE_LABEL: "image:latest",
    }
    assert client.containers.create.call_args.args[0] == "image:latest"
    assert client.containers.create.call_args.kwargs["ports"] == {"8000/tcp": ("127.0.0.1", None)}
    assert name == container_name_for_image("image", manager.owner_did)
    assert manager.owned_containers[name]["container"] is client.containers.create.return_value
    with pytest.raises(AttributeError):
        manager.owner_did = "did:test:other"


@pytest.mark.parametrize("failure", [DockerException("ping failed"), TypeError("bad client"), RuntimeError("bad implementation")])
@pytest.mark.asyncio
async def test_failed_ping_releases_client_and_preserves_unexpected_errors(failure, monkeypatch):
    client = MagicMock()
    client.ping.side_effect = failure
    monkeypatch.setattr(manager_module.docker, "from_env", MagicMock(return_value=client))
    error_type = RuntimeError if isinstance(failure, DockerException) else type(failure)
    with pytest.raises(error_type):
        await MCPToolManager.create(owner_did="did:test:owner")
    client.close.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("prior_state", ["missing", "removed"])
async def test_stale_resource_record_is_retired_before_a_new_image_pull_fails(prior_state):
    from docker.errors import APIError

    client = MagicMock()
    container = MagicMock(status="exited", labels={MCP_OWNER_LABEL: "did:test:owner", MCP_IMAGE_LABEL: "image:latest"})
    old_connection = AsyncMock()
    manager = MCPToolManager(owner_did="did:test:owner", docker_client=client)
    manager.owned_containers["owned"] = {"container": container, "connection": old_connection, "tools": []}
    client.containers.get.side_effect = NotFound("gone") if prior_state == "missing" else [container, NotFound("removed")]
    client.images.get.side_effect = NotFound("pull required")
    client.images.pull.side_effect = APIError("registry unavailable")
    with pytest.raises(APIError, match="registry unavailable"):
        await manager.start_tool_container("image", container_name="owned")
    assert manager.owned_containers == {}
    assert not await manager.stop_tool("owned")
    old_connection.close.assert_awaited_once()


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
@pytest.mark.parametrize("failure_stage", ["acquire", "ping"])
@pytest.mark.parametrize("failure_type", [DockerException, RequestsConnectionError, ReadTimeout, ChunkedEncodingError])
async def test_daemon_unavailability_disables_only_local_docker_tools(monkeypatch, caplog, failure_stage, failure_type):
    client = MagicMock()
    acquire = MagicMock(return_value=client)
    if failure_stage == "acquire":
        acquire.side_effect = failure_type("daemon unavailable")
    else:
        client.ping.side_effect = failure_type("daemon unavailable")
    monkeypatch.setattr(manager_module.docker, "from_env", acquire)
    feature = MCPAgent(SimpleNamespace(agent_id="did:test:host-agent"))
    await feature.initialize()
    assert feature.manager is None and feature.gateway_manager is None
    assert "daemon unavailable" in caplog.text
    if failure_stage == "ping":
        client.close.assert_called_once()


@pytest.mark.asyncio
async def test_missing_required_python_dependency_fails_startup_clearly(monkeypatch):
    original_import = builtins.__import__
    failure = ModuleNotFoundError("required docker SDK is not installed")

    def import_without_docker(name, *args, **kwargs):
        if name == "docker":
            raise failure
        return original_import(name, *args, **kwargs)

    feature = MCPAgent(SimpleNamespace(agent_id="did:test:host-agent"))
    with monkeypatch.context() as isolated:
        isolated.delitem(sys.modules, "kestrel_feature_mcp.manager")
        isolated.setattr(builtins, "__import__", import_without_docker)
        with pytest.raises(ModuleNotFoundError, match="required docker SDK") as caught:
            await feature.initialize()
        assert caught.value is failure


@pytest.mark.asyncio
async def test_unexpected_runtime_failure_is_not_classified_as_daemon_unavailability(monkeypatch):
    client = MagicMock()
    failure = RuntimeError("programming error in ping")
    client.ping.side_effect = failure
    monkeypatch.setattr(manager_module.docker, "from_env", MagicMock(return_value=client))
    feature = MCPAgent(SimpleNamespace(agent_id="did:test:host-agent"))
    with pytest.raises(RuntimeError, match="programming error in ping") as caught:
        await feature.initialize()
    assert caught.value is failure
    client.close.assert_called_once()


@pytest.mark.asyncio
async def test_feature_initialization_does_not_hide_an_invalid_agent():
    feature = MCPAgent(SimpleNamespace(agent_id=None))
    with pytest.raises(ValueError, match="agent DID"):
        await feature.initialize()


@pytest.mark.asyncio
async def test_slow_load_does_not_block_unrelated_unload_or_lose_a_same_resource_gate():
    client = MagicMock()
    client.containers.get.side_effect = NotFound("absent")
    client.images.get.side_effect = NotFound("pull required")
    entered = threading.Event()
    release = threading.Event()

    def pull(image):
        entered.set()
        if not release.wait(5):
            raise TimeoutError("test did not release controlled pull")

    client.images.pull.side_effect = pull
    manager = MCPToolManager(owner_did="did:test:scope", docker_client=client)
    manager._wait_for_container_ready = AsyncMock()
    name = container_name_for_image("slow", manager.owner_did)
    unrelated = MagicMock()
    manager._retain_container("unrelated", unrelated)
    loading = asyncio.create_task(manager.start_tool_container("slow"))
    cancelled = following = None
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        cancelled = asyncio.create_task(manager.stop_tool(name))
        await asyncio.sleep(0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        following = asyncio.create_task(manager.stop_tool(name))
        assert await asyncio.wait_for(manager.stop_tool("unrelated"), 1)
        assert not loading.done() and not following.done()
        unrelated.stop.assert_called_once()
        release.set()
        assert await loading == name
        assert await following
        assert manager.owned_containers == {}
        assert not manager._lifecycle_gates
    finally:
        release.set()
        await asyncio.gather(*(task for task in (loading, cancelled, following) if task is not None), return_exceptions=True)
        await manager.aclose()
