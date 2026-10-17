"""
Integration tests for MCP Tool Manager.

Tests the dynamic loading and execution of MCP tools via Docker.
Uses REAL Docker containers and REAL MCP SDK connections.
"""

import pytest
import pytest_asyncio
import asyncio
import os
import tempfile
import shutil
from pathlib import Path
import logging
from contextlib import AsyncExitStack, asynccontextmanager
import uuid

from kestrel_feature_mcp.manager import MCPToolManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Test image
TEST_IMAGE = "kestrel-mcp-test-server"

@pytest.fixture
def check_docker():
    """Skip test if Docker is not available."""
    try:
        import docker
        from docker.credentials.errors import StoreError
        client = docker.from_env()
        client.ping()
    except ImportError as e:
        pytest.skip(f"Docker SDK not installed: {e}")
    except docker.credentials.errors.StoreError as e:
        pytest.skip(f"Docker credential store not available: {e}")
    except Exception as e:
        pytest.skip(f"Docker not available: {e}")

@pytest_asyncio.fixture
async def build_test_image(check_docker):
    """Build the test MCP server image."""
    try:
        import docker
        from docker.credentials.errors import StoreError
        client = docker.from_env()
        dockerfile_path = Path(__file__).parent / "mcp_test_server"

        logger.info(f"Building test image {TEST_IMAGE} from {dockerfile_path}...")
        client.images.build(
            path=str(dockerfile_path),
            tag=TEST_IMAGE,
            rm=True
        )
        yield TEST_IMAGE
        # Optional: cleanup image
        # client.images.remove(TEST_IMAGE)
    except docker.credentials.errors.StoreError as e:
        pytest.skip(f"Docker credential store not available: {e}")

@pytest_asyncio.fixture
async def mcp_manager(check_docker):
    """MCPToolManager instance for testing."""
    async with _owned_manager("did:test:manager") as manager:
        yield manager


@asynccontextmanager
async def _owned_manager(owner_did):
    manager = await MCPToolManager.create(owner_did=owner_did)
    try:
        yield manager
    finally:
        async with AsyncExitStack() as cleanup:
            cleanup.push_async_callback(manager.aclose)
            for name in manager.owned_containers:
                cleanup.push_async_callback(manager.stop_tool, name)


@pytest.mark.asyncio
@pytest.mark.docker
@pytest.mark.timeout(60)
async def test_agents_with_the_same_image_keep_independent_processes_through_reload_and_failure(build_test_image):
    from kestrel_feature_mcp.manager import ContainerOwnershipError

    identity = uuid.uuid4().hex
    async with (_owned_manager(f"did:test:first-{identity}") as first,
                _owned_manager(f"did:test:second-{identity}") as second):
        first_name = await first.start_tool_container(build_test_image)
        second_name = await second.start_tool_container(build_test_image)
        await first.connect_to_tool(first_name)
        await second.connect_to_tool(second_name)
        first_container = first.owned_containers[first_name]["container"]
        second_container = second.owned_containers[second_name]["container"]
        assert first_name != second_name
        assert first_container.id != second_container.id

        with pytest.raises(ContainerOwnershipError):
            await second.start_tool_container(build_test_image, container_name=first_name)
        with pytest.raises(ContainerOwnershipError):
            await second.connect_to_tool(first_name)
        assert (await first.call_tool(first_name, "echo", {"text": "ownership intact"})).content[0].text == "Echo: ownership intact"

        await first.start_tool_container(build_test_image)
        await first.connect_to_tool(first_name)
        assert (await second.call_tool(second_name, "echo", {"text": "after peer reload"})).content[0].text == "Echo: after peer reload"

        changed = await asyncio.to_thread(first_container.exec_run, [
            "python", "-c",
            "from pathlib import Path; Path('/app/server.py').write_text('raise SystemExit(23)\\n')",
        ])
        assert changed.exit_code == 0, changed.output
        with pytest.raises(RuntimeError, match="exited unexpectedly"):
            await first.start_tool_container(build_test_image)
        assert await first.stop_tool(first_name)
        await asyncio.to_thread(second_container.reload)
        assert second_container.status == "running"
        assert (await second.call_tool(second_name, "echo", {"text": "after peer unload"})).content[0].text == "Echo: after peer unload"


@pytest.mark.asyncio
@pytest.mark.docker
@pytest.mark.timeout(60)
async def test_new_manager_restores_its_existing_labeled_container(build_test_image):
    owner = f"did:test:restore-{uuid.uuid4().hex}"
    async with _owned_manager(owner) as earlier, _owned_manager(owner) as restored:
        name = await earlier.start_tool_container(build_test_image)
        container_id = earlier.owned_containers[name]["container"].id
        assert await restored.start_tool_container(build_test_image) == name
        assert restored.owned_containers[name]["container"].id == container_id
        await restored.connect_to_tool(name)
        assert (await restored.call_tool(name, "echo", {"text": "restored"})).content[0].text == "Echo: restored"


@pytest.mark.asyncio
@pytest.mark.docker
@pytest.mark.timeout(60)
async def test_failed_real_container_reload_remains_owned_and_can_be_unloaded(mcp_manager, build_test_image):
    """A process that exits on restart loses its tools but retains cleanup custody."""
    from docker.errors import NotFound

    name = "test-mcp-failed-reload"
    await mcp_manager.start_tool_container(build_test_image, container_name=name)
    await mcp_manager.connect_to_tool(name)
    connection = mcp_manager.owned_containers[name]["connection"]
    result = await mcp_manager.call_tool(name, "echo", {"text": "before reload"})
    assert result.content[0].text == "Echo: before reload"

    container = mcp_manager.owned_containers[name]["container"]
    changed = await asyncio.to_thread(container.exec_run, [
        "python", "-c",
        "from pathlib import Path; Path('/app/server.py').write_text('raise SystemExit(23)\\n')",
    ])
    assert changed.exit_code == 0, changed.output
    with pytest.raises(RuntimeError, match="exited unexpectedly"):
        await mcp_manager.start_tool_container(build_test_image, container_name=name)

    assert not connection.is_connected
    assert mcp_manager.get_all_tools() == []
    assert mcp_manager.owned_containers[name]["container"].id == container.id
    with pytest.raises(ValueError, match="not connected"):
        await mcp_manager.call_tool(name, "echo", {})
    assert await mcp_manager.stop_tool(name)
    assert name not in mcp_manager.owned_containers
    with pytest.raises(NotFound):
        await asyncio.to_thread(mcp_manager.docker_client.containers.get, name)

@pytest.mark.asyncio
async def test_mcp_server_lifecycle(mcp_manager, build_test_image):
    """
    Test the full lifecycle of a custom MCP server:
    1. Start container
    2. Connect via SSE
    3. List tools
    4. Execute tool (echo)
    5. Verify output
    6. Execute tool (add)
    7. Verify output
    8. Stop tool
    """
    container_name = "test-mcp-server"
    
    # 1. Start container
    logger.info(f"Starting {TEST_IMAGE}...")
    await mcp_manager.start_tool_container(
        TEST_IMAGE,
        container_name=container_name,
        environment={"PORT": "8000"}
    )
    
    # 2. Connect
    logger.info("Connecting to tool...")
    # Retry connection a few times as container startup might take a moment
    for i in range(5):
        try:
            tools = await mcp_manager.connect_to_tool(container_name)
            break
        except Exception as e:
            if i == 4:
                raise
            logger.info(f"Connection attempt {i+1} failed, retrying... ({e})")
            await asyncio.sleep(2)
    
    # 3. List tools
    logger.info(f"Discovered tools: {[t.name for t in tools]}")
    tool_names = [t.name for t in tools]
    assert "echo" in tool_names
    assert "add" in tool_names
    
    # 4. Execute tool (echo)
    test_text = "Hello MCP"
    logger.info(f"Calling echo with '{test_text}'...")
    
    result = await mcp_manager.call_tool(
        container_name, 
        "echo", 
        {"text": test_text}
    )
    
    # 5. Verify output
    logger.info(f"Echo result: {result}")
    # Result is likely a CallToolResult
    assert hasattr(result, "content")
    assert result.content[0].text == f"Echo: {test_text}"
    
    # 6. Execute tool (add)
    logger.info("Calling add with 10 + 20...")
    result = await mcp_manager.call_tool(
        container_name,
        "add",
        {"a": 10, "b": 20}
    )
    
    # 7. Verify output
    logger.info(f"Add result: {result}")
    assert int(result.content[0].text) == 30
    
    # 8. Stop tool
    logger.info("Stopping tool...")
    await mcp_manager.stop_tool(container_name)
    
    # Verify container is gone or stopped
    import docker
    client = docker.from_env()
    try:
        container = client.containers.get(container_name)
        assert container.status != "running"
    except docker.errors.NotFound:
        pass # Container removed, which is also fine
