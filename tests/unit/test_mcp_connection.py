"""Native MCP requests and connection ownership against a real HTTP SDK server."""

import asyncio
import json
import socket
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
import uvicorn
from mcp import types
from mcp.server import MCPServer
from mcp.shared.exceptions import MCPError

from kestrel_feature_mcp.connection import MCPConnection, MCP_PROTOCOL_VERSION
from kestrel_feature_mcp.manager import DockerMCPGatewayError, MCPGatewayManager, MCPToolManager


@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan")])
@pytest.mark.parametrize("field", ["connect_timeout", "call_timeout"])
def test_invalid_deadlines_fail_before_any_connection(value, field):
    with pytest.raises(ValueError, match="finite positive"):
        MCPConnection("http://127.0.0.1:1/mcp", **{field: value})


@pytest_asyncio.fixture
async def mcp_http_server(request):
    settings = getattr(request, "param", {})

    class TestServer(MCPServer):
        async def _handle_list_tools(self, ctx, params):
            await asyncio.sleep(settings.get("list_delay", 0))
            listed = await self.list_tools()
            if settings.get("repeat_cursor"):
                return types.ListToolsResult(tools=listed, next_cursor="repeated")
            if settings.get("paginate"):
                return types.ListToolsResult(
                    tools=listed[1:] if params and params.cursor else listed[:1],
                    next_cursor=None if params and params.cursor else "page-2",
                )
            return types.ListToolsResult(tools=listed)

    mcp = TestServer("native-connection-test")

    @mcp.tool()
    async def echo(text: str) -> str:
        return text

    @mcp.tool()
    async def fail() -> str:
        raise ValueError("test tool failure")

    app = mcp.streamable_http_app(stateless_http=True, json_response=True)
    requests = []

    async def recorded(scope, receive, send):
        if scope["type"] != "http":
            return await app(scope, receive, send)
        body = bytearray()

        async def read():
            message = await receive()
            body.extend(message.get("body", b""))
            return message

        try:
            await app(scope, read, send)
        finally:
            requests.append((scope, bytes(body)))

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(recorded, log_level="error"))
    task = asyncio.create_task(server.serve(sockets=[sock]))

    async def ready():
        while not server.started:
            if task.done():
                await task
                raise RuntimeError("test HTTP server exited before startup")
            await asyncio.sleep(0.01)

    try:
        await asyncio.wait_for(ready(), 5)
        yield f"http://127.0.0.1:{port}/mcp", requests
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        sock.close()


@pytest.mark.asyncio
async def test_requests_use_modern_wire_and_bearer_header(mcp_http_server):
    url, requests = mcp_http_server
    connection = MCPConnection(url, headers={"Authorization": "Bearer test-token"})
    try:
        tools = await connection.connect()
        assert {t.name for t in tools} == {"echo", "fail"}
        assert next(t for t in tools if t.name == "echo").input_schema["properties"]["text"]
        result = await connection.call_tool("echo", {"text": "native MCP"})
        assert not result.is_error
        assert result.content[0].text == "native MCP"
    finally:
        await connection.close()

    assert not connection.is_connected
    messages = []
    for scope, body in requests:
        headers = dict(scope["headers"])
        assert b"mcp-session-id" not in headers
        assert headers[b"authorization"] == b"Bearer test-token"
        if body:
            message = json.loads(body)
            assert headers[b"mcp-method"].decode() == message["method"]
            if message["method"] == "tools/call":
                assert headers[b"mcp-name"] == b"echo"
            messages.append(message)
    assert [m["method"] for m in messages] == ["tools/list", "tools/call"]
    for message in messages:
        assert MCP_PROTOCOL_VERSION in json.dumps(message["params"]["_meta"])


@pytest.mark.asyncio
async def test_sdk_tool_failure_is_preserved(mcp_http_server):
    url, _ = mcp_http_server
    connection = MCPConnection(url)
    try:
        await connection.connect()
        result = await connection.call_tool("fail")
        assert result.is_error
        assert result.content[0].text == "Error executing tool fail"
    finally:
        await connection.close()


@pytest.mark.asyncio
async def test_failed_startup_joins_owner_and_can_retry(mcp_http_server):
    url, _ = mcp_http_server
    connection = MCPConnection(url.replace("/mcp", "/missing"), call_timeout=1)
    with pytest.raises(MCPError, match="Not Found"):
        await connection.connect()
    assert not connection.is_connected
    assert connection._task is None
    connection.url = url
    try:
        await connection.connect()
        assert connection.is_connected
    finally:
        await connection.close()


@pytest.mark.asyncio
async def test_calls_on_closed_connection_fail_clearly():
    connection = MCPConnection("http://127.0.0.1:1/mcp")
    with pytest.raises(RuntimeError, match="not connected"):
        await connection.call_tool("echo")
    await connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_caller", [False, True])
async def test_abandoned_startup_joins_owner(monkeypatch, cancel_caller):
    connection = MCPConnection("http://127.0.0.1:1/mcp", connect_timeout=0.05)
    entered = asyncio.Event()
    exited = asyncio.Event()

    async def blocked_owner():
        try:
            entered.set()
            await asyncio.Future()
        finally:
            exited.set()

    monkeypatch.setattr(connection, "_run", blocked_owner)
    caller = asyncio.create_task(connection.connect())
    await entered.wait()
    if cancel_caller:
        caller.cancel()
    with pytest.raises(asyncio.CancelledError if cancel_caller else TimeoutError):
        await caller
    assert exited.is_set()
    assert connection._task is None
    assert not connection.is_connected


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"paginate": True}], indirect=True)
async def test_all_tool_pages_are_discovered(mcp_http_server):
    url, requests = mcp_http_server
    connection = MCPConnection(url)
    try:
        tools = await connection.connect()
        assert {t.name for t in tools} == {"echo", "fail"}
    finally:
        await connection.close()
    messages = [json.loads(body) for _, body in requests if body]
    assert len(messages) == 2
    assert messages[1]["params"]["cursor"] == "page-2"


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"repeat_cursor": True}], indirect=True)
async def test_repeated_cursor_fails_without_leaking_owner(mcp_http_server):
    url, _ = mcp_http_server
    connection = MCPConnection(url)
    with pytest.raises(ValueError, match="repeated.*cursor"):
        await connection.connect()
    assert not connection.is_connected
    assert connection._task is None


def container_manager(url):
    port = url.split(":")[-1].split("/")[0]
    container = MagicMock()
    container.ports = {"8000/tcp": [{"HostPort": port}]}
    docker_client = MagicMock()
    docker_client.containers.get.return_value = container
    return MCPToolManager(docker_client=docker_client)


@pytest.mark.asyncio
async def test_container_reconnect_uses_native_client_and_retires_old_owner(mcp_http_server):
    url, requests = mcp_http_server
    manager = container_manager(url)
    try:
        await manager.connect_to_tool("test")
        old = manager.active_tools["test"]["connection"]
        await manager.connect_to_tool("test")
        assert not old.is_connected
        assert old._task is None
        result = await manager.call_tool("test", "echo", {"text": "container"})
        assert result.content[0].text == "container"
        assert manager.get_all_tools()[0]["inputSchema"]
    finally:
        await manager._drop_connection("test")
    assert all(scope["path"] == "/mcp" for scope, _ in requests)


@pytest.mark.asyncio
async def test_gateway_uses_same_native_client_with_its_bearer_token(mcp_http_server):
    url, requests = mcp_http_server
    manager = MCPGatewayManager()
    manager.gateway = SimpleNamespace(endpoint_url=url, is_running=True)
    try:
        await manager._connect("gateway-token")
        assert manager.is_connected
        result = await manager.call_tool("echo", {"text": "gateway"})
        assert result.content[0].text == "gateway"
        assert manager.get_all_tools()[0]["inputSchema"]
    finally:
        await manager._disconnect()
    assert not manager.is_connected
    assert manager.tools == {}
    assert all(dict(scope["headers"])[b"authorization"] == b"Bearer gateway-token"
               for scope, _ in requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"list_delay": 0.25}], indirect=True)
@pytest.mark.parametrize("kind", ["gateway", "container"])
async def test_list_timeout_never_publishes_a_dead_manager(monkeypatch, mcp_http_server, kind):
    url, _ = mcp_http_server
    monkeypatch.setattr("kestrel_feature_mcp.manager.CALL_TOOL_TIMEOUT", 0.05)
    if kind == "container":
        manager = container_manager(url)
        call = manager.connect_to_tool("test")
    else:
        manager = MCPGatewayManager()
        manager.gateway = SimpleNamespace(endpoint_url=url, is_running=True)
        call = manager._connect("test")
    with pytest.raises((TimeoutError, MCPError, DockerMCPGatewayError)):
        await call
    if kind == "container":
        assert manager.active_tools == {}
    else:
        assert manager.connection is None
        assert manager.tools == {}
        assert not manager.is_connected
    assert not [task for task in asyncio.all_tasks() if task.get_name() == "mcp-connection"]


@pytest.mark.asyncio
async def test_container_readiness_checks_the_actual_protocol(mcp_http_server):
    url, _ = mcp_http_server
    manager = container_manager(url)
    port = int(url.split(":")[-1].split("/")[0])
    assert await manager._check_mcp_ready("127.0.0.1", port)
    assert not [task for task in asyncio.all_tasks() if task.get_name() == "mcp-connection"]
