"""Native MCP requests and connection ownership against a real HTTP SDK server."""

import asyncio
import json
import socket
from types import SimpleNamespace
from unittest.mock import MagicMock, AsyncMock

import pytest
from mcp.shared.exceptions import MCPError

from kestrel_feature_mcp.connection import MCPConnection
from mcp_types.version import LATEST_PROTOCOL_VERSION
from kestrel_feature_mcp.manager import DockerMCPGatewayError, MCPGatewayManager, MCPToolManager


@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan")])
@pytest.mark.parametrize("field", ["connect_timeout", "call_timeout", "close_timeout"])
def test_invalid_deadlines_fail_before_any_connection(value, field):
    with pytest.raises(ValueError, match="finite positive"):
        MCPConnection("http://127.0.0.1:1/mcp", **{field: value})




@pytest.mark.asyncio
async def test_requests_use_modern_wire_and_bearer_header(mcp_http_server):
    url, requests = mcp_http_server.url, mcp_http_server.requests
    connection = MCPConnection(url, headers={"Authorization": "Bearer test-token"})
    try:
        tools = await connection.connect()
        assert connection.protocol_version == LATEST_PROTOCOL_VERSION
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
    assert [m["method"] for m in messages] == ["server/discover", "tools/list", "tools/call"]
    for message in messages:
        assert LATEST_PROTOCOL_VERSION in json.dumps(message["params"]["_meta"])


@pytest.mark.asyncio
async def test_sdk_tool_failure_is_preserved(mcp_http_server):
    url = mcp_http_server.url
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
    url = mcp_http_server.url
    connection = MCPConnection(url.replace("/mcp", "/missing"), call_timeout=1)
    with pytest.raises(ExceptionGroup) as caught:
        await connection.connect()
    known, unexpected = caught.value.split(MCPError)
    assert known is not None and unexpected is None
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
    url, requests = mcp_http_server.url, mcp_http_server.requests
    connection = MCPConnection(url)
    try:
        tools = await connection.connect()
        assert {t.name for t in tools} == {"echo", "fail"}
    finally:
        await connection.close()
    messages = [json.loads(body) for _, body in requests if body
                and json.loads(body)["method"] == "tools/list"]
    assert len(messages) == 2
    assert messages[1]["params"]["cursor"] == "page-2"


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"repeat_cursor": True}], indirect=True)
async def test_repeated_cursor_fails_without_leaking_owner(mcp_http_server):
    url = mcp_http_server.url
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
    url, requests = mcp_http_server.url, mcp_http_server.requests
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
        assert manager.get_all_tools()[0]["protocol_version"] == LATEST_PROTOCOL_VERSION
    finally:
        await manager._drop_connection("test")
    assert all(scope["path"] == "/mcp" for scope, _ in requests)


@pytest.mark.asyncio
async def test_gateway_uses_same_native_client_with_its_bearer_token(mcp_http_server):
    url, requests = mcp_http_server.url, mcp_http_server.requests
    manager = MCPGatewayManager()
    manager.gateway = SimpleNamespace(endpoint_url=url, is_running=True)
    try:
        await manager._connect("gateway-token")
        assert manager.is_connected
        result = await manager.call_tool("echo", {"text": "gateway"})
        assert result.content[0].text == "gateway"
        assert manager.get_all_tools()[0]["inputSchema"]
        assert manager.get_all_tools()[0]["protocol_version"] == LATEST_PROTOCOL_VERSION
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
    url = mcp_http_server.url
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
    url = mcp_http_server.url
    manager = container_manager(url)
    port = int(url.split(":")[-1].split("/")[0])
    assert await manager._check_mcp_ready("127.0.0.1", port)
    assert not [task for task in asyncio.all_tasks() if task.get_name() == "mcp-connection"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"legacy": True}], indirect=True)
async def test_official_sdk_negotiates_a_published_handshake_revision(mcp_http_server):
    url, requests = mcp_http_server.url, mcp_http_server.requests
    connection = MCPConnection(url)
    try:
        await connection.connect()
        assert connection.protocol_version == "2025-11-25"
        result = await connection.call_tool("echo", {"text": "negotiated"})
        assert result.content[0].text == "negotiated"
    finally:
        await connection.close()
    methods = [json.loads(body)["method"] for _, body in requests if body]
    assert methods[:3] == ["server/discover", "initialize", "notifications/initialized"]
    assert any(scope["method"] == "DELETE" for scope, _ in requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"legacy": True, "delete_delay": 0.5}], indirect=True)
async def test_slow_session_termination_has_a_finite_shutdown_deadline(mcp_http_server):
    url = mcp_http_server.url
    connection = MCPConnection(url, close_timeout=0.05)
    await connection.connect()
    owner = connection._task
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(connection.close(), 0.3)
    assert owner.done()
    assert connection._task is None
    assert not connection.is_connected


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"legacy": True, "delete_delay": 0.2}], indirect=True)
async def test_cancelled_close_propagates_and_retains_the_owner_for_rejoin(mcp_http_server):
    url, requests = mcp_http_server.url, mcp_http_server.requests
    connection = MCPConnection(url)
    await connection.connect()
    owner = connection._task
    closing = asyncio.create_task(connection.close())
    try:
        async with asyncio.timeout(1):
            while not any(scope["method"] == "DELETE" for scope, _ in requests):
                await asyncio.sleep(0.001)
        closing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await closing
        assert connection._task is owner
        assert not connection.is_connected
        with pytest.raises(RuntimeError, match="not connected"):
            await connection.call_tool("echo", {"text": "closing"})
    finally:
        await connection.close()
    assert owner.done()


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"list_delay": 0.25}], indirect=True)
async def test_initial_discovery_uses_the_call_budget_after_connecting(mcp_http_server):
    url = mcp_http_server.url
    connection = MCPConnection(url, connect_timeout=0.15, call_timeout=1)
    try:
        tools = await connection.connect()
        assert {tool.name for tool in tools} == {"echo", "fail"}
    finally:
        await connection.close()


@pytest.mark.asyncio
async def test_readiness_refuses_real_transport_exception_groups():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        manager = MCPToolManager(docker_client=MagicMock())
        assert not await manager._check_mcp_ready("127.0.0.1", sock.getsockname()[1])
    assert not [task for task in asyncio.all_tasks() if task.get_name() == "mcp-connection"]


@pytest.mark.asyncio
async def test_readiness_does_not_hide_unexpected_group_members(monkeypatch):
    error = ExceptionGroup("unexpected", [ValueError("programming defect")])
    connection = SimpleNamespace(connect=AsyncMock(side_effect=error), close=AsyncMock())
    monkeypatch.setattr("kestrel_feature_mcp.manager.MCPConnection", lambda *a, **kw: connection)
    manager = MCPToolManager(docker_client=MagicMock())
    with pytest.raises(ExceptionGroup) as caught:
        await manager._check_mcp_ready("127.0.0.1", 1)
    assert caught.value.exceptions == error.exceptions
    connection.close.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"discover_delay": 0.25}], indirect=True)
async def test_connect_deadline_joins_a_real_slow_negotiation(mcp_http_server):
    url = mcp_http_server.url
    connection = MCPConnection(url, connect_timeout=0.05)
    with pytest.raises(TimeoutError):
        await connection.connect()
    assert connection._task is None
    assert not connection.is_connected


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"unsupported_version": True}], indirect=True)
async def test_no_common_revision_fails_without_a_private_fallback(mcp_http_server):
    url, requests = mcp_http_server.url, mcp_http_server.requests
    connection = MCPConnection(url)
    with pytest.raises(ExceptionGroup) as caught:
        await connection.connect()
    known, unexpected = caught.value.split(MCPError)
    assert known is not None and unexpected is None
    assert connection._task is None
    assert not connection.is_connected
    assert [json.loads(body)["method"] for _, body in requests if body] == ["server/discover"]


@pytest.mark.asyncio
async def test_close_of_a_dead_transport_does_not_rethrow_its_historical_failure(mcp_http_server):
    connection = MCPConnection(mcp_http_server.url, call_timeout=1)
    await connection.connect()
    owner = connection._task
    await mcp_http_server.stop()
    with pytest.raises((MCPError, ExceptionGroup)):
        await connection.call_tool("echo", {"text": "unreachable"})
    async with asyncio.timeout(2):
        while not owner.done():
            await asyncio.sleep(0)
    assert owner.exception() is not None
    await connection.close()
    assert connection._task is None


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"legacy": True, "delete_delay": 0.5}], indirect=True)
async def test_readiness_cleanup_uses_its_own_budget_and_reports_failure(mcp_http_server):
    manager = MCPToolManager(docker_client=MagicMock())
    port = int(mcp_http_server.url.split(":")[-1].split("/")[0])
    assert not await manager._check_mcp_ready("127.0.0.1", port, timeout=0.1)
    assert not [task for task in asyncio.all_tasks() if task.get_name() == "mcp-connection"]
