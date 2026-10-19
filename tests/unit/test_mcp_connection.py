"""Native MCP requests and connection ownership against a real HTTP SDK server."""

import asyncio
import json
import socket
from types import SimpleNamespace
from unittest.mock import MagicMock, AsyncMock

import pytest
from mcp.shared.exceptions import MCPError

from kestrel_feature_mcp.connection import MCPConnection, MCPCallOutcomeUnknownError
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
    with pytest.raises(ConnectionError, match="not connected"):
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


def container_manager(url, *, image="image"):
    port = url.split(":")[-1].split("/")[0]
    container = MagicMock()
    container.status = "running"
    container.ports = {"8000/tcp": [{"HostPort": port}]}
    container.labels = {"io.kestrel.mcp.agent-did": "did:test:manager", "io.kestrel.mcp.image": image}
    docker_client = MagicMock()
    docker_client.containers.get.return_value = container
    def removed(**kwargs):
        from docker.errors import NotFound
        docker_client.containers.get.side_effect = NotFound("removed")
    container.remove.side_effect = removed
    return MCPToolManager(owner_did="did:test:manager", docker_client=docker_client)


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"list_delay": 0.05}], indirect=True)
async def test_concurrent_reconnects_retire_every_superseded_native_owner(mcp_http_server, monkeypatch):
    from kestrel_feature_mcp import manager as manager_module

    connections = []
    original = manager_module.MCPConnection

    def tracked_connection(*args, **kwargs):
        connection = original(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(manager_module, "MCPConnection", tracked_connection)
    manager = container_manager(mcp_http_server.url)
    try:
        await asyncio.gather(manager.connect_to_tool("test"), manager.connect_to_tool("test"))
        assert len(connections) == 2
        assert sum(connection.is_connected for connection in connections) == 1
        assert connections[0]._task is None
        assert manager.owned_containers["test"]["connection"] is connections[1]
        assert (await manager.call_tool("test", "echo", {"text": "current"})).content[0].text == "current"
    finally:
        for connection in connections:
            await connection.close()
        await manager.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"list_delay": 0.15}], indirect=True)
async def test_cancelled_configuration_waiter_never_retires_the_active_owner(mcp_http_server):
    manager = container_manager(mcp_http_server.url)
    connecting = asyncio.create_task(manager.connect_to_tool("test"))
    try:
        async with asyncio.timeout(2):
            while ("test" not in manager.owned_containers
                   or not manager.owned_containers["test"]["connection"].is_connected):
                await asyncio.sleep(0.001)
        first = manager.owned_containers["test"]["connection"]
        waiter = asyncio.create_task(manager.stop_tool("test"))
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        await connecting
        assert first.is_connected
        manager.docker_client.containers.get.return_value.stop.assert_not_called()
        await manager.connect_to_tool("test")
        assert first._task is None
        assert manager.owned_containers["test"]["connection"].is_connected
    finally:
        if not connecting.done():
            connecting.cancel()
        await asyncio.gather(connecting, return_exceptions=True)
        await manager._drop_connection("test")
        await manager.aclose()


@pytest.mark.asyncio
async def test_tool_call_does_not_hold_or_wait_for_the_configuration_lock(mcp_http_server):
    manager = container_manager(mcp_http_server.url)
    try:
        await manager.connect_to_tool("test")
        async with manager._container_lifecycle("test"):
            result = await asyncio.wait_for(manager.call_tool("test", "echo", {"text": "concurrent"}), 1)
        assert result.content[0].text == "concurrent"
    finally:
        await manager._drop_connection("test")
        await manager.aclose()


@pytest.mark.asyncio
async def test_container_reconnect_uses_native_client_and_retires_old_owner(mcp_http_server):
    url, requests = mcp_http_server.url, mcp_http_server.requests
    manager = container_manager(url)
    try:
        await manager.connect_to_tool("test")
        old = manager.owned_containers["test"]["connection"]
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
@pytest.mark.parametrize("change", ["record", "connection", "catalog"])
async def test_bound_container_caller_rejects_withdrawn_identity_before_io(mcp_http_server, change):
    manager = container_manager(mcp_http_server.url)
    replacement = MCPConnection(mcp_http_server.url)
    original = None
    try:
        await manager.connect_to_tool("test")
        info = manager.owned_containers["test"]
        original = info["connection"]
        bound = manager.tool_caller("test")
        assert (await bound("echo", {"text": "original"})).content[0].text == "original"
        if change == "record":
            manager.owned_containers["test"] = dict(info)
        elif change == "connection":
            await replacement.connect()
            info["connection"] = replacement
        else:
            info["tools"] = None
        count = len(mcp_http_server.requests)
        assert original.is_connected  # Publication, rather than a dead socket, must refuse it.
        with pytest.raises(ValueError, match="changed; rediscover"):
            await bound("echo", {"text": "stale"})
        assert len(mcp_http_server.requests) == count
    finally:
        await replacement.close()
        if original is not None:
            await original.close()
        await manager._drop_connection("test")
        await manager.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["disconnect", "connection"])
async def test_bound_gateway_caller_does_not_follow_a_replacement(mcp_http_server, change):
    manager = MCPGatewayManager()
    manager.gateway = SimpleNamespace(endpoint_url=mcp_http_server.url, is_running=True)
    replacement = MCPConnection(mcp_http_server.url)
    original = None
    try:
        await manager._connect("test")
        original = manager.connection
        bound = manager.tool_caller()
        assert (await bound("echo", {"text": "original"})).content[0].text == "original"
        if change == "connection":
            await replacement.connect()
            manager.connection = replacement
        else:
            manager.connection = None
        count = len(mcp_http_server.requests)
        assert original.is_connected
        with pytest.raises(ValueError, match="changed; rediscover"):
            await bound("echo", {"text": "stale"})
        assert len(mcp_http_server.requests) == count
    finally:
        await replacement.close()
        if original is not None:
            await original.close()
        await manager._disconnect()


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
        assert manager.owned_containers["test"]["tools"] is None
        assert not manager.owned_containers["test"]["connection"].is_connected
        await manager._drop_connection("test")
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
        with pytest.raises(ConnectionError, match="not connected"):
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
        manager = MCPToolManager(owner_did="did:test:manager", docker_client=MagicMock())
        assert not await manager._check_mcp_ready("127.0.0.1", sock.getsockname()[1])
    assert not [task for task in asyncio.all_tasks() if task.get_name() == "mcp-connection"]


@pytest.mark.asyncio
async def test_readiness_does_not_hide_unexpected_group_members(monkeypatch):
    error = ExceptionGroup("unexpected", [ValueError("programming defect")])
    connection = SimpleNamespace(connect=AsyncMock(side_effect=error), close=AsyncMock())
    monkeypatch.setattr("kestrel_feature_mcp.manager.MCPConnection", lambda *a, **kw: connection)
    manager = MCPToolManager(owner_did="did:test:manager", docker_client=MagicMock())
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
    with pytest.raises(MCPCallOutcomeUnknownError) as caught:
        await connection.call_tool("echo", {"text": "unreachable"})
    assert isinstance(caught.value.__cause__, (MCPError, ExceptionGroup))
    async with asyncio.timeout(2):
        while not owner.done():
            await asyncio.sleep(0)
    assert owner.exception() is not None
    await connection.close()
    assert connection._task is None


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"legacy": True, "delete_delay": 0.5}], indirect=True)
async def test_readiness_cleanup_uses_its_own_budget_and_reports_failure(mcp_http_server):
    manager = MCPToolManager(owner_did="did:test:manager", docker_client=MagicMock())
    port = int(mcp_http_server.url.split(":")[-1].split("/")[0])
    assert not await manager._check_mcp_ready("127.0.0.1", port, timeout=0.1)
    assert not [task for task in asyncio.all_tasks() if task.get_name() == "mcp-connection"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{
    "legacy": True, "initialize_body_delay": 2, "delete_delay": 2,
}], indirect=True)
@pytest.mark.parametrize("close_timeout", [0.1, 15])
async def test_shutdown_deadline_covers_cleanup_of_a_partial_sdk_entry(mcp_http_server, close_timeout):
    connection = MCPConnection(mcp_http_server.url, connect_timeout=0.5, close_timeout=close_timeout)
    try:
        with pytest.raises(TimeoutError, match="MCP connection deadline"):
            await asyncio.wait_for(connection.connect(), 3.5)
    finally:
        owner = connection._task
        if owner is not None:
            await asyncio.wait({owner}, timeout=3)
        await connection.close()
    assert connection._task is None
    assert any(scope["method"] == "DELETE" for scope, _ in mcp_http_server.requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{
    "legacy": True, "initialize_body_delay": 2, "delete_delay": 2,
}], indirect=True)
async def test_abandoned_partial_entry_still_has_an_owned_shutdown_deadline(mcp_http_server):
    connection = MCPConnection(mcp_http_server.url, connect_timeout=0.5, close_timeout=0.5)
    caller = asyncio.create_task(connection.connect())
    try:
        async with asyncio.timeout(1.5):
            while not any(scope["method"] == "DELETE" for scope, _ in mcp_http_server.requests):
                await asyncio.sleep(0.001)
        owner = connection._task
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        done, _ = await asyncio.wait({owner}, timeout=0.8)
        assert owner in done, "abandoning the caller must not abandon SDK-entry cleanup"
    finally:
        retained = connection._task
        if retained is not None:
            await asyncio.wait({retained}, timeout=3)
        await connection.close()
    assert connection._task is None


@pytest.mark.asyncio
async def test_uncooperative_cleanup_has_a_finite_join_and_retains_ownership():
    connection = MCPConnection("http://127.0.0.1:1/mcp", close_timeout=0.05)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def resistant_owner():
        try:
            entered.set()
            await asyncio.Future()
        finally:
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    continue

    owner = asyncio.create_task(resistant_owner())
    connection._task = owner
    owner.add_done_callback(connection._owner_finished)
    await entered.wait()
    try:
        with pytest.raises(TimeoutError, match="MCP shutdown deadline"):
            await asyncio.wait_for(connection.close(), 1)
        assert connection._task is owner
        assert not owner.done()
        assert not connection.is_connected
    finally:
        release.set()
        await asyncio.wait({owner}, timeout=1)
        await connection.close()
    assert connection._task is None


@pytest.mark.asyncio
@pytest.mark.parametrize("mcp_http_server", [{"list_delay": 0.25}], indirect=True)
async def test_container_retains_startup_owner_without_admitting_calls_before_discovery(mcp_http_server):
    manager = container_manager(mcp_http_server.url)
    startup = asyncio.create_task(manager.connect_to_tool("test"))
    try:
        async with asyncio.timeout(2):
            while ("test" not in manager.owned_containers
                   or not manager.owned_containers["test"]["connection"].is_connected):
                await asyncio.sleep(0.001)
        with pytest.raises(ValueError, match="not connected"):
            await manager.call_tool("test", "echo", {"text": "premature"})
        await startup
        result = await manager.call_tool("test", "echo", {"text": "published"})
        assert result.content[0].text == "published"
    finally:
        await asyncio.wait({startup}, timeout=2)
        await manager._drop_connection("test")
