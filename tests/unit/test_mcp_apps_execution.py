"""Native HTTP calls through actual Core hooks, approvals and SQLite audit."""

import asyncio
from contextlib import AsyncExitStack
from contextvars import copy_context
from dataclasses import dataclass
import json

import pytest
import pytest_asyncio
from mcp import types
from kestrel_sdk.resources import ResourceConflict, ResourceOutcomeUnknown
from kestrel_sdk.hooks.base import Hook, HookEvent, HookOutput
from kestrel_sovereign.a2a.stores.unified.observability_store import ObservabilityStore
from kestrel_sovereign.agent.orchestrator_engine import OrchestratorEngineMixin
from kestrel_sovereign.features.security.approval_queue import ApprovalQueue
from kestrel_sovereign.features.security.hooks import SecurityHook
from kestrel_sovereign.features.security.permissions import PermissionLevel, PermissionStore
from kestrel_sovereign.hooks.manager import HooksManager
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend

from kestrel_feature_mcp.apps_execution import AppExecutor, RegisteredAppTool
from kestrel_feature_mcp.connection import MCPConnection, bind_tool_caller
from kestrel_feature_mcp.dynamic_tools import MCPToolWrapper
from tests.unit.test_mcp_core_registry import CoreRegistryHost


class GovernedMCPHost(OrchestratorEngineMixin, CoreRegistryHost):
    def __init__(self, store):
        super().__init__()
        self.observability_store = store
        self.hooks_manager = HooksManager()


class SchedulingStore(ObservabilityStore):
    dispatch_started = None
    release_dispatch = None

    async def log_tool_call(self, *args, **kwargs):
        self.admitted_sources.append(kwargs["metadata"]["source"])
        return await super().log_tool_call(*args, **kwargs)

    async def log_tool_dispatch(self, entry, *, required=False):
        if self.dispatch_started is not None:
            self.dispatch_started.set()
            await self.release_dispatch.wait()
        return await super().log_tool_dispatch(entry, required=required)


@dataclass
class AppBoundary:
    host: GovernedMCPHost
    backend: SQLiteBackend
    store: SchedulingStore
    permissions: PermissionStore
    approvals: ApprovalQueue
    approval_requests: asyncio.Queue
    executor: AppExecutor
    connection: MCPConnection
    registered: list[RegisteredAppTool]
    view: object
    owner_current: list[bool]

    def tool(self, name):
        return next(item for item in self.registered if item.tool.native_tool.name == name)


@pytest_asyncio.fixture
async def app_boundary(mcp_http_server, tmp_path):
    async with AsyncExitStack() as cleanup:
        backend = SQLiteBackend(str(tmp_path / "apps-audit.db"))
        await backend.connect()
        store = SchedulingStore(backend)
        store.admitted_sources = []
        await store.initialize()
        cleanup.push_async_callback(store.close)
        host = GovernedMCPHost(store)
        permissions = PermissionStore(str(tmp_path / "apps-permissions.db"))
        await permissions.initialize()
        requests = asyncio.Queue()
        queue = ApprovalQueue(on_request_added=requests.put, permission_store=permissions, agent=host)
        host.hooks_manager.register(SecurityHook(permissions, queue))
        connection = MCPConnection(mcp_http_server.url)
        native = await connection.connect()
        cleanup.push_async_callback(connection.close)
        caller = bind_tool_caller(connection, lambda: True, "native-apps", tool_names=[tool.name for tool in native])
        executor = AppExecutor(max_pending_calls=2)
        wrappers = [MCPToolWrapper(handle_name="app__" + tool.name, tool=tool,
                    caller=caller, app_executor=executor) for tool in native]
        registered = []
        host.register_dynamic_tools("mcp:original", wrappers,
            on_registered=lambda tool, binding: registered.append(RegisteredAppTool(tool, binding)))
        owner_current = [True]
        source = next(item for item in registered if item.tool.resource_uri)
        view = executor.open_view(source, registered, session_id="mcp-app:owned-view",
            owner_is_current=lambda: owner_current[0])
        cleanup.push_async_callback(view.close)
        yield AppBoundary(host, backend, store, permissions, queue, requests,
            executor, connection, registered, view, owner_current)
        queue.cancel_all()


pytestmark = pytest.mark.parametrize("mcp_http_server", [
    {"apps_tools": True, "apps_execution_tools": True,
     "advertised_tool_contracts": {"echo": {"meta": {"ui": {"visibility": ["model"]}}}}},
], indirect=True)


async def allow(boundary, name, permission=PermissionLevel.ALLOW):
    tool = boundary.tool(name)
    await boundary.permissions.set_permission("mcp:original", tool.binding.name, permission)
    return tool


@pytest.mark.asyncio
async def test_app_only_native_tool_is_governed_and_private_result_follows_required_sql_audit(app_boundary, mcp_http_server):
    peer = app_boundary
    tool = await allow(peer, "app_mutate")
    assert all(item["function"]["name"] != tool.binding.name for item in peer.host._build_all_tools())
    outside = await tool.binding.invoke({"text": "outside"}, session_id="untrusted-source", source="mcp-app")
    assert outside["status"] == "error" and not mcp_http_server.witness
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    call = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "once"}))
    try:
        await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
        assert mcp_http_server.witness == ["once"]
        assert not call.done(), "Native private data escaped before required structured audit"
        peer.store.release_dispatch.set()
        result = await call
        assert isinstance(result, types.CallToolResult)
        assert result.structured_content == {"text": "once"}
        assert result.meta["private-result"] == {"view": "only"}
        assert result.meta["io.modelcontextprotocol/serverInfo"]["name"] == "native-connection-test"
        assert result.content[0].meta == {"private-block": "view-only"}
        rows = await peer.backend.fetch_all("SELECT session_id, tool_name, result_status FROM a2a_tool_dispatches ORDER BY ts")
        assert len(rows) == 2
        assert tuple(rows[-1]) == (peer.view.session_id, tool.binding.name, "success")
        assert peer.store.admitted_sources[-1] == "mcp-app"
    finally:
        peer.store.release_dispatch.set()
        if not call.done():
            call.cancel()
        await asyncio.gather(call, return_exceptions=True)


@pytest.mark.asyncio
async def test_native_app_call_waits_for_real_one_shot_approval(app_boundary, mcp_http_server):
    peer = app_boundary
    await allow(peer, "app_mutate", PermissionLevel.ASK)
    first = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "approved"}))
    request = await asyncio.wait_for(peer.approval_requests.get(), 5)
    assert not first.done() and not mcp_http_server.witness
    assert await peer.approvals.submit_decision(request.id, True, scope="once")
    assert (await first).structured_content == {"text": "approved"}
    second = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "denied"}))
    request2 = await asyncio.wait_for(peer.approval_requests.get(), 5)
    assert request2.id != request.id
    assert await peer.approvals.submit_decision(request2.id, False)
    assert (await second).is_error
    assert mcp_http_server.witness == ["approved"]


@pytest.mark.asyncio
@pytest.mark.parametrize("withdraw", ["view", "owner", "connection", "registration"])
async def test_original_view_authority_is_rechecked_after_approval(app_boundary, mcp_http_server, withdraw):
    peer = app_boundary
    await allow(peer, "app_mutate", PermissionLevel.ASK)
    call = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "stale"}))
    request = await asyncio.wait_for(peer.approval_requests.get(), 5)
    if withdraw == "view":
        await peer.view.close()
    elif withdraw == "owner":
        peer.owner_current[0] = False
    elif withdraw == "connection":
        await peer.connection.close()
        await peer.connection.connect()
    else:
        peer.host.unregister_dynamic_tools("mcp:original")
    await peer.approvals.submit_decision(request.id, True, scope="once")
    if withdraw == "view":
        with pytest.raises(asyncio.CancelledError):
            await call
    else:
        with pytest.raises((ResourceConflict, ResourceOutcomeUnknown)):
            await call
    assert not mcp_http_server.witness


@pytest.mark.asyncio
async def test_failed_actual_sql_audit_withholds_native_result_and_never_reissues(app_boundary, mcp_http_server):
    peer = app_boundary
    await allow(peer, "app_mutate")
    await peer.backend.execute("DROP TABLE a2a_tool_dispatches")
    with pytest.raises(ResourceOutcomeUnknown, match="audit"):
        await peer.executor.invoke(peer.view, "app_mutate", {"text": "effect-before-audit-failure"})
    assert mcp_http_server.witness == ["effect-before-audit-failure"]


@pytest.mark.asyncio
async def test_app_cannot_call_model_only_or_foreign_tools(app_boundary, mcp_http_server):
    peer = app_boundary
    # The current catalog is a snapshot. Later remote metadata does not grant
    # tools absent from the retained original connection/batch.
    assert "echo" not in {tool.name for tool in peer.view.list_tools()}
    for name in ["echo", "not-advertised", "app__app_mutate"]:
        with pytest.raises(ResourceConflict, match="not available"):
            await peer.executor.invoke(peer.view, name, {})
    foreign = AppExecutor(max_pending_calls=2)
    with pytest.raises(ResourceConflict, match="another host"):
        await foreign.invoke(peer.view, "app_mutate", {"text": "foreign"})
    assert not mcp_http_server.witness


@pytest.mark.asyncio
async def test_view_close_joins_required_sql_finalization_through_repeated_cancellation(app_boundary, mcp_http_server):
    peer = app_boundary
    await allow(peer, "app_mutate")
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    call = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "before-close"}))
    closing = None
    try:
        await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
        assert mcp_http_server.witness == ["before-close"]
        closing = asyncio.create_task(peer.view.close())
        await asyncio.sleep(0)
        with pytest.raises(ResourceConflict, match="expired"):
            peer.view.list_tools()
        for _ in range(2):
            closing.cancel()
            await asyncio.sleep(0)
            assert not closing.done(), "View released an admitted call before its SQL audit finished"
        peer.store.release_dispatch.set()
        with pytest.raises(BaseExceptionGroup) as error:
            await closing
        assert all(isinstance(item, asyncio.CancelledError) for item in error.value.exceptions)
        with pytest.raises(asyncio.CancelledError):
            await call
        row = await peer.backend.fetch_one("SELECT result_status, error_class FROM a2a_tool_dispatches")
        assert tuple(row) == ("error", "ResourceOutcomeUnknown")
        assert mcp_http_server.witness == ["before-close"]
        assert not peer.view._calls
    finally:
        peer.store.release_dispatch.set()
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)
        if not call.done():
            call.cancel()
        await asyncio.gather(call, return_exceptions=True)


@pytest.mark.asyncio
async def test_timed_out_native_call_after_effects_is_unknown_and_not_replayed(app_boundary, mcp_http_server):
    peer = app_boundary
    await allow(peer, "app_mutate")
    peer.connection._call_timeout = 0.05
    mcp_http_server.settings["app_tool_delay"] = 0.2
    with pytest.raises(ResourceOutcomeUnknown, match="unknown"):
        await peer.executor.invoke(peer.view, "app_mutate", {"text": "effect-before-timeout"})
    assert mcp_http_server.witness == ["effect-before-timeout"]
    await asyncio.wait_for(mcp_http_server.settings["app_reply_recorded"].wait(), 5)
    requests = [json.loads(body) for _, body in mcp_http_server.requests if body]
    assert sum(message.get("method") == "tools/call" for message in requests) == 1
    row = await peer.backend.fetch_one("SELECT result_status FROM a2a_tool_dispatches")
    assert row[0] == "error"


@pytest.mark.asyncio
async def test_view_catalog_keeps_native_names_and_cannot_be_widened_by_exports(app_boundary, mcp_http_server):
    peer = app_boundary
    exported = peer.view.list_tools()
    assert {tool.name for tool in exported} == {"status_view", "app_mutate", "fail"}
    exported[0].meta["ui"]["visibility"].append("unrecognized")
    exported.clear()
    assert {tool.name for tool in peer.view.list_tools()} == {"status_view", "app_mutate", "fail"}
    other = MCPConnection(mcp_http_server.url)
    try:
        native = await other.connect()
        caller = bind_tool_caller(other, lambda: True, "other", tool_names=[tool.name for tool in native])
        source_tool = next(tool for tool in native if tool.name == "status_view")
        wrapper = MCPToolWrapper(handle_name="other__status_view", tool=source_tool,
            caller=caller, app_executor=peer.executor)
        foreign = []
        peer.host.register_dynamic_tools("mcp:other", [wrapper],
            on_registered=lambda tool, binding: foreign.append(RegisteredAppTool(tool, binding)))
        with pytest.raises(ValueError, match="same executor and original connection"):
            peer.executor.open_view(peer.view.source, [*peer.registered, *foreign],
                session_id="mcp-app:foreign", owner_is_current=lambda: True)
        assert not mcp_http_server.witness
    finally:
        await other.close()


@pytest.mark.asyncio
async def test_pending_app_calls_are_bounded_before_more_approval_or_execution_work(app_boundary, mcp_http_server):
    peer = app_boundary
    await allow(peer, "app_mutate", PermissionLevel.ASK)
    calls = [asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": str(index)}))
             for index in range(2)]
    try:
        for _ in calls:
            await asyncio.wait_for(peer.approval_requests.get(), 5)
        excess = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "excess"}))
        extra_approval = asyncio.create_task(peer.approval_requests.get())
        try:
            done, _ = await asyncio.wait({excess, extra_approval}, return_when=asyncio.FIRST_COMPLETED)
            assert excess in done, "An excess call reached the approval queue"
            with pytest.raises(ResourceConflict, match="pending-call limit"):
                await excess
            assert not mcp_http_server.witness
        finally:
            extra_approval.cancel()
            await peer.view.close()
            await asyncio.gather(excess, extra_approval, return_exceptions=True)
        await peer.view.close()
        assert all(call.done() and call.cancelled() for call in calls)
    finally:
        peer.approvals.cancel_all()
        await peer.view.close()
        await asyncio.gather(*calls, return_exceptions=True)


@pytest.mark.asyncio
async def test_inherited_context_cannot_reuse_an_admitted_app_invocation(app_boundary, mcp_http_server):
    peer = app_boundary
    tool = await allow(peer, "app_mutate")
    captured = []

    class CaptureContext(Hook):
        def __init__(self):
            super().__init__("capture-app-context", [HookEvent.POST_TOOL_USE])

        async def execute(self, value):
            captured.append(copy_context())
            return HookOutput.allow()

    peer.host.hooks_manager.register(CaptureContext())
    await peer.executor.invoke(peer.view, "app_mutate", {"text": "original"})
    assert len(captured) == 1
    inherited = asyncio.create_task(tool.tool.execute(text="reused-context"), context=captured[0])
    with pytest.raises(ResourceConflict, match="cannot be reused"):
        await inherited
    assert mcp_http_server.witness == ["original"]


@pytest.mark.asyncio
async def test_changed_governed_projection_cannot_reveal_the_unmodified_private_native_result(app_boundary, mcp_http_server):
    peer = app_boundary
    await allow(peer, "app_mutate")

    class RedactBusinessData(Hook):
        def __init__(self):
            super().__init__("redact-native-business-output", [HookEvent.POST_TOOL_USE])

        async def execute(self, value):
            value.tool_response["data"]["structuredContent"]["text"] = "redacted"
            return HookOutput.allow()

    peer.host.hooks_manager.register(RedactBusinessData())
    with pytest.raises(ResourceConflict, match="governed result changed"):
        await peer.executor.invoke(peer.view, "app_mutate", {"text": "original-private-data"})
    assert mcp_http_server.witness == ["original-private-data"]


@pytest.mark.asyncio
async def test_view_reads_only_its_original_associated_native_resource(app_boundary, mcp_http_server):
    peer = app_boundary
    with pytest.raises(ResourceConflict, match="originating tool association"):
        await peer.view.read_resource("ui://foreign/view.html", max_html_bytes=4096)
    assert mcp_http_server.settings.get("resource_reads", []) == []
    loaded = await peer.view.read_resource("ui://status/view.html", max_html_bytes=4096)
    assert loaded.html == "<!doctype html><p>Status</p>"
    assert mcp_http_server.settings["resource_reads"] == ["resources/read"]
    assert not mcp_http_server.witness
    await peer.view.close()
    with pytest.raises(ResourceConflict, match="expired"):
        await peer.view.read_resource(loaded.uri, max_html_bytes=4096)
    assert mcp_http_server.settings["resource_reads"] == ["resources/read"]


@pytest.mark.asyncio
async def test_view_owner_withdrawal_during_native_resource_read_withholds_html(app_boundary, mcp_http_server):
    peer = app_boundary
    mcp_http_server.settings["resource_delay"] = 0.1
    reading = asyncio.create_task(peer.view.read_resource("ui://status/view.html", max_html_bytes=4096))
    await asyncio.wait_for(mcp_http_server.settings["resource_read_started"].wait(), 5)
    peer.owner_current[0] = False
    with pytest.raises(ResourceConflict, match="expired"):
        await reading
    assert not mcp_http_server.witness
    assert mcp_http_server.settings["resource_reads"] == ["resources/read"]


@pytest.mark.asyncio
async def test_invalid_view_configuration_is_refused_before_native_io(app_boundary, mcp_http_server):
    peer = app_boundary
    for limit in [0, -1, True, None, 1.5]:
        with pytest.raises(ValueError, match="positive integer"):
            AppExecutor(max_pending_calls=limit)
    original = dict(source=peer.view.source, registered=peer.registered,
        session_id="mcp-app:configured", owner_is_current=lambda: True)
    for changes, error, message in [
        ({"session_id": " "}, ValueError, "session_id"),
        ({"registered": []}, ValueError, "retained"),
        ({"registered": [*peer.registered, peer.registered[0]]}, ValueError, "Duplicate"),
        ({"owner_is_current": None}, TypeError, "owner predicate"),
        ({"source": peer.tool("echo")}, ValueError, "associated"),
    ]:
        with pytest.raises(error, match=message):
            peer.executor.open_view(**(original | changes))
    with pytest.raises(TypeError, match="arguments must be an object"):
        await peer.executor.invoke(peer.view, "app_mutate", [])
    assert not mcp_http_server.witness
    assert peer.approval_requests.empty()
    assert mcp_http_server.settings.get("resource_reads", []) == []
