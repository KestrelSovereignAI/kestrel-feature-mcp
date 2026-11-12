"""Native HTTP calls through actual Core hooks, approvals and SQLite audit."""

from uuid import uuid4

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
from contextvars import copy_context
from dataclasses import dataclass
import json
from types import SimpleNamespace

import pytest
import pytest_asyncio
from mcp import types
from kestrel_sdk.resources import ResourceConflict, ResourceOutcomeUnknown
from kestrel_sdk.hooks.base import Hook, HookEvent, HookOutput
from kestrel_sdk.tools import DeferredToolResult
from kestrel_sovereign.a2a.stores.unified.observability_store import ObservabilityStore
from kestrel_sovereign.features.security.approval_queue import ApprovalQueue
from kestrel_sovereign.features.security.hooks import SecurityHook
from kestrel_sovereign.features.security.permissions import PermissionLevel, PermissionStore
from kestrel_sovereign.kestrel_agent import KestrelAgent
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend
from kestrel_sovereign.testing.fixtures import native_tool_effect_agent as native_tool_effect_agent
from kestrel_sovereign.tool_effect_store import ToolEffectReconciliationRequired

from kestrel_feature_mcp.apps_execution import AppExecutor, MCPAppResultWithheld, RegisteredAppTool
from kestrel_feature_mcp.connection import MCPConnection, bind_tool_caller
from kestrel_feature_mcp.dynamic_tools import MCPToolWrapper


class SchedulingStore(ObservabilityStore):
    dispatch_started = None
    release_dispatch = None

    async def log_tool_call(self, *args, **kwargs):
        self.admitted_sources.append(kwargs["metadata"]["source"])
        return await super().log_tool_call(*args, **kwargs)

    async def log_tool_dispatch(self, entry, *, required=False):
        self.dispatch_attempts += 1
        if self.dispatch_started is not None:
            self.dispatch_started.set()
            await self.release_dispatch.wait()
        result = await super().log_tool_dispatch(entry, required=required)
        self.dispatch_acks += 1
        return result


@dataclass
class AppBoundary:
    host: KestrelAgent
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


@pytest.fixture
def initial_publisher():
    return None


@pytest_asyncio.fixture
async def app_boundary(mcp_http_server, tmp_path, initial_publisher, app_executor_factory, native_tool_effect_agent):
    async with AsyncExitStack() as cleanup:
        backend = SQLiteBackend(str(tmp_path / "apps-audit.db"))
        await backend.connect()
        store = SchedulingStore(backend)
        store.admitted_sources = []
        store.dispatch_attempts = 0
        store.dispatch_acks = 0
        await store.initialize()
        cleanup.push_async_callback(store.close)
        host = await native_tool_effect_agent(did='did:test:registry-catalog')
        host.observability_store = store
        permissions = PermissionStore(str(tmp_path / "apps-permissions.db"))
        await permissions.initialize()
        requests = asyncio.Queue()
        queue = ApprovalQueue(on_request_added=requests.put, permission_store=permissions, agent=host)
        host.hooks_manager.register(SecurityHook(permissions, queue))
        connection = MCPConnection(mcp_http_server.url)
        native = await connection.connect()
        cleanup.push_async_callback(connection.close)
        caller = bind_tool_caller(connection, lambda: True, "native-apps", tool_names=[tool.name for tool in native])
        executor = app_executor_factory(host=host, max_pending_calls=2,
            initial_publisher=initial_publisher.publish if initial_publisher is not None else None)
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
async def test_native_app_call_uses_and_retires_its_host_owned_task(app_boundary, mcp_http_server, monkeypatch):
    peer = app_boundary
    await allow(peer, 'app_mutate')
    admitted, retired = [], []

    @asynccontextmanager
    async def call_scope(operation, *, name, cancel):
        async with peer.host.mcp_app_call_scope(operation, name=name, cancel=cancel) as owner:
            admitted.append(owner.task)
            yield owner
        retired.append(owner.task)

    monkeypatch.setattr(peer.executor, '_call_scope', call_scope, raising=False)
    result = await peer.executor.invoke(peer.view, 'app_mutate', {'text': 'host-owned'},
        operation_id=uuid4().hex)
    assert len(admitted) == 1, 'MCP App bypassed its original host-owned task admission'
    assert retired == admitted and admitted[0].done() and not peer.view._calls
    assert result.structured_content == {'text': 'host-owned'}
    assert mcp_http_server.witness == ['host-owned']


@pytest.mark.asyncio
async def test_app_only_native_tool_is_governed_and_private_result_follows_required_sql_audit(app_boundary, mcp_http_server):
    peer = app_boundary
    tool = await allow(peer, "app_mutate")
    assert all(item["function"]["name"] != tool.binding.name for item in peer.host._build_all_tools())
    outside = await tool.binding.invoke({"text": "outside"}, session_id="untrusted-source", source="mcp-app", operation_id=uuid4().hex)
    assert outside["status"] == "error" and not mcp_http_server.witness
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    call = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "once"}, operation_id=uuid4().hex))
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
    first = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "approved"}, operation_id=uuid4().hex))
    request = await asyncio.wait_for(peer.approval_requests.get(), 5)
    assert not first.done() and not mcp_http_server.witness
    assert await peer.approvals.submit_decision(request.id, True, scope="once")
    assert (await first).structured_content == {"text": "approved"}
    second = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "denied"}, operation_id=uuid4().hex))
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
    call = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "stale"}, operation_id=uuid4().hex))
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
        with pytest.raises(ResourceConflict, match="before native execution"):
            await call
        assert not call.cancelled()
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
        await peer.executor.invoke(peer.view, "app_mutate", {"text": "effect-before-audit-failure"}, operation_id=uuid4().hex)
    assert mcp_http_server.witness == ["effect-before-audit-failure"]


@pytest.mark.asyncio
async def test_app_cannot_call_model_only_or_foreign_tools(app_boundary, mcp_http_server):
    peer = app_boundary
    # The current catalog is a snapshot. Later remote metadata does not grant
    # tools absent from the retained original connection/batch.
    assert "echo" not in {tool.name for tool in peer.view.list_tools()}
    for name in ["echo", "not-advertised", "app__app_mutate"]:
        with pytest.raises(ResourceConflict, match="not available"):
            await peer.executor.invoke(peer.view, name, {}, operation_id=uuid4().hex)
    foreign = AppExecutor(host=peer.host, max_pending_calls=2)
    with pytest.raises(ResourceConflict, match="another host"):
        await foreign.invoke(peer.view, "app_mutate", {"text": "foreign"}, operation_id=uuid4().hex)
    assert not mcp_http_server.witness


@pytest.mark.asyncio
@pytest.mark.parametrize('cancellation', ['view', 'caller-first', 'view-first'])
async def test_view_close_joins_required_sql_finalization_through_repeated_cancellation(
        app_boundary, mcp_http_server, cancellation):
    peer = app_boundary
    await allow(peer, "app_mutate")
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    call = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "before-close"}, operation_id=uuid4().hex))
    closing = None
    try:
        await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
        assert mcp_http_server.witness == ["before-close"]
        child, = peer.view._calls
        if cancellation == 'caller-first':
            call.cancel()
            async with asyncio.timeout(5):
                while child not in peer.view._cancelled_calls:
                    await asyncio.sleep(0)
        closing = asyncio.create_task(peer.view.close())
        async with asyncio.timeout(5):
            while child not in peer.view._cancelled_calls or not peer.view.is_closed:
                await asyncio.sleep(0)
        if cancellation == 'view-first':
            call.cancel()
        assert not child.done(), 'The original App task lost its pending SQL finalization'
        with pytest.raises(ResourceConflict, match="expired"):
            peer.view.list_tools()
        for _ in range(2):
            closing.cancel()
            await asyncio.sleep(0)
            assert not closing.done(), "View released an admitted call before its SQL audit finished"
        peer.store.release_dispatch.set()
        with pytest.raises(asyncio.CancelledError):
            await closing
        assert closing.cancelled()
        if cancellation == 'view':
            with pytest.raises(ResourceOutcomeUnknown):
                await call
            assert not call.cancelled()
        else:
            with pytest.raises(asyncio.CancelledError):
                await call
            assert call.cancelled()
        row = await peer.backend.fetch_one("SELECT result_status, error_class FROM a2a_tool_dispatches")
        # The native effect returned before cancellation; its audit acknowledged
        # that known effect. Closing still withholds the private result.
        assert tuple(row) == ("success", None)
        assert peer.store.dispatch_attempts == peer.store.dispatch_acks == 1
        assert await peer.host.tool_effect_store.database.fetchone(
            "SELECT state FROM tool_effect_claims") == ("RETURNED_OK",)
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
@pytest.mark.parametrize("rewrite_projection", [False, True])
async def test_timed_out_native_call_after_effects_is_unknown_and_not_replayed(app_boundary, mcp_http_server, rewrite_projection):
    peer = app_boundary
    await allow(peer, "app_mutate")
    if rewrite_projection:
        class RedactOutcomeData(Hook):
            def __init__(self):
                super().__init__("redact-model-outcome-data", [HookEvent.POST_TOOL_USE])

            async def execute(self, value):
                value.tool_response["data"] = {}
                return HookOutput.allow()

        peer.host.hooks_manager.register(RedactOutcomeData())
    peer.connection._call_timeout = 0.05
    mcp_http_server.settings["app_tool_delay"] = 0.2
    operation_id = uuid4().hex
    with pytest.raises(ResourceOutcomeUnknown):
        await peer.executor.invoke(peer.view, "app_mutate", {"text": "effect-before-timeout"}, operation_id=operation_id)
    assert mcp_http_server.witness == ["effect-before-timeout"]
    await asyncio.wait_for(mcp_http_server.settings["app_reply_recorded"].wait(), 5)
    assert await peer.host.tool_effect_store.database.fetchone(
        'SELECT state FROM tool_effect_claims') == ('UNCONFIRMED',)
    with pytest.raises(ToolEffectReconciliationRequired):
        await peer.executor.invoke(peer.view, "app_mutate", {"text": "effect-before-timeout"}, operation_id=operation_id)
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
    calls = [asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": str(index)}, operation_id=uuid4().hex))
             for index in range(2)]
    try:
        for _ in calls:
            await asyncio.wait_for(peer.approval_requests.get(), 5)
        excess = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "excess"}, operation_id=uuid4().hex))
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
        assert all(call.done() and not call.cancelled() and isinstance(call.exception(), ResourceConflict)
                   for call in calls)
    finally:
        peer.approvals.cancel_all()
        await peer.view.close()
        await asyncio.gather(*calls, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("revoke_view", [False, True])
async def test_actual_app_caller_cancellation_remains_cancellation(app_boundary, mcp_http_server, revoke_view):
    peer = app_boundary
    await allow(peer, "app_mutate", PermissionLevel.ASK)
    call = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "cancelled"}, operation_id=uuid4().hex))
    await asyncio.wait_for(peer.approval_requests.get(), 5)
    if revoke_view:
        peer.view.revoke()
    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call
    assert call.cancelled() and not mcp_http_server.witness
    await peer.view.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["tool", "resource"])
async def test_view_withdrawal_at_the_owned_result_handoff_withholds_delivery(app_boundary, mcp_http_server, operation):
    peer = app_boundary
    await allow(peer, "app_mutate")
    holder, scheduled = [], []

    def current_owner():
        completed = bool(mcp_http_server.witness or mcp_http_server.settings.get("resource_reads"))
        if completed and not scheduled:
            scheduled.append(True)
            # A real lifecycle callback runs after native completion but before
            # the awaiting API task receives its owned child's result.
            asyncio.get_running_loop().call_soon(holder[0].revoke)
        return True

    view = peer.executor.open_view(peer.view.source, peer.registered,
        session_id="mcp-app:owned-handoff", owner_is_current=current_owner)
    holder.append(view)
    try:
        if operation == "tool":
            with pytest.raises(ResourceOutcomeUnknown):
                await peer.executor.invoke(view, "app_mutate", {"text": "handoff-once"}, operation_id=uuid4().hex)
            assert mcp_http_server.witness == ["handoff-once"]
        else:
            with pytest.raises(ResourceConflict):
                await view.read_resource("ui://status/view.html", max_html_bytes=4096)
            assert not mcp_http_server.witness
        assert scheduled and not view._calls
    finally:
        await view.close()


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
    await peer.executor.invoke(peer.view, "app_mutate", {"text": "original"}, operation_id=uuid4().hex)
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
    with pytest.raises(ResourceOutcomeUnknown, match="governed result changed"):
        await peer.executor.invoke(peer.view, "app_mutate", {"text": "original-private-data"}, operation_id=uuid4().hex)
    assert mcp_http_server.witness == ["original-private-data"]


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", ["deny", "ask", "stop", "raise", "timeout", "invalid", "replace-equal"])
async def test_native_app_delivery_requires_completed_post_policy_even_without_projection_edits(
    app_boundary, mcp_http_server, policy,
):
    peer = app_boundary
    tool = await allow(peer, "app_mutate")

    class WithholdNativeDelivery(Hook):
        def __init__(self):
            super().__init__("withhold-native-app-delivery", [HookEvent.POST_TOOL_USE], timeout=0.01)

        async def execute(self, value):
            assert value.tool_name == tool.binding.name
            if policy == "deny":
                return HookOutput.deny("Native delivery refused")
            if policy == "ask":
                return HookOutput.ask("post-policy-approval", "Delivery needs approval")
            if policy == "stop":
                return HookOutput(continue_execution=False)
            if policy == "raise":
                raise RuntimeError("Post-tool policy did not complete")
            if policy == "timeout":
                await asyncio.sleep(10)
            if policy == "replace-equal":
                value.tool_response = dict(value.tool_response)
                return HookOutput.allow()
            return None

    peer.host.hooks_manager.register(WithholdNativeDelivery())
    with pytest.raises(MCPAppResultWithheld, match="Post-tool policy did not approve"):
        await peer.executor.invoke(peer.view, "app_mutate", {"text": "effect-before-post-policy"}, operation_id=uuid4().hex)
    assert mcp_http_server.witness == ["effect-before-post-policy"]
    rows = await peer.backend.fetch_all("SELECT session_id, tool_name, result_status FROM a2a_tool_dispatches")
    assert len(rows) == 1 and tuple(rows[0]) == (peer.view.session_id, tool.binding.name, "success")


@pytest.mark.asyncio
@pytest.mark.parametrize("transfer", [False, True])
async def test_in_process_hook_cannot_bypass_host_completion_by_consuming_the_factory(
    app_boundary, mcp_http_server, transfer,
):
    peer = app_boundary
    tool = await allow(peer, "app_mutate")

    class PrematureCompletion(Hook):
        def __init__(self):
            super().__init__("premature-native-app-completion", [HookEvent.POST_TOOL_USE])

        async def execute(self, value):
            result = value.tool_response
            if transfer:
                result = result.for_tool(tool.binding.name, [])
            result.finalize(result, allowed=True)
            return HookOutput.allow()

    peer.host.hooks_manager.register(PrematureCompletion())
    with pytest.raises(MCPAppResultWithheld, match="governed result changed"):
        await peer.executor.invoke(peer.view, "app_mutate", {"text": "host-completion-required"}, operation_id=uuid4().hex)
    assert mcp_http_server.witness == ["host-completion-required"]
    row = await peer.backend.fetch_one("SELECT result_status FROM a2a_tool_dispatches")
    assert row[0] == "success"


@pytest.mark.asyncio
async def test_native_app_result_waits_for_post_policy_then_required_sql(app_boundary, mcp_http_server):
    peer = app_boundary
    await allow(peer, "app_mutate")
    policy_started, release_policy = asyncio.Event(), asyncio.Event()
    policy_results = []
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()

    class CompletePostPolicy(Hook):
        def __init__(self):
            super().__init__("complete-native-app-policy", [HookEvent.POST_TOOL_USE])

        async def execute(self, value):
            policy_results.append(value.tool_response)
            policy_started.set()
            await release_policy.wait()
            return HookOutput.allow()

    peer.host.hooks_manager.register(CompletePostPolicy())
    call = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "policy-first"}, operation_id=uuid4().hex))
    try:
        await asyncio.wait_for(policy_started.wait(), 5)
        assert len(policy_results) == 1 and isinstance(policy_results[0], DeferredToolResult)
        serialized = json.dumps(policy_results[0])
        assert "policy-first" in serialized
        assert "private-result" not in serialized and "private-block" not in serialized
        assert not call.done() and not peer.store.dispatch_started.is_set()
        assert mcp_http_server.witness == ["policy-first"]
        release_policy.set()
        await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
        assert not call.done(), "Policy approval cannot replace required SQL completion"
        peer.store.release_dispatch.set()
        result = await call
        assert result.structured_content == {"text": "policy-first"}
        assert result.meta["private-result"] == {"view": "only"}
        assert mcp_http_server.witness == ["policy-first"]
    finally:
        release_policy.set()
        peer.store.release_dispatch.set()
        if not call.done():
            call.cancel()
        await asyncio.gather(call, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("withdraw", ["owner", "connection", "registration"])
@pytest.mark.parametrize("uncertain", [False, True])
async def test_currency_loss_after_native_effect_is_never_reported_as_nothing_ran(app_boundary, mcp_http_server, withdraw, uncertain):
    peer = app_boundary
    await allow(peer, "app_mutate")
    if uncertain:
        peer.connection._call_timeout = 0.05
        mcp_http_server.settings["app_tool_delay"] = 0.2
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    call = asyncio.create_task(peer.executor.invoke(peer.view, "app_mutate", {"text": "confirmed-effect"}, operation_id=uuid4().hex))
    try:
        await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
        assert mcp_http_server.witness == ["confirmed-effect"]
        if withdraw == "owner":
            peer.owner_current[0] = False
        elif withdraw == "connection":
            await peer.connection.close()
            await peer.connection.connect()
        else:
            peer.host.unregister_dynamic_tools("mcp:original")
        peer.store.release_dispatch.set()
        with pytest.raises(ResourceOutcomeUnknown, match="replay|retry"):
            await call
        assert mcp_http_server.witness == ["confirmed-effect"]
        row = await peer.backend.fetch_one("SELECT result_status FROM a2a_tool_dispatches")
        assert row[0] == ("error" if uncertain else "success")
    finally:
        peer.store.release_dispatch.set()
        if not call.done():
            call.cancel()
        await asyncio.gather(call, return_exceptions=True)


@pytest.mark.asyncio
async def test_actual_core_binding_is_usable_through_only_its_public_sdk_contract(app_boundary, mcp_http_server):
    peer = app_boundary
    await allow(peer, "app_mutate")

    class PublicBinding:
        """Expose the SDK's three members; execution remains actual Core/SQL."""

        def __init__(self, binding):
            self._binding = binding

        @property
        def name(self):
            return self._binding.name

        @property
        def is_current(self):
            return self._binding.is_current

        async def invoke(self, arguments, *, session_id, operation_id, source="external"):
            return await self._binding.invoke(arguments, session_id=session_id, operation_id=operation_id, source=source)

    registered = [RegisteredAppTool(item.tool, PublicBinding(item.binding)) for item in peer.registered]
    source = next(item for item in registered if item.tool is peer.view.source.tool)
    view = peer.executor.open_view(source, registered, session_id="mcp-app:public-sdk-only",
        owner_is_current=lambda: peer.owner_current[0])
    try:
        result = await peer.executor.invoke(view, "app_mutate", {"text": "public-contract"}, operation_id=uuid4().hex)
        assert result.structured_content == {"text": "public-contract"}
        assert mcp_http_server.witness == ["public-contract"]
        row = await peer.backend.fetch_one("SELECT session_id, result_status FROM a2a_tool_dispatches")
        assert tuple(row) == ("mcp-app:public-sdk-only", "success")
    finally:
        await view.close()


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
            AppExecutor(host=peer.host, max_pending_calls=limit)
    for host in [None, object(), SimpleNamespace(supports_deferred_tool_results=False),
                 SimpleNamespace(supports_deferred_tool_results=1)]:
        with pytest.raises(ValueError, match="supports deferred tool results"):
            AppExecutor(host=host, max_pending_calls=2)
    original = dict(source=peer.view.source, registered=peer.registered,
        session_id="mcp-app:configured", owner_is_current=lambda: True)
    async def async_owner():
        return True

    for changes, error, message in [
        ({"session_id": " "}, ValueError, "session_id"),
        ({"registered": []}, ValueError, "retained"),
        ({"registered": [*peer.registered, peer.registered[0]]}, ValueError, "Duplicate"),
        ({"owner_is_current": None}, TypeError, "owner predicate"),
        ({"owner_is_current": async_owner}, TypeError, "synchronous"),
        ({"owner_is_current": lambda: 1}, ResourceConflict, "expired"),
        ({"source": peer.tool("echo")}, ValueError, "associated"),
    ]:
        with pytest.raises(error, match=message):
            peer.executor.open_view(**(original | changes))
    with pytest.raises(TypeError, match="arguments must be an object"):
        await peer.executor.invoke(peer.view, "app_mutate", [], operation_id=uuid4().hex)
    assert not mcp_http_server.witness
    assert peer.approval_requests.empty()
    assert mcp_http_server.settings.get("resource_reads", []) == []


@pytest.mark.asyncio
async def test_reentrant_owner_revocation_refuses_the_original_view(app_boundary, mcp_http_server):
    peer = app_boundary
    holder = []
    def current_owner():
        if holder:
            holder[0].revoke()
        return True

    view = peer.executor.open_view(peer.view.source, peer.registered,
        session_id="mcp-app:reentrant-owner", owner_is_current=current_owner)
    holder.append(view)
    try:
        with pytest.raises(ResourceConflict, match="expired"):
            view.require_current()
        assert view._closed and not mcp_http_server.witness
    finally:
        await view.close()


@pytest.mark.asyncio
async def test_physical_delivery_retains_native_result_until_original_transport_settles(app_boundary, mcp_http_server):
    peer = app_boundary
    await allow(peer, "app_mutate")
    reached, cancelled, settle = asyncio.Event(), asyncio.Event(), asyncio.Event()
    guards = []
    cancellations = []

    async def delivery():
        # The real governed call and SQL finish before transport owns the data.
        result = await peer.executor.invoke(peer.view, "app_mutate", {"text": "private-delivery"}, operation_id=uuid4().hex)
        assert result.meta["private-result"] == {"view": "only"}
        async with peer.view.borrow_delivery() as current:
            guards.append(current)
            current()
            reached.set()
            try:
                await settle.wait()
            except asyncio.CancelledError:
                cancellations.append(True)
                cancelled.set()
                await settle.wait()
            current()

    sender = asyncio.create_task(delivery())
    closer = None
    try:
        await asyncio.wait_for(reached.wait(), 5)
        closer = asyncio.create_task(peer.view.close())
        await asyncio.wait_for(cancelled.wait(), 5)
        peer.view.cancel_delivery(sender)
        peer.view.revoke()
        await asyncio.sleep(0)
        assert not sender.done() and not closer.done() and cancellations == [True]
        rows = await peer.backend.fetch_all("SELECT result_status FROM a2a_tool_dispatches")
        assert [tuple(row) for row in rows] == [("success",)]
        settle.set()
        with pytest.raises(ResourceConflict):
            await sender
        with pytest.raises(BaseExceptionGroup):
            await closer
        with pytest.raises(ResourceConflict, match="ended"):
            guards[0]()
    finally:
        settle.set()
        await asyncio.gather(sender, *([closer] if closer else []), return_exceptions=True)
    assert mcp_http_server.witness == ["private-delivery"]


@pytest.mark.asyncio
async def test_delivery_borrow_refuses_foreign_owner_and_expired_guard(app_boundary):
    view = app_boundary.view
    async with view.borrow_delivery() as current:
        current()
        async def foreign():
            with pytest.raises(ResourceConflict, match="owner"):
                current()
            with pytest.raises(ResourceConflict, match="another View"):
                view.cancel_delivery(asyncio.current_task())
        await asyncio.create_task(foreign())
    with pytest.raises(ResourceConflict, match="ended"):
        current()
    view.require_current()


@pytest.mark.asyncio
async def test_delivery_borrows_share_the_original_view_pending_limit(app_boundary):
    view = app_boundary.view
    assert view.executor.supports_owned_delivery is True and view.is_closed is False
    first, second, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    async def hold(ready):
        async with view.borrow_delivery():
            ready.set()
            await release.wait()
    owners = [asyncio.create_task(hold(first)), asyncio.create_task(hold(second))]
    try:
        await asyncio.wait_for(asyncio.gather(first.wait(), second.wait()), 5)
        with pytest.raises(ResourceConflict, match="cannot admit"):
            async with view.borrow_delivery():
                raise AssertionError("over-budget response entered")
    finally:
        release.set()
        await asyncio.gather(*owners)
    async with view.borrow_delivery() as current:
        current()
    await view.close()
    assert view.is_closed is True


@pytest.mark.asyncio
async def test_view_cannot_join_its_own_physical_delivery(app_boundary):
    view = app_boundary.view
    async with view.borrow_delivery():
        with pytest.raises(ResourceConflict, match="external lifetime owner"):
            await view.close()
        assert not view.is_closed
    await view.close()


@pytest.mark.asyncio
async def test_completed_borrow_cannot_cancel_task_now_delivering_for_another_view(app_boundary):
    peer = app_boundary
    other = peer.executor.open_view(peer.view.source, peer.registered,
        session_id="another-physical-view", owner_is_current=lambda: True)
    entered, release = asyncio.Event(), asyncio.Event()
    async def sender():
        async with peer.view.borrow_delivery():
            pass
        async with other.borrow_delivery():
            entered.set()
            await release.wait()
    child = asyncio.create_task(sender())
    try:
        await asyncio.wait_for(entered.wait(), 5)
        with pytest.raises(ResourceConflict, match="another View"):
            peer.view.cancel_delivery(child)
        assert not child.cancelling()
    finally:
        release.set()
        await asyncio.gather(child, return_exceptions=True)
        await other.close()


@pytest.mark.asyncio
async def test_a_fresh_borrow_has_its_own_single_cancellation(app_boundary):
    view = app_boundary.view
    entered = [asyncio.Event(), asyncio.Event()]
    cancelled = []
    async def sender():
        for index in range(2):
            async with view.borrow_delivery():
                entered[index].set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    cancelled.append(index)
                    asyncio.current_task().uncancel()
    child = asyncio.create_task(sender())
    try:
        await asyncio.wait_for(entered[0].wait(), 5)
        view.cancel_delivery(child)
        await asyncio.wait_for(entered[1].wait(), 5)
        view.cancel_delivery(child)
        await asyncio.wait_for(asyncio.shield(child), 1)
        assert cancelled == [0, 1]
    finally:
        if not child.done():
            child.cancel()
        await asyncio.gather(child, return_exceptions=True)


@pytest.mark.asyncio
async def test_close_joins_only_the_original_borrow_not_later_host_work(app_boundary):
    view = app_boundary.view
    entered, left, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    async def sender():
        async with view.borrow_delivery():
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                asyncio.current_task().uncancel()
        left.set()
        await release.wait()
        raise ValueError("unrelated later host work")
    child = asyncio.create_task(sender())
    closer = None
    try:
        await asyncio.wait_for(entered.wait(), 5)
        closer = asyncio.create_task(view.close())
        await asyncio.wait_for(left.wait(), 5)
        await asyncio.wait_for(asyncio.shield(closer), 1)
        assert not child.done()
    finally:
        release.set()
        await asyncio.gather(child, *([closer] if closer else []), return_exceptions=True)


@pytest.mark.parametrize('kind', ['tool', 'resource'])
@pytest.mark.parametrize('expire_after', [1, 2])
async def test_live_view_authority_is_checked_after_each_native_intermediate(
    app_boundary, mcp_http_server, kind, expire_after,
):
    b = app_boundary
    await allow(b, 'app_mutate')
    rounds = []
    method = 'tools/call' if kind == 'tool' else 'resources/read'

    async def defer(ctx, call_next):
        if ctx.method != method:
            return await call_next(ctx)
        rounds.append(ctx.params.get('requestState'))
        if len(rounds) == expire_after:
            # The original live View predicate models reader authorization;
            # leave its physical owner open to exclude maintenance cancellation.
            b.owner_current[0] = False
        return types.InputRequiredResult(request_state='private-view-continuation')

    mcp_http_server.mcp.middleware.append(defer)
    with pytest.raises(ResourceOutcomeUnknown):
        if kind == 'tool':
            await b.executor.invoke(b.view, 'app_mutate', {'text': 'same-approved-call'}, operation_id=uuid4().hex)
        else:
            await b.view.read_resource('ui://status/view.html', max_html_bytes=4096)
    assert len(rounds) == expire_after
    calls = [json.loads(body) for _, body in mcp_http_server.requests if body
        and json.loads(body).get('method') == method]
    assert len(calls) == expire_after
    assert not mcp_http_server.witness
    rows = await b.backend.fetch_all('SELECT result_status FROM a2a_tool_dispatches')
    assert len(rows) == (1 if kind == 'tool' else 0)
    if rows:
        assert rows[0][0] == 'error'


@pytest.mark.asyncio
async def test_original_app_intent_cannot_be_replayed_after_a_confirmed_native_effect(app_boundary, mcp_http_server):
    peer = app_boundary
    await allow(peer, 'app_mutate')
    operation_id = uuid4().hex
    result = await peer.executor.invoke(peer.view, 'app_mutate', {'text': 'original-confirmed-effect'},
        operation_id=operation_id)
    assert not result.is_error
    with pytest.raises(ToolEffectReconciliationRequired):
        await peer.executor.invoke(peer.view, 'app_mutate', {'text': 'original-confirmed-effect'},
            operation_id=operation_id)
    assert mcp_http_server.witness == ['original-confirmed-effect']
    requests = [json.loads(body) for _, body in mcp_http_server.requests if body]
    assert sum(message.get('method') == 'tools/call' for message in requests) == 1


@pytest.mark.asyncio
async def test_known_native_app_argument_rejection_retains_a_definite_error(app_boundary, mcp_http_server):
    peer = app_boundary
    await allow(peer, 'app_mutate')
    mcp_http_server.settings['reject_call'] = True
    with pytest.raises(ResourceConflict, match='rejected before tool execution'):
        await peer.executor.invoke(peer.view, 'app_mutate', {'text': 'must-not-execute'},
            operation_id=uuid4().hex)
    assert mcp_http_server.witness == []
    assert await peer.host.tool_effect_store.database.fetchone(
        'SELECT state FROM tool_effect_claims') == ('RETURNED_ERROR',)
    assert await peer.host.tool_effect_store.database.fetchone(
        'SELECT state FROM tool_effect_operations') == ('CLOSED',)
