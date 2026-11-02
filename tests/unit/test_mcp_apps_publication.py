"""Private associations with real MCP, Core permissions and required SQLite audit.

CallerContext scopes below exercise the host callback contract. They are not
HTTP authentication tests; no route advertises this in-process component yet.
"""

import asyncio
import inspect
import json

import pytest
import pytest_asyncio

from kestrel_sdk.resources import ResourceConflict, ResourceOutcomeUnknown
from kestrel_sovereign.agent.parts import part_collector
from kestrel_sovereign.auth import AuthMethod, CallerContext, caller_context_scope, current_caller_context
from kestrel_sovereign.execution_custody import ExecutionAuthorityError, is_execution_control_error
from kestrel_sovereign.features.security.permissions import PermissionLevel

from kestrel_feature_mcp.apps_publication import AppPublications
from kestrel_feature_mcp.apps_execution import RegisteredAppTool
from kestrel_feature_mcp.dynamic_tools import MCPToolWrapper
from tests.unit.test_mcp_apps_execution import app_boundary as app_boundary, allow


pytestmark = pytest.mark.parametrize("mcp_http_server", [
    {"apps_tools": True, "apps_execution_tools": True,
     "app_mutate_visibility": ["model", "app"]},
], indirect=True)


@pytest.fixture
def initial_publisher():
    return None


@pytest.fixture
def publication_state():
    return {"clock": [10.0], "chat": [None, "original-chat"]}


@pytest.fixture
def app_executor_factory(publication_state):
    def create(*, host, max_pending_calls, initial_publisher):
        assert initial_publisher is None
        state = publication_state
        state["chat"][0] = host.did

        def original_owner(context):
            caller = current_caller_context()
            if caller is None or caller.auth_method not in {AuthMethod.API_KEY, AuthMethod.JWT, AuthMethod.OAUTH_SESSION}:
                return None
            return caller

        def require_reader(owner, context):
            caller = original_owner(context)
            if (caller is None or caller != owner
                    or state["chat"] != [context.agent_id, context.session_id]):
                raise ResourceConflict("The original authenticated chat reader is required")

        registry = AppPublications(host=host, max_pending_calls=max_pending_calls, agent_id=host.did,
            publication_owner=original_owner, require_reader=require_reader,
            max_publications=4, max_views=4, max_payload_bytes=8192,
            max_publications_per_owner=2, max_views_per_owner=2,
            retention_seconds=30, clock=lambda: state["clock"][0])
        state["registry"] = registry
        return registry.executor
    return create


@pytest_asyncio.fixture
async def publications(app_boundary, publication_state):
    peer = app_boundary
    registry = publication_state["registry"]
    registry.register("mcp:original", peer.registered, is_current=lambda: peer.owner_current[0])
    try:
        yield registry, publication_state["clock"], publication_state["chat"]
    finally:
        await registry.close()


ALICE = CallerContext.authenticated("alice")
BOB = CallerContext.authenticated("bob")


async def execute_initial(peer, *, text="once", chat="original-chat", caller=ALICE):
    tool = await allow(peer, "app_mutate")
    with caller_context_scope(caller), part_collector(host=peer.host, session_id=chat):
        result = await tool.binding.invoke({"text": text}, session_id=chat, source="chat")
    return result


async def publish(peer, registry, *, text="once", chat="original-chat", caller=ALICE):
    result = await execute_initial(peer, text=text, chat=chat, caller=caller)
    parts = [part for part in result["parts"] if part["type"] == "mcp_app"]
    assert len(parts) == 1
    part = parts[0]
    assert set(part["data"]) == {"reference", "session_id"}
    assert part["data"]["session_id"] == chat
    return part["data"]["reference"], result


def replace_core_registration(peer, *, reuse_wrappers=False):
    wrappers = [item.tool if reuse_wrappers else MCPToolWrapper(handle_name=item.binding.name,
        tool=item.tool.native_tool, caller=item.tool.bound_caller, app_executor=peer.executor)
        for item in peer.registered]
    peer.host.unregister_dynamic_tools("mcp:original")
    registered = []
    peer.host.register_dynamic_tools("mcp:original", wrappers,
        on_registered=lambda tool, binding: registered.append(RegisteredAppTool(tool, binding)))
    return registered


@pytest.mark.asyncio
async def test_private_result_reopens_without_replaying_native_effect(app_boundary, publications, mcp_http_server):
    registry, _, _ = publications
    reference, public = await publish(app_boundary, registry)
    assert '"private-result":' not in json.dumps(public)
    assert '"view-only"' not in json.dumps(public)
    with caller_context_scope(ALICE):
        first = registry.open_view(reference)
        arguments, result = registry.initial_result(reference, first)
        assert arguments == {"text": "once"}
        assert result.meta["private-result"] == {"view": "only"}
        arguments["text"] = "changed"
        result.meta["private-result"]["view"] = "changed"
        await registry.close_view(first)
        second = registry.open_view(reference)
        arguments, result = registry.initial_result(reference, second)
        assert arguments == {"text": "once"} and result.meta["private-result"] == {"view": "only"}
    assert mcp_http_server.witness == ["once"]
    rows = await app_boundary.backend.fetch_all("SELECT session_id,result_status FROM a2a_tool_dispatches")
    assert [tuple(row) for row in rows] == [("original-chat", "success")]


@pytest.mark.asyncio
@pytest.mark.parametrize("caller", [None, BOB])
async def test_chat_locator_cannot_authenticate_reader(app_boundary, publications, caller):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with caller_context_scope(caller), pytest.raises(ResourceConflict, match="result is unavailable"):
        registry.open_view(reference)


@pytest.mark.asyncio
async def test_unauthorized_locator_holder_cannot_probe_a_faulty_source_predicate(app_boundary, publications):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    checks = []
    def faulty_source():
        checks.append(True)
        raise ValueError("private-source-diagnostic")

    registry._batches["mcp:original"].is_current = faulty_source
    with caller_context_scope(BOB), pytest.raises(ResourceConflict, match="result is unavailable"):
        registry.open_view(reference)
    assert not checks
    with caller_context_scope(ALICE), pytest.raises(ValueError, match="private-source-diagnostic"):
        registry.open_view(reference)
    assert checks == [True]


@pytest.mark.asyncio
@pytest.mark.parametrize("wrong_field", [0, 1])
async def test_same_principal_still_requires_original_agent_and_chat(app_boundary, publications, wrong_field):
    registry, _, chat = publications
    reference, _ = await publish(app_boundary, registry)
    chat[wrong_field] = "another-owner"
    with caller_context_scope(ALICE), pytest.raises(ResourceConflict, match="result is unavailable"):
        registry.open_view(reference)


@pytest.mark.asyncio
async def test_live_view_rechecks_independent_reader_at_every_operation(app_boundary, publications):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
    with caller_context_scope(BOB), pytest.raises(ResourceConflict, match="result is unavailable"):
        registry.initial_result(reference, view)
    with caller_context_scope(None), pytest.raises(ResourceConflict, match="result is unavailable"):
        view.list_tools()


@pytest.mark.asyncio
async def test_physical_view_cannot_read_another_initial_result(app_boundary, publications):
    registry, _, _ = publications
    first, _ = await publish(app_boundary, registry, text="first")
    second, _ = await publish(app_boundary, registry, text="second")
    with caller_context_scope(ALICE):
        view = registry.open_view(first)
        with pytest.raises(ResourceConflict, match="does not own"):
            registry.initial_result(second, view)


@pytest.mark.asyncio
async def test_retention_boundary_revokes_views_without_result_replay(app_boundary, publications, mcp_http_server):
    registry, clock, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        clock[0] = 40.0
        with pytest.raises(ResourceConflict, match="unavailable"):
            registry.initial_result(reference, view)
        with pytest.raises(ResourceConflict):
            view.list_tools()
    await registry.drain_retired()
    assert not registry._views and mcp_http_server.witness == ["once"]


@pytest.mark.asyncio
@pytest.mark.parametrize("withdraw", ["retention", "owner", "registration", "connection"])
async def test_idle_drain_reclaims_expired_and_stale_associations(app_boundary, publications, withdraw):
    registry, clock, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
    if withdraw == "retention":
        clock[0] = 40.0
    elif withdraw == "owner":
        app_boundary.owner_current[0] = False
    elif withdraw == "registration":
        app_boundary.host.unregister_dynamic_tools("mcp:original")
    else:
        await app_boundary.connection.close()
    # No subsequent resource/result read is needed to withdraw the View.
    await registry.drain_retired()
    assert view._closed and not registry._publications and not registry._views


@pytest.mark.asyncio
async def test_idle_retention_drain_recovers_both_publication_and_view_capacity(app_boundary, publications, mcp_http_server):
    registry, clock, _ = publications
    first, _ = await publish(app_boundary, registry, text="one")
    await publish(app_boundary, registry, text="two")
    with caller_context_scope(ALICE):
        registry.open_view(first)
        registry.open_view(first)
    clock[0] = 40.0
    await registry.drain_retired()
    assert not registry._views and not registry._publications
    reference, _ = await publish(app_boundary, registry, text="after-retention")
    with caller_context_scope(ALICE):
        registry.open_view(reference)
    assert mcp_http_server.witness == ["one", "two", "after-retention"]


@pytest.mark.asyncio
async def test_owner_replacement_revokes_old_results_and_physical_views(app_boundary, publications):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        replacement = replace_core_registration(app_boundary)
        registry.register("mcp:original", replacement, is_current=lambda: True)
        with pytest.raises(ResourceConflict, match="unavailable"):
            registry.initial_result(reference, view)
        with pytest.raises(ResourceConflict):
            view.list_tools()
    await registry.drain_retired()
    assert not registry._views


@pytest.mark.asyncio
async def test_invalid_replacement_preserves_original_usable_association(app_boundary, publications):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with pytest.raises(ValueError, match="Duplicate"):
        registry.register("mcp:original", app_boundary.registered * 2, is_current=lambda: True)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        assert registry.initial_result(reference, view)[0] == {"text": "once"}


@pytest.mark.asyncio
async def test_staged_result_cannot_be_retargeted_by_rebinding_the_same_wrapper(app_boundary, publications, mcp_http_server):
    peer = app_boundary
    registry, _, _ = publications
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    call = asyncio.create_task(execute_initial(peer, text="old-registration"))
    try:
        await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
        replacement = replace_core_registration(peer, reuse_wrappers=True)
        with pytest.raises(ValueError, match="already belonged"):
            registry.register("mcp:original", replacement, is_current=lambda: True)
        peer.store.release_dispatch.set()
        result = await call
        assert [part["type"] for part in result["parts"]] == ["notice"]
        assert not registry._publications
    finally:
        peer.store.release_dispatch.set()
        if not call.done():
            call.cancel()
        await asyncio.gather(call, return_exceptions=True)
    assert mcp_http_server.witness == ["old-registration"]


@pytest.mark.asyncio
@pytest.mark.parametrize("replacement", ["empty", "no-ui"])
async def test_replacement_without_ui_retires_old_private_associations(app_boundary, publications, replacement):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    tools = [] if replacement == "empty" else [app_boundary.tool("echo")]
    registry.register("mcp:original", tools, is_current=lambda: True)
    with caller_context_scope(ALICE), pytest.raises(ResourceConflict, match="unavailable"):
        registry.open_view(reference)


@pytest.mark.asyncio
async def test_callback_revocation_cannot_leave_physical_view_admitted(app_boundary, publications):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        original = registry._require_reader

        def retire_during_authorization(owner, context):
            original(owner, context)
            registry.retire("mcp:original")

        registry._require_reader = retire_during_authorization
        with pytest.raises(ResourceConflict):
            view.require_current()


@pytest.mark.asyncio
async def test_reader_callback_must_explicitly_return_none_or_raise(app_boundary, publications):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    registry._require_reader = lambda owner, context: True
    with caller_context_scope(ALICE), pytest.raises(TypeError, match="return None or raise"):
        registry.open_view(reference)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [0, -1, True, 0.5])
@pytest.mark.parametrize("field", ["max_publications", "max_views", "max_payload_bytes", "max_publications_per_owner", "max_views_per_owner"])
async def test_invalid_publication_limits_fail_before_retaining_native_data(app_boundary, field, value):
    kwargs = dict(host=app_boundary.host, max_pending_calls=2, agent_id=app_boundary.host.did,
        publication_owner=lambda context: None, require_reader=lambda owner, context: None,
        max_publications=4, max_views=4, max_payload_bytes=8192,
            max_publications_per_owner=2, max_views_per_owner=2, retention_seconds=30)
    kwargs[field] = value
    with pytest.raises(ValueError, match="positive integers"):
        AppPublications(**kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [0, -1, True, float("nan"), float("inf")])
async def test_invalid_retention_fails_before_retaining_native_data(app_boundary, value):
    with pytest.raises(ValueError, match="positive and finite"):
        AppPublications(host=app_boundary.host, max_pending_calls=2, agent_id=app_boundary.host.did,
            publication_owner=lambda context: None, require_reader=lambda owner, context: None,
            max_publications=4, max_views=4, max_payload_bytes=8192,
            max_publications_per_owner=2, max_views_per_owner=2, retention_seconds=value)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["publication_owner", "require_reader"])
async def test_async_authorization_callbacks_cannot_escape_as_principal_snapshots(app_boundary, field):
    async def invalid(*args):
        return None

    kwargs = dict(host=app_boundary.host, max_pending_calls=2, agent_id=app_boundary.host.did,
        publication_owner=lambda context: None, require_reader=lambda owner, context: None,
        max_publications=4, max_views=4, max_payload_bytes=8192,
            max_publications_per_owner=2, max_views_per_owner=2, retention_seconds=30)
    kwargs[field] = invalid
    with pytest.raises(TypeError, match="synchronous function or method"):
        AppPublications(**kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize(("changes", "error"), [
    ({"host": None}, ValueError), ({"agent_id": None}, ValueError),
    ({"agent_id": " "}, ValueError), ({"clock": None}, TypeError),
    ({"publication_owner": None}, TypeError), ({"require_reader": None}, TypeError),
])
async def test_invalid_publication_owner_configuration_fails_at_construction(app_boundary, changes, error):
    kwargs = dict(host=app_boundary.host, max_pending_calls=2, agent_id=app_boundary.host.did,
        publication_owner=lambda context: None, require_reader=lambda owner, context: None,
        max_publications=4, max_views=4, max_payload_bytes=8192,
            max_publications_per_owner=2, max_views_per_owner=2, retention_seconds=30)
    with pytest.raises(error):
        AppPublications(**(kwargs | changes))


@pytest.mark.asyncio
async def test_invalid_registration_callbacks_cannot_admit_or_replace_a_batch(app_boundary, publications):
    registry, _, _ = publications
    async def async_current():
        return True

    original = dict(owner="mcp:original", tools=app_boundary.registered, is_current=lambda: True)
    for changes, error, match in [
        ({"owner": ""}, ValueError, "registration owner"),
        ({"tools": None}, ValueError, "registration owner"),
        ({"is_current": None}, ValueError, "registration owner"),
        ({"is_current": async_current}, TypeError, "synchronous"),
        ({"is_current": lambda: 1}, ResourceConflict, "registration is unavailable"),
    ]:
        with pytest.raises(error, match=match):
            registry.register(**(original | changes))
    await registry.close()
    with pytest.raises(ResourceConflict, match="closed"):
        registry.register(**original)


@pytest.mark.asyncio
async def test_foreign_physical_view_cannot_be_closed_through_a_different_publisher(app_boundary, publications):
    registry, _, _ = publications
    with pytest.raises(ResourceConflict, match="another publisher"):
        await registry.close_view(app_boundary.view)
    assert not app_boundary.view._closed


@pytest.mark.asyncio
async def test_retirement_joins_real_pending_core_approval_before_connection_cleanup(app_boundary, publications, mcp_http_server):
    peer = app_boundary
    registry, _, _ = publications
    reference, _ = await publish(peer, registry)
    await allow(peer, "app_mutate", PermissionLevel.ASK)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        call = asyncio.create_task(registry.executor.invoke(view, "app_mutate", {"text": "not-approved"}))
        try:
            await asyncio.wait_for(peer.approval_requests.get(), 5)
            registry.retire("mcp:original")
            assert view._closed, "Withdrawal must revoke before asynchronous cleanup"
            await registry.drain_retired()
            with pytest.raises(ResourceConflict):
                await call
        finally:
            if not call.done():
                call.cancel()
            await asyncio.gather(call, return_exceptions=True)
    assert not registry._views and mcp_http_server.witness == ["once"]
    rows = await peer.backend.fetch_all("SELECT session_id FROM a2a_tool_dispatches")
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_physical_close_and_feature_shutdown_join_the_same_required_audit(app_boundary, publications, mcp_http_server):
    peer = app_boundary
    registry, _, _ = publications
    reference, _ = await publish(peer, registry)
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    closers = []
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        call = asyncio.create_task(registry.executor.invoke(view, "app_mutate", {"text": "shutdown-once"}))
        try:
            await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
            closers = [asyncio.create_task(registry.close_view(view)), asyncio.create_task(registry.close())]
            await asyncio.sleep(0)
            assert view._closed and all(not closer.done() for closer in closers)
            peer.store.release_dispatch.set()
            results = await asyncio.gather(*closers, return_exceptions=True)
            assert results == [None, None]
            with pytest.raises(ResourceOutcomeUnknown):
                await call
        finally:
            peer.store.release_dispatch.set()
            if not call.done():
                call.cancel()
            await asyncio.gather(call, *closers, return_exceptions=True)
    assert not registry._views and mcp_http_server.witness == ["once", "shutdown-once"]
    rows = await peer.backend.fetch_all("SELECT session_id FROM a2a_tool_dispatches")
    assert [tuple(row) for row in rows] == [("original-chat",), ("original-chat",)]


@pytest.mark.asyncio
async def test_second_close_of_the_same_original_view_is_idempotent(app_boundary, publications):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
    await registry.close_view(view)
    await registry.close_view(view)
    assert view._closed and view not in registry._views


@pytest.mark.asyncio
async def test_source_retirement_drains_a_real_inflight_native_http_call(app_boundary, publications, mcp_http_server):
    peer = app_boundary
    registry, _, _ = publications
    reference, _ = await publish(peer, registry)
    mcp_http_server.settings["app_tool_delay"] = 0.2
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        call = asyncio.create_task(peer.executor.invoke(view, "app_mutate", {"text": "native-inflight"}))
        try:
            async with asyncio.timeout(5):
                while "native-inflight" not in mcp_http_server.witness:
                    await asyncio.sleep(0.01)
            peer.owner_current[0] = False
            await registry.drain_retired()
            with pytest.raises(ResourceOutcomeUnknown, match="replay|retry"):
                await call
        finally:
            if not call.done():
                call.cancel()
            await asyncio.gather(call, return_exceptions=True)
    assert not registry._views and mcp_http_server.witness == ["once", "native-inflight"]
    rows = await peer.backend.fetch_all("SELECT session_id FROM a2a_tool_dispatches")
    assert len(rows) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [PermissionError, TypeError, RuntimeError, ExecutionAuthorityError])
async def test_reader_failure_after_native_effect_preserves_no_replay_outcome(app_boundary, publications, mcp_http_server, error_type):
    peer = app_boundary
    registry, _, _ = publications
    reference, _ = await publish(peer, registry)
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    error = error_type("private-reader-diagnostic")
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        call = asyncio.create_task(registry.executor.invoke(view, "app_mutate", {"text": "reader-withdrawn"}))
        try:
            await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
            def refuse(owner, context):
                raise error

            registry._require_reader = refuse
            peer.store.release_dispatch.set()
            with pytest.raises(ResourceOutcomeUnknown, match="replay|retry") as caught:
                await call
            causes = []
            current = caught.value
            while current is not None and current not in causes:
                causes.append(current)
                current = current.__cause__
            assert error in causes
            assert is_execution_control_error(caught.value) is (error_type is ExecutionAuthorityError)
        finally:
            peer.store.release_dispatch.set()
            if not call.done():
                call.cancel()
            await asyncio.gather(call, return_exceptions=True)
    assert mcp_http_server.witness == ["once", "reader-withdrawn"]
    rows = await peer.backend.fetch_all("SELECT result_status FROM a2a_tool_dispatches")
    assert [tuple(row) for row in rows] == [("success",), ("success",)]


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit])
async def test_reader_process_control_is_preserved_as_the_original_exception(app_boundary, publications, error_type):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    error = error_type("original-process-control")
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        def stop(owner, context):
            raise error

        registry._require_reader = stop
        with pytest.raises(error_type) as caught:
            view.require_current()
    assert caught.value is error


@pytest.mark.asyncio
async def test_original_connection_loss_withholds_both_initial_result_and_resource(app_boundary, publications):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        await app_boundary.connection.close()
        with pytest.raises(ResourceConflict):
            registry.initial_result(reference, view)
        with pytest.raises(ResourceConflict):
            await view.read_resource(view.source.tool.resource_uri, max_html_bytes=8192)


@pytest.mark.asyncio
async def test_capacity_refuses_new_private_output_after_confirmed_effect(app_boundary, publications, mcp_http_server):
    registry, _, _ = publications
    first, _ = await publish(app_boundary, registry, text="one")
    await publish(app_boundary, registry, text="two")
    withheld = await execute_initial(app_boundary, text="three")
    assert withheld["status"] == "ok"
    assert [part["type"] for part in withheld["parts"]] == ["notice"]
    assert "Do not run it again" in withheld["parts"][0]["data"]["body"]
    assert len(registry._publications) == 2
    with caller_context_scope(ALICE):
        view = registry.open_view(first)
        assert registry.initial_result(first, view)[0] == {"text": "one"}
    assert mcp_http_server.witness == ["one", "two", "three"]


@pytest.mark.asyncio
async def test_physical_view_limit_recovers_only_after_owned_close(app_boundary, publications):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with caller_context_scope(ALICE):
        first = registry.open_view(reference)
        registry.open_view(reference)
        with pytest.raises(ResourceConflict, match="View limit reached"):
            registry.open_view(reference)
        first.revoke()
        with pytest.raises(ResourceConflict, match="View limit reached"):
            registry.open_view(reference)
        await registry.close_view(first)
        registry.open_view(reference)


@pytest.mark.asyncio
async def test_busy_chat_cannot_exhaust_another_chats_result_and_view_budget(app_boundary, publications, mcp_http_server):
    registry, _, reader_chat = publications
    first, _ = await publish(app_boundary, registry, text="one")
    await publish(app_boundary, registry, text="two")
    with caller_context_scope(ALICE):
        registry.open_view(first)
        registry.open_view(first)
    withheld = await execute_initial(app_boundary, text="chat-limit")
    assert [part["type"] for part in withheld["parts"]] == ["notice"]
    second, _ = await publish(app_boundary, registry, text="other-chat", chat="another-chat", caller=BOB)
    reader_chat[1] = "another-chat"
    with caller_context_scope(BOB):
        view = registry.open_view(second)
        assert registry.initial_result(second, view)[0] == {"text": "other-chat"}
    assert len(registry._views) == 3 and mcp_http_server.witness == ["one", "two", "chat-limit", "other-chat"]


@pytest.mark.asyncio
async def test_global_result_budget_still_bounds_all_chats(app_boundary, publications, mcp_http_server):
    registry, _, _ = publications
    for chat, caller in [("original-chat", ALICE), ("another-chat", BOB)]:
        for index in range(2):
            await publish(app_boundary, registry, text=f"{chat}-{index}", chat=chat, caller=caller)
    withheld = await execute_initial(app_boundary, text="global-limit", chat="third-chat",
        caller=CallerContext.authenticated("charlie"))
    assert [part["type"] for part in withheld["parts"]] == ["notice"]
    assert len(registry._publications) == 4 and len(mcp_http_server.witness) == 5


@pytest.mark.asyncio
async def test_owner_result_budget_cannot_be_evaded_by_changing_chats(app_boundary, publications, mcp_http_server):
    registry, _, _ = publications
    await publish(app_boundary, registry, text="one")
    await publish(app_boundary, registry, text="two")
    withheld = await execute_initial(app_boundary, text="same-owner-another-chat", chat="another-chat")
    assert [part["type"] for part in withheld["parts"]] == ["notice"]
    assert len(registry._publications) == 2 and mcp_http_server.witness == ["one", "two", "same-owner-another-chat"]


@pytest.mark.asyncio
async def test_global_view_budget_bounds_distinct_authenticated_principals(app_boundary, publications):
    registry, _, reader_chat = publications
    for caller, chat in [(ALICE, "alice-chat"), (BOB, "bob-chat")]:
        reference, _ = await publish(app_boundary, registry, caller=caller, chat=chat)
        reader_chat[1] = chat
        with caller_context_scope(caller):
            registry.open_view(reference)
            registry.open_view(reference)
    charlie = CallerContext.authenticated("charlie")
    reference, _ = await publish(app_boundary, registry, caller=charlie, chat="charlie-chat")
    reader_chat[1] = "charlie-chat"
    with caller_context_scope(charlie), pytest.raises(ResourceConflict, match="View limit reached"):
        registry.open_view(reference)
    assert len(registry._views) == 4


@pytest.mark.asyncio
async def test_missing_expired_and_refused_locators_have_one_non_disclosing_error(app_boundary, publications):
    registry, clock, _ = publications
    reference, _ = await publish(app_boundary, registry)
    messages = []
    for locator, caller in [("not-a-result", ALICE), (reference, BOB)]:
        with caller_context_scope(caller), pytest.raises(ResourceConflict) as caught:
            registry.open_view(locator)
        messages.append(str(caught.value))
    clock[0] = 40.0
    with caller_context_scope(ALICE), pytest.raises(ResourceConflict) as caught:
        registry.open_view(reference)
    messages.append(str(caught.value))
    assert len(set(messages)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["coroutine", "generator", "async-generator"])
async def test_returned_deferred_owner_work_is_rejected_without_retaining_private_data(app_boundary, publications, mcp_http_server, kind):
    registry, _, _ = publications
    async def coroutine():
        return ALICE

    def generator():
        yield ALICE

    async def async_generator():
        yield ALICE

    values = []
    def owner(context):
        value = {"coroutine": coroutine, "generator": generator, "async-generator": async_generator}[kind]()
        values.append(value)
        return value

    registry._publication_owner = owner
    try:
        result = await execute_initial(app_boundary)
        assert [part["type"] for part in result["parts"]] == ["notice"]
        assert not registry._publications and mcp_http_server.witness == ["once"]
        if kind == "coroutine":
            assert values[0].cr_frame is None
        elif kind == "generator":
            assert values[0].gi_frame is None
    finally:
        for value in values:
            if inspect.isasyncgen(value):
                await value.aclose()
            else:
                value.close()


@pytest.mark.asyncio
async def test_unbound_initial_caller_is_refused_before_real_native_io(app_boundary, publications, mcp_http_server):
    peer = app_boundary
    with pytest.raises(ValueError, match="original bound native caller"):
        MCPToolWrapper(handle_name="bad_initial_binding", tool=peer.tool("app_mutate").tool.native_tool,
            caller=peer.connection.call_tool, app_executor=peer.executor)
    assert not mcp_http_server.witness
    rows = await peer.backend.fetch_all("SELECT result_status FROM a2a_tool_dispatches")
    assert not rows


@pytest.mark.asyncio
async def test_non_view_initial_tool_stale_after_construction_is_definite_failure(app_boundary, publications, mcp_http_server):
    peer = app_boundary
    tool = await allow(peer, "app_mutate")
    await peer.connection.close()
    with caller_context_scope(ALICE), part_collector(host=peer.host, session_id="original-chat"):
        result = await tool.binding.invoke({"text": "never-sent"}, session_id="original-chat", source="chat")
    assert result["status"] == "error" and "rediscover" in result["error"]
    assert not mcp_http_server.witness
    rows = await peer.backend.fetch_all("SELECT result_status FROM a2a_tool_dispatches")
    assert [tuple(row) for row in rows] == [("error",)]


@pytest.mark.asyncio
async def test_refused_reader_does_not_cancel_the_original_owners_pending_call(app_boundary, publications, mcp_http_server):
    peer = app_boundary
    registry, _, _ = publications
    reference, _ = await publish(peer, registry)
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        call = asyncio.create_task(peer.executor.invoke(view, "app_mutate", {"text": "authorized-owner"}))
        try:
            await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
            with caller_context_scope(BOB), pytest.raises(ResourceConflict):
                view.list_tools()
            assert not view._closed and not call.done()
            assert registry.initial_result(reference, view)[0] == {"text": "once"}
            peer.store.release_dispatch.set()
            assert (await call).structured_content == {"text": "authorized-owner"}
        finally:
            peer.store.release_dispatch.set()
            if not call.done():
                call.cancel()
            await asyncio.gather(call, return_exceptions=True)
    assert mcp_http_server.witness == ["once", "authorized-owner"]


@pytest.mark.asyncio
@pytest.mark.parametrize("fault_kind", ["raises", "awaitable", "control-and-join-cancellation"])
async def test_faulty_source_is_isolated_and_drain_joins_its_required_audit(app_boundary, publications, mcp_http_server, fault_kind):
    peer = app_boundary
    registry, _, reader_chat = publications
    good_ref, _ = await publish(peer, registry, text="good-source")
    with caller_context_scope(ALICE):
        good_view = registry.open_view(good_ref)
    fault = [False]
    control = ExecutionAuthorityError("original-source-control")
    async def deferred_current():
        return True

    def source_current():
        if fault[0]:
            if fault_kind == "raises":
                raise ValueError("original-source-predicate-fault")
            if fault_kind == "control-and-join-cancellation":
                raise control
            return deferred_current()
        return True

    wrappers = [MCPToolWrapper(handle_name="isolated__" + item.tool.native_tool.name,
        tool=item.tool.native_tool, caller=item.tool.bound_caller, app_executor=peer.executor)
        for item in peer.registered]
    isolated = []
    peer.host.register_dynamic_tools("mcp:isolated", wrappers,
        on_registered=lambda tool, binding: isolated.append(RegisteredAppTool(tool, binding)))
    registry.register("mcp:isolated", isolated, is_current=source_current)
    tool = next(item for item in isolated if item.tool.native_tool.name == "app_mutate")
    await peer.permissions.set_permission("mcp:isolated", tool.binding.name, PermissionLevel.ALLOW)
    with caller_context_scope(BOB), part_collector(host=peer.host, session_id="isolated-chat"):
        result = await tool.binding.invoke({"text": "isolated-source"}, session_id="isolated-chat", source="chat")
    reference = next(part for part in result["parts"] if part["type"] == "mcp_app")["data"]["reference"]
    reader_chat[1] = "isolated-chat"
    fault[0] = True
    await publish(peer, registry, text="good-before-drain")
    fault[0] = False
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    draining = None
    with caller_context_scope(BOB):
        bad_view = registry.open_view(reference)
        call = asyncio.create_task(peer.executor.invoke(bad_view, "app_mutate", {"text": "effect-before-source-fault"}))
        try:
            await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
            fault[0] = True
            reader_chat[1] = "original-chat"
            with caller_context_scope(ALICE):
                assert registry.initial_result(good_ref, good_view)[0] == {"text": "good-source"}
            draining = asyncio.create_task(registry.drain_retired())
            await asyncio.sleep(0)
            assert bad_view._closed and not good_view._closed and not draining.done()
            if fault_kind == "control-and-join-cancellation":
                draining.cancel()
            peer.store.release_dispatch.set()
            if fault_kind == "control-and-join-cancellation":
                with pytest.raises(BaseExceptionGroup) as caught:
                    await draining
                assert is_execution_control_error(caught.value)
                def explicit_errors(error):
                    yield error
                    if isinstance(error, BaseExceptionGroup):
                        for child in error.exceptions:
                            yield from explicit_errors(child)
                    if error.__cause__ is not None:
                        yield from explicit_errors(error.__cause__)
                assert any(error is control for error in explicit_errors(caught.value))
                assert any(isinstance(error, asyncio.CancelledError) for error in explicit_errors(caught.value))
                # A failed join retains custody; a subsequent close releases
                # only the already-settled View, without replaying its effect.
                await registry.close_view(bad_view)
            else:
                with pytest.raises(ValueError if fault_kind == "raises" else TypeError):
                    await draining
            with pytest.raises(ResourceOutcomeUnknown):
                await call
        finally:
            peer.store.release_dispatch.set()
            if not call.done():
                call.cancel()
            await asyncio.gather(call, *([draining] if draining is not None else []), return_exceptions=True)
    with caller_context_scope(ALICE):
        assert registry.initial_result(good_ref, good_view)[0] == {"text": "good-source"}
    assert bad_view not in registry._views and good_view in registry._views
    assert mcp_http_server.witness == ["good-source", "isolated-source", "good-before-drain", "effect-before-source-fault"]
    rows = await peer.backend.fetch_all("SELECT session_id FROM a2a_tool_dispatches")
    assert len(rows) == 4


@pytest.mark.asyncio
async def test_native_private_payload_limit_is_counted_before_retention(app_boundary, publications, mcp_http_server):
    registry, _, _ = publications
    registry._max_payload_bytes = 1
    withheld = await execute_initial(app_boundary)
    assert withheld["status"] == "ok"
    assert [part["type"] for part in withheld["parts"]] == ["notice"]
    assert "Do not run it again" in withheld["parts"][0]["data"]["body"]
    assert not registry._publications and mcp_http_server.witness == ["once"]


@pytest.mark.asyncio
@pytest.mark.parametrize("caller", [None, CallerContext.anonymous(), CallerContext.a2a_transport()])
async def test_unbound_interactive_publisher_retains_no_private_result(app_boundary, publications, mcp_http_server, caller):
    registry, _, _ = publications
    tool = await allow(app_boundary, "app_mutate")
    with caller_context_scope(caller), part_collector(host=app_boundary.host, session_id="original-chat"):
        result = await tool.binding.invoke({"text": "unbound"}, session_id="original-chat", source="chat")
    assert not registry._publications and '"mcp_app"' not in json.dumps(result)
    assert mcp_http_server.witness == ["unbound"]


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["max_publications_per_owner", "max_views_per_owner"])
async def test_owner_budget_cannot_exceed_its_global_budget(app_boundary, field):
    options = dict(host=app_boundary.host, max_pending_calls=2, agent_id=app_boundary.host.did,
        publication_owner=lambda context: None, require_reader=lambda owner, context: None,
        max_publications=4, max_views=4, max_payload_bytes=8192,
        max_publications_per_owner=2, max_views_per_owner=2, retention_seconds=30)
    options[field] = 5
    with pytest.raises(ValueError, match="owner limits cannot exceed"):
        AppPublications(**options)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), "10"])
async def test_invalid_clock_output_fails_before_an_executor_is_published(app_boundary, value):
    with pytest.raises(ValueError, match="monotonic clock"):
        AppPublications(host=app_boundary.host, max_pending_calls=2, agent_id=app_boundary.host.did,
            publication_owner=lambda context: None, require_reader=lambda owner, context: None,
            max_publications=4, max_views=4, max_payload_bytes=8192,
            max_publications_per_owner=2, max_views_per_owner=2, retention_seconds=30, clock=lambda: value)


@pytest.mark.asyncio
async def test_generator_and_async_clock_functions_are_rejected_at_construction(app_boundary):
    def generator(*args):
        yield None

    async def async_clock():
        return 10

    options = dict(host=app_boundary.host, max_pending_calls=2, agent_id=app_boundary.host.did,
        publication_owner=lambda context: None, require_reader=lambda owner, context: None,
        max_publications=4, max_views=4, max_payload_bytes=8192,
        max_publications_per_owner=2, max_views_per_owner=2, retention_seconds=30)
    for changes in [{"publication_owner": generator}, {"require_reader": generator}, {"clock": async_clock}]:
        with pytest.raises(TypeError, match="synchronous function or method"):
            AppPublications(**(options | changes))


@pytest.mark.asyncio
async def test_missing_registration_and_closed_publisher_withhold_completed_results(app_boundary, publications, mcp_http_server):
    registry, _, _ = publications
    registry.retire("mcp:original")
    missing = await execute_initial(app_boundary, text="missing-registration")
    await registry.close()
    closed = await execute_initial(app_boundary, text="closed-publisher")
    for result in [missing, closed]:
        assert result["status"] == "ok" and [part["type"] for part in result["parts"]] == ["notice"]
    with caller_context_scope(ALICE), pytest.raises(ResourceConflict, match="result is unavailable"):
        registry.open_view("not-a-capability")
    assert not registry._publications and mcp_http_server.witness == ["missing-registration", "closed-publisher"]


@pytest.mark.asyncio
async def test_tool_wrapper_cannot_join_another_owners_registration(app_boundary, publications):
    registry, _, _ = publications
    with pytest.raises(ValueError, match="already belonged"):
        registry.register("mcp:another-owner", app_boundary.registered, is_current=lambda: True)


@pytest.mark.asyncio
async def test_actual_chat_destination_cannot_publish_into_a_different_agent_store(app_boundary, publications, mcp_http_server):
    registry, _, _ = publications
    registry._agent_id = "did:key:another-configured-agent"
    result = await execute_initial(app_boundary)
    assert [part["type"] for part in result["parts"]] == ["notice"]
    assert not registry._publications and mcp_http_server.witness == ["once"]


@pytest.mark.asyncio
async def test_payload_budget_accepts_exact_native_utf8_boundary_and_refuses_one_byte_less(app_boundary, publications, mcp_http_server):
    registry, clock, _ = publications
    text = "€"
    reference, _ = await publish(app_boundary, registry, text=text)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        arguments, native = registry.initial_result(reference, view)
    native_bytes = len(native.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8"))
    input_bytes = len(json.dumps(arguments, ensure_ascii=False, allow_nan=False).encode("utf-8"))
    clock[0] = 40.0
    await registry.drain_retired()
    registry._max_payload_bytes = native_bytes + input_bytes
    await publish(app_boundary, registry, text=text)
    registry._max_payload_bytes -= 1
    result = await execute_initial(app_boundary, text=text)
    assert [part["type"] for part in result["parts"]] == ["notice"]
    assert len(registry._publications) == 1 and mcp_http_server.witness == [text, text, text]
