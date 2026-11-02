"""Private associations with real MCP, Core permissions and required SQLite audit.

CallerContext scopes below exercise the host callback contract. They are not
HTTP authentication tests; no route advertises this in-process component yet.
"""

import asyncio
import json

import pytest
import pytest_asyncio

from kestrel_sdk.resources import ResourceConflict
from kestrel_sovereign.agent.parts import part_collector
from kestrel_sovereign.auth import CallerContext, caller_context_scope, current_caller_context
from kestrel_sovereign.features.security.permissions import PermissionLevel

from kestrel_feature_mcp.apps_publication import AppPublications
from tests.unit.test_mcp_apps_execution import app_boundary as app_boundary, allow


pytestmark = pytest.mark.parametrize("mcp_http_server", [
    {"apps_tools": True, "apps_execution_tools": True,
     "app_mutate_visibility": ["model", "app"]},
], indirect=True)


class Publisher:
    registry = None

    def publish(self, *args):
        return self.registry.publish(*args)


@pytest.fixture
def initial_publisher():
    return Publisher()


@pytest_asyncio.fixture
async def publications(app_boundary, initial_publisher):
    peer = app_boundary
    now = [10.0]
    reader_chat = [peer.host.did, "original-chat"]

    def original_owner(context):
        return current_caller_context()

    def require_reader(owner, context):
        caller = current_caller_context()
        if (caller is None or caller != owner
                or reader_chat != [context.agent_id, context.session_id]):
            raise ResourceConflict("The original authenticated chat reader is required")

    registry = AppPublications(executor=peer.executor, agent_id=peer.host.did,
        publication_owner=original_owner, require_reader=require_reader,
        max_publications=2, max_views=2, max_payload_bytes=8192,
        retention_seconds=30, clock=lambda: now[0])
    initial_publisher.registry = registry
    registry.register("mcp:original", peer.registered, is_current=lambda: peer.owner_current[0])
    try:
        yield registry, now, reader_chat
    finally:
        await registry.close()


ALICE = CallerContext.authenticated("alice")
BOB = CallerContext.authenticated("bob")


async def execute_initial(peer, *, text="once", chat="original-chat"):
    tool = await allow(peer, "app_mutate")
    with caller_context_scope(ALICE), part_collector(host=peer.host, session_id=chat):
        result = await tool.binding.invoke({"text": text}, session_id=chat, source="chat")
    return result


async def publish(peer, registry, *, text="once", chat="original-chat"):
    result = await execute_initial(peer, text=text, chat=chat)
    parts = [part for part in result["parts"] if part["type"] == "mcp_app"]
    assert len(parts) == 1
    part = parts[0]
    assert set(part["data"]) == {"reference", "session_id"}
    assert part["data"]["session_id"] == chat
    return part["data"]["reference"], result


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
    with caller_context_scope(caller), pytest.raises(ResourceConflict, match="authenticated chat reader"):
        registry.open_view(reference)


@pytest.mark.asyncio
@pytest.mark.parametrize("wrong_field", [0, 1])
async def test_same_principal_still_requires_original_agent_and_chat(app_boundary, publications, wrong_field):
    registry, _, chat = publications
    reference, _ = await publish(app_boundary, registry)
    chat[wrong_field] = "another-owner"
    with caller_context_scope(ALICE), pytest.raises(ResourceConflict, match="authenticated chat reader"):
        registry.open_view(reference)


@pytest.mark.asyncio
async def test_live_view_rechecks_independent_reader_at_every_operation(app_boundary, publications):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
    with caller_context_scope(BOB), pytest.raises(ResourceConflict, match="authenticated chat reader"):
        registry.initial_result(reference, view)
    with caller_context_scope(None), pytest.raises(ResourceConflict, match="authenticated chat reader"):
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
async def test_owner_replacement_revokes_old_results_and_physical_views(app_boundary, publications):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        registry.register("mcp:original", app_boundary.registered, is_current=lambda: True)
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
@pytest.mark.parametrize("field", ["max_publications", "max_views", "max_payload_bytes"])
async def test_invalid_publication_limits_fail_before_retaining_native_data(app_boundary, field, value):
    kwargs = dict(executor=app_boundary.executor, agent_id=app_boundary.host.did,
        publication_owner=lambda context: None, require_reader=lambda owner, context: None,
        max_publications=2, max_views=2, max_payload_bytes=8192, retention_seconds=30)
    kwargs[field] = value
    with pytest.raises(ValueError, match="positive integers"):
        AppPublications(**kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [0, -1, True, float("nan"), float("inf")])
async def test_invalid_retention_fails_before_retaining_native_data(app_boundary, value):
    with pytest.raises(ValueError, match="positive and finite"):
        AppPublications(executor=app_boundary.executor, agent_id=app_boundary.host.did,
            publication_owner=lambda context: None, require_reader=lambda owner, context: None,
            max_publications=2, max_views=2, max_payload_bytes=8192, retention_seconds=value)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["publication_owner", "require_reader"])
async def test_async_authorization_callbacks_cannot_escape_as_principal_snapshots(app_boundary, field):
    async def invalid(*args):
        return None

    kwargs = dict(executor=app_boundary.executor, agent_id=app_boundary.host.did,
        publication_owner=lambda context: None, require_reader=lambda owner, context: None,
        max_publications=2, max_views=2, max_payload_bytes=8192, retention_seconds=30)
    kwargs[field] = invalid
    with pytest.raises(TypeError, match="synchronous function or method"):
        AppPublications(**kwargs)


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
async def test_original_connection_loss_withholds_both_initial_result_and_resource(app_boundary, publications):
    registry, _, _ = publications
    reference, _ = await publish(app_boundary, registry)
    with caller_context_scope(ALICE):
        view = registry.open_view(reference)
        await app_boundary.connection.close()
        with pytest.raises((ResourceConflict, ValueError)):
            registry.initial_result(reference, view)
        with pytest.raises((ResourceConflict, ValueError)):
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
async def test_native_private_payload_limit_is_counted_before_retention(app_boundary, publications, mcp_http_server):
    registry, _, _ = publications
    registry._max_payload_bytes = 1
    withheld = await execute_initial(app_boundary)
    assert withheld["status"] == "ok"
    assert [part["type"] for part in withheld["parts"]] == ["notice"]
    assert "Do not run it again" in withheld["parts"][0]["data"]["body"]
    assert not registry._publications and mcp_http_server.witness == ["once"]


@pytest.mark.asyncio
async def test_unbound_interactive_publisher_retains_no_private_result(app_boundary, publications, mcp_http_server):
    registry, _, _ = publications
    tool = await allow(app_boundary, "app_mutate")
    with caller_context_scope(None), part_collector(host=app_boundary.host, session_id="original-chat"):
        result = await tool.binding.invoke({"text": "unbound"}, session_id="original-chat", source="chat")
    assert not registry._publications and '"mcp_app"' not in json.dumps(result)
    assert mcp_http_server.witness == ["unbound"]
