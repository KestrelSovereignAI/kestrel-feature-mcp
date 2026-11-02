"""The first native App result stays private until real Core policy and SQL."""

import asyncio
import json

import pytest

from kestrel_sdk.hooks.base import Hook, HookEvent, HookOutput
from kestrel_sdk.resources import ResourceOutcomeUnknown
from kestrel_sdk.tools import ToolPublicationContext
from kestrel_sovereign.agent.parts import part_collector

from tests.unit.test_mcp_apps_execution import app_boundary as app_boundary, allow


pytestmark = pytest.mark.parametrize("mcp_http_server", [
    {"apps_tools": True, "apps_execution_tools": True,
     "app_mutate_visibility": ["model", "app"]},
], indirect=True)


class InitialPublisher:
    def __init__(self):
        self.publications = []

    def publish(self, tool, context, native, arguments):
        self.publications.append((tool, context, native, arguments))
        return [{"type": "mcp_app", "data": {"reference": "owned-private-result"}}]


@pytest.fixture
def initial_publisher():
    return InitialPublisher()


@pytest.mark.asyncio
async def test_first_private_result_waits_for_audited_destination(app_boundary, mcp_http_server, initial_publisher):
    peer = app_boundary
    tool = await allow(peer, "app_mutate")
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    with part_collector(host=peer.host, session_id="initial-chat"):
        call = asyncio.create_task(tool.binding.invoke({"text": "once"}, session_id="initial-chat", source="chat"))
        try:
            await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
            assert mcp_http_server.witness == ["once"]
            assert not call.done() and not initial_publisher.publications
            peer.store.release_dispatch.set()
            result = await call
        finally:
            peer.store.release_dispatch.set()
            if not call.done():
                call.cancel()
            await asyncio.gather(call, return_exceptions=True)
    assert len(initial_publisher.publications) == 1
    source, context, native, arguments = initial_publisher.publications[0]
    assert source is tool.tool and context == ToolPublicationContext(peer.host.did, "initial-chat")
    assert native.meta["private-result"] == {"view": "only"}
    assert native.content[0].meta == {"private-block": "view-only"}
    assert arguments == {"text": "once"}
    encoded = json.dumps(result)
    assert '"private-result":' not in encoded and '"private-block":' not in encoded
    assert '"view-only"' not in encoded
    assert any(part["type"] == "mcp_app" for part in result["parts"])
    rows = await peer.backend.fetch_all("SELECT session_id,result_status FROM a2a_tool_dispatches")
    assert [tuple(row) for row in rows] == [("initial-chat", "success")]


@pytest.mark.asyncio
async def test_headless_results_do_not_create_private_views(app_boundary, mcp_http_server, initial_publisher):
    peer = app_boundary
    tool = await allow(peer, "app_mutate")
    result = await tool.binding.invoke({"text": "headless"}, session_id="headless", source="scheduled")
    assert not initial_publisher.publications and mcp_http_server.witness == ["headless"]
    assert "mcp_app" not in json.dumps(result) and "private-result" not in json.dumps(result)


@pytest.mark.asyncio
async def test_initial_publication_honors_completed_post_policy(app_boundary, mcp_http_server, initial_publisher):
    class Redact(Hook):
        def __init__(self):
            super().__init__("initial-result-redaction", [HookEvent.POST_TOOL_USE])

        async def execute(self, value):
            value.tool_response["confirmation"] = "Reviewed replacement"
            return HookOutput.allow()

    peer = app_boundary
    peer.host.hooks_manager.register(Redact())
    tool = await allow(peer, "app_mutate")
    with part_collector(host=peer.host, session_id="initial-chat"):
        result = await tool.binding.invoke({"text": "redacted"}, session_id="initial-chat", source="chat")
    assert not initial_publisher.publications and mcp_http_server.witness == ["redacted"]
    assert result["confirmation"] == "Reviewed replacement"


@pytest.mark.asyncio
async def test_missing_real_dispatch_table_withholds_initial_private_data(app_boundary, mcp_http_server, initial_publisher):
    peer = app_boundary
    tool = await allow(peer, "app_mutate")
    await peer.backend.execute("DROP TABLE a2a_tool_dispatches")
    with part_collector(host=peer.host, session_id="initial-chat"):
        with pytest.raises(ResourceOutcomeUnknown):
            await tool.binding.invoke({"text": "executed"}, session_id="initial-chat", source="chat")
    assert not initial_publisher.publications and mcp_http_server.witness == ["executed"]


@pytest.mark.asyncio
async def test_view_tool_calls_do_not_publish_another_initial_result(app_boundary, mcp_http_server, initial_publisher):
    peer = app_boundary
    tool = await allow(peer, "app_mutate")
    with part_collector(host=peer.host, session_id="initial-chat"):
        await tool.binding.invoke({"text": "initial"}, session_id="initial-chat", source="chat")
    result = await peer.executor.invoke(peer.view, "app_mutate", {"text": "view-call"})
    assert result.meta["private-result"] == {"view": "only"}
    assert len(initial_publisher.publications) == 1
    assert mcp_http_server.witness == ["initial", "view-call"]


@pytest.mark.asyncio
async def test_closed_connection_cannot_publish_a_staged_initial_result(app_boundary, mcp_http_server, initial_publisher):
    peer = app_boundary
    tool = await allow(peer, "app_mutate")
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    with part_collector(host=peer.host, session_id="initial-chat"):
        call = asyncio.create_task(tool.binding.invoke({"text": "once"}, session_id="initial-chat", source="chat"))
        try:
            await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
            await peer.connection.close()
            peer.store.release_dispatch.set()
            result = await call
        finally:
            peer.store.release_dispatch.set()
            if not call.done():
                call.cancel()
            await asyncio.gather(call, return_exceptions=True)
    assert not initial_publisher.publications and mcp_http_server.witness == ["once"]
    assert result["status"] == "ok"
    assert [part["type"] for part in result["parts"]] == ["notice"]
    assert "Do not run it again" in result["parts"][0]["data"]["body"]


@pytest.mark.asyncio
async def test_a_closed_chat_cannot_gain_a_late_initial_view(app_boundary, mcp_http_server, initial_publisher):
    peer = app_boundary
    tool = await allow(peer, "app_mutate")
    peer.store.dispatch_started, peer.store.release_dispatch = asyncio.Event(), asyncio.Event()
    with part_collector(host=peer.host, session_id="initial-chat"):
        call = asyncio.create_task(tool.binding.invoke({"text": "once"}, session_id="initial-chat", source="chat"))
        await asyncio.wait_for(peer.store.dispatch_started.wait(), 5)
    try:
        peer.store.release_dispatch.set()
        result = await call
    finally:
        peer.store.release_dispatch.set()
        if not call.done():
            call.cancel()
        await asyncio.gather(call, return_exceptions=True)
    assert not initial_publisher.publications and mcp_http_server.witness == ["once"]
    assert not any(part["type"] == "mcp_app" for part in result.get("parts", []))
