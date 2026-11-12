"""Optional host composition against actual Core, HTTP MCP and SQLite."""

from uuid import uuid4

import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass
import json

from fastapi import FastAPI, Request
import httpx2
from mcp_types import CLIENT_CAPABILITIES_META_KEY
import pytest
import pytest_asyncio
from pydantic import ValidationError

from kestrel_sovereign import server
from kestrel_sovereign.a2a.stores.unified.observability_store import ObservabilityStore
from kestrel_sovereign.agent.parts import part_collector
from kestrel_sovereign.auth import caller_context_scope
from kestrel_sovereign.features.security.approval_queue import ApprovalQueue
from kestrel_sovereign.features.security.hooks import SecurityHook
from kestrel_sovereign.features.security.permissions import PermissionLevel, PermissionStore
from kestrel_sovereign.kestrel_agent import KestrelAgent
from kestrel_sovereign.testing.fixtures import native_tool_effect_agent as native_tool_effect_agent
from kestrel_sovereign.security.private_delivery import PrivateDeliveryMiddleware
from kestrel_sovereign.security.request_auth import (
    AuthenticatedSessionMiddleware, InteractiveAuthenticationLifetimeMiddleware, RequestAuthenticationService,
)
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend

from kestrel_feature_mcp.apps_host import AppsSettings
from kestrel_feature_mcp.connection import bind_tool_caller
from kestrel_feature_mcp.feature import MCPAgent, MCPHostCapabilityError
from tests.unit.test_mcp_core_registry import CoreRegistryHost


@dataclass
class AppsBoundary:
    app: object
    feature: MCPAgent
    agent: KestrelAgent
    connection: object
    client: object
    backend: object
    permissions: object
    queue: object
    requests: object

    async def initial_view(self):
        initial = await self.client.post("/api/owned-turn")
        assert initial.status_code == 200, initial.text
        reference = next(part["data"]["reference"] for part in initial.json()["parts"] if part["type"] == "mcp_app")
        opened = await self.client.post(f"/api/mcp/apps/publications/{reference}/views?session_id=original-chat", json={})
        assert opened.status_code == 200, opened.text
        return reference, opened.json()


def apps_application(agent):
    app = FastAPI()
    app.state.agent = agent
    app.state.request_authentication = RequestAuthenticationService(
        api_key=lambda: server.get_api_key(generate_if_missing=False))
    app.add_middleware(InteractiveAuthenticationLifetimeMiddleware)
    app.middleware("http")(server.auth_middleware)
    app.add_middleware(AuthenticatedSessionMiddleware, secret_key="owned-apps-session-signing-key",
                       session_cookie="kestrel_session", max_age=600)
    app.add_middleware(PrivateDeliveryMiddleware)
    server._mount_feature_ui_assets(app)
    server._mount_feature_routers(app)
    return app


@pytest.mark.parametrize("settings", [
    {"enabled": "true"}, {"max_views": True}, {"retention_seconds": float("inf")},
    {"maintenance_seconds": 0}, {"max_views": 2, "max_views_per_owner": 3},
    {"max_publications": 2, "max_publications_per_owner": 3}, {"unknown": 1},
])
def test_invalid_app_policy_is_refused_before_native_resources(settings):
    with pytest.raises(ValidationError):
        AppsSettings.model_validate(settings)


@pytest.mark.asyncio
async def test_apps_are_explicitly_disabled_and_unsupported_host_fails_clearly():
    feature = MCPAgent(CoreRegistryHost())
    assert (await feature.get_config())["apps"]["enabled"] is False
    assert feature.get_router() is None and feature.get_ui_contributions() is None
    with pytest.raises(TypeError, match="authenticated physical View host"):
        await feature.set_config({"apps": {"enabled": True}})
    assert (await feature.get_config())["apps"]["enabled"] is False


@pytest_asyncio.fixture
async def native_apps_host(request, mcp_http_server, tmp_path, monkeypatch, apps_sandbox_url, apps_host_origin, native_tool_effect_agent):
    key = "owned-mcp-composition-api-key"
    monkeypatch.setenv("KESTREL_API_KEY", key)
    monkeypatch.setenv("KESTREL_HOME", str(tmp_path))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    async with AsyncExitStack() as owned:
        agent = await native_tool_effect_agent(did='did:test:mcp-apps-composition')
        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        await backend.connect()
        owned.push_async_callback(backend.close)
        agent.observability_store = ObservabilityStore(backend)
        await agent.observability_store.initialize()
        permissions = PermissionStore(str(tmp_path / "permissions.db"))
        await permissions.initialize()
        requests = asyncio.Queue()
        queue = ApprovalQueue(on_request_added=requests.put, permission_store=permissions, agent=agent)
        owned.callback(queue.cancel_all)
        agent.hooks_manager.register(SecurityHook(permissions, queue))
        feature = MCPAgent(agent)
        await agent._register_feature(feature)
        owned.push_async_callback(agent._unregister_feature_runtime, feature, unload=True)
        assert not hasattr(feature, "enabled")
        if getattr(request, "param", "reactivate") == "reactivate":
            # Exercise the public Core's actual soft reactivation lifecycle.
            # Initial registration is covered separately, without adding flags.
            await agent._unregister_feature_runtime(feature, unload=False)
            await agent._activate_feature_runtime(feature)
        await feature.set_config({"apps": {"enabled": True,
            "host": {"sandbox_url": apps_sandbox_url, "host_origin": apps_host_origin}}})
        connection = feature._new_mcp_connection(mcp_http_server.url)
        tools = await connection.connect()
        owned.push_async_callback(connection.close)
        caller = bind_tool_caller(connection, lambda: connection.is_connected, "owned-composition",
                                  tool_names=[tool.name for tool in tools])
        feature._mount_tools("mcp:composition", "native", [tool.model_dump(by_alias=True) for tool in tools], caller)
        registered = feature._apps_publications._batches["mcp:composition"].tools
        source = next(item for item in registered if item.tool.native_tool.name == "app_mutate")
        await permissions.set_permission("mcp:composition", source.binding.name, PermissionLevel.ALLOW)
        app = apps_application(agent)

        @app.post("/api/owned-turn")
        async def initial(request: Request):
            with caller_context_scope(request.state.caller), part_collector(host=agent, session_id="original-chat"):
                return await source.binding.invoke({"text": "initial-once"}, session_id="original-chat", source="chat", operation_id=uuid4().hex)

        client = await owned.enter_async_context(httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),
            base_url="https://composition.test", headers={"X-API-Key": key}))
        yield AppsBoundary(app, feature, agent, connection, client, backend, permissions, queue, requests)


@pytest.mark.parametrize("native_apps_host", ["startup"], indirect=True)
@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
@pytest.mark.parametrize("retirement", ["deactivate", "missing-runtime", "host-disabled"])
async def test_initial_core_registration_mounts_the_actual_apps_producer_without_an_enabled_attribute(
    native_apps_host, retirement,
):
    b = native_apps_host
    assert not hasattr(b.feature, "enabled")
    assert b.agent.feature_contribution_runtime.is_active(b.feature)
    batch = b.feature._apps_publications._batches["mcp:composition"]
    batch.require_current()
    assert batch.tools and b.connection.is_connected
    runtime = b.agent.feature_contribution_runtime
    if retirement == "deactivate":
        assert runtime.deactivate(b.feature)
    elif retirement == "missing-runtime":
        b.agent.feature_contribution_runtime = None
    else:
        b.feature.enabled = False
    try:
        # A feature still present in agent.features cannot keep the native batch.
        assert b.agent.features[b.feature.name] is b.feature
        assert not batch.is_live()
        with pytest.raises(MCPHostCapabilityError, match="active native Core feature registration"):
            b.feature._mount_tools("mcp:composition", "native",
                [item.tool.native_tool.model_dump(mode="json", by_alias=True) for item in batch.tools],
                batch.tools[0].tool.bound_caller)
        assert b.feature._apps_publications._batches["mcp:composition"] is batch
        assert all(item.binding.is_current for item in batch.tools)
    finally:
        b.agent.feature_contribution_runtime = runtime


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
@pytest.mark.asyncio
async def test_real_feature_mount_negotiates_apps_and_connection_retirement_withdraws_views(
    native_apps_host, mcp_http_server,
):
    b = native_apps_host
    discovered = [json.loads(body) for _, body in mcp_http_server.requests
                  if body and json.loads(body).get("method") == "server/discover"]
    assert discovered, [json.loads(body).get("method") for _, body in mcp_http_server.requests if body]
    capabilities = discovered[0]["params"]["_meta"][CLIENT_CAPABILITIES_META_KEY]
    assert capabilities["extensions"]["io.modelcontextprotocol/ui"] == {}
    assert b.feature.get_ui_contributions().modules == ["parent-entry.js", "oauth-panel.js"]
    assert b.feature.get_ui_contributions().css == ["oauth-panel.css"]
    reference, opened = await b.initial_view()
    assert opened["result"]["_meta"]["private-result"] == {"view": "only"}
    await b.connection.close()
    refused = await b.client.post(f"/api/mcp/apps/publications/{reference}/views?session_id=original-chat", json={})
    assert refused.status_code == 404, refused.text
    await b.feature._apps_host.maintain()
    assert not b.feature._apps_host._views
    assert mcp_http_server.witness == ["initial-once"]
    rows = await b.backend.fetch_all("SELECT session_id,result_status FROM a2a_tool_dispatches")
    assert [tuple(row) for row in rows] == [("original-chat", "success")]


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
@pytest.mark.asyncio
async def test_soft_reenable_recreates_the_original_declared_apps_host(native_apps_host):
    b = native_apps_host
    previous = b.feature._apps_host
    await b.feature.shutdown()
    assert previous.retired and b.feature._apps_host is None
    await b.feature.initialize()
    assert b.feature._apps_host is not None and b.feature._apps_host is not previous
    assert b.feature.get_router() is not None


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
@pytest.mark.parametrize("retirement", ["registration", "connection"])
@pytest.mark.asyncio
async def test_unmount_and_connection_close_cancel_pending_approval_without_native_effect(
    native_apps_host, mcp_http_server, retirement,
):
    b = native_apps_host
    _reference, opened = await b.initial_view()
    source = next(item for item in b.feature._apps_publications._batches["mcp:composition"].tools
                  if item.tool.native_tool.name == "app_mutate")
    await b.permissions.set_permission("mcp:composition", source.binding.name, PermissionLevel.ASK)
    call = asyncio.create_task(b.client.post(f'/api/mcp/apps/views/{opened["view_id"]}/tools/call?session_id=original-chat',
        json={"name": "app_mutate", "arguments": {"text": "must-not-execute"}, "operation_id": uuid4().hex}))
    try:
        approval = await asyncio.wait_for(b.requests.get(), 5)
        assert not call.done()
        if retirement == "registration":
            b.feature._unmount_tools("mcp:composition")
            await b.feature._apps_host.maintain()
        else:
            await b.connection.close()
        assert "mcp:composition" not in b.feature._apps_publications._batches
        assert not b.feature._apps_publications._views
        response = await asyncio.wait_for(call, 5)
        assert response.status_code == 404, response.text
        decision = await b.queue.submit_decision(approval.id, True, scope="once")
        assert decision.awaiter_gone is True
        assert not await b.queue.submit_decision(approval.id, True, scope="once")
        assert mcp_http_server.witness == ["initial-once"]
    finally:
        b.queue.cancel_all()
        await asyncio.gather(call, return_exceptions=True)


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
@pytest.mark.asyncio
async def test_invalid_reconfiguration_preserves_the_current_host_and_copied_settings(native_apps_host):
    b = native_apps_host
    await b.connection.close()
    original = b.feature._apps_host
    configuration = await b.feature.get_config()
    changed = await b.feature.get_config()
    changed["apps"]["host"]["sandbox_url"] = "javascript:invalid"
    assert await b.feature.get_config() == configuration
    with pytest.raises(ValueError):
        await b.feature.set_config(changed)
    assert b.feature._apps_host is original and not original.retired
    assert await b.feature.get_config() == configuration


@pytest.mark.asyncio
@pytest.mark.parametrize('missing', ['capability', 'scope'])
@pytest.mark.parametrize('mcp_http_server', [{'apps_tools': True, 'apps_execution_tools': True,
    'app_mutate_visibility': ['model', 'app']}], indirect=True)
async def test_missing_owned_call_contract_preserves_original_configuration(native_apps_host, monkeypatch, missing):
    b = native_apps_host
    await b.connection.close()
    original = b.feature._apps_host
    configuration = await b.feature.get_config()
    changed = await b.feature.get_config()
    changed['apps']['max_pending_calls'] += 1
    if missing == 'capability':
        monkeypatch.setattr(b.agent, 'supports_owned_mcp_app_calls', False)
    else:
        monkeypatch.setattr(b.agent, 'mcp_app_call_scope', None)
    with pytest.raises(TypeError, match='host-owned task contract'):
        await b.feature.set_config(changed)
    assert b.feature._apps_host is original and not original.retired, (
        'An unsupported App task host retired the original configuration before validation')
    assert await b.feature.get_config() == configuration


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
@pytest.mark.asyncio
async def test_normal_core_mounts_survive_apps_configuration_and_host_replacement(native_apps_host, monkeypatch):
    b = native_apps_host
    await b.connection.close()
    configuration = await b.feature.get_config()
    await b.feature.set_config({"apps": {"enabled": False}})
    app = apps_application(b.agent)
    monkeypatch.setattr(server, "SERVE_UI", True)
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),
        base_url="https://composition.test", headers={"X-API-Key": "owned-mcp-composition-api-key"}) as client:
        asset = "/features/mcpagent/static/parent-entry.js"
        route = "/api/mcp/apps/views/" + "a" * 43 + "/tools?session_id=original-chat"
        assert (await client.get(asset)).status_code == 200
        assert (await client.get(route)).status_code == 404
        await b.feature.set_config(configuration)
        enabled = await client.get(route)
        assert enabled.status_code == 404 and enabled.json() == {"error": {"code": "mcp_app_unavailable"}}
        original = b.feature._apps_host
        await b.feature.shutdown()
        assert (await client.get(route)).status_code == 404
        await b.feature.initialize()
        assert b.feature._apps_host is not original
        replaced = await client.get(route)
        assert replaced.status_code == 404 and replaced.json() == {"error": {"code": "mcp_app_unavailable"}}


@pytest.mark.parametrize("mcp_http_server", [{"apps_tools": True, "apps_execution_tools": True,
    "app_mutate_visibility": ["model", "app"]}], indirect=True)
@pytest.mark.asyncio
async def test_native_cookie_owner_and_csrf_cover_private_app_mutations(native_apps_host, mcp_http_server, monkeypatch):
    b = native_apps_host
    monkeypatch.setenv("KESTREL_REQUIRE_OAUTH", "1")
    monkeypatch.setenv("KESTREL_ALLOWED_EMAILS", "cookie@composition.test")
    @b.app.get("/api/owned-cookie-login")
    async def login(request: Request):
        request.session["user_email"] = "cookie@composition.test"
        return {"signed_in": True}
    assert (await b.client.get("/api/owned-cookie-login")).status_code == 200
    b.client.headers.pop("X-API-Key")
    initial = await b.client.post("/api/owned-turn")
    assert initial.status_code == 200
    reference = next(part["data"]["reference"] for part in initial.json()["parts"] if part["type"] == "mcp_app")
    path = f"/api/mcp/apps/publications/{reference}/views?session_id=original-chat"
    assert (await b.client.post(path, json={})).status_code == 403
    b.client.cookies.set("kestrel_csrf", "owned-cookie-csrf")
    headers = {"X-CSRF-Token": "owned-cookie-csrf", "Origin": "https://composition.test"}
    opened = await b.client.post(path, json={}, headers=headers)
    assert opened.status_code == 200, opened.text
    view = f'/api/mcp/apps/views/{opened.json()["view_id"]}'
    call = view + "/tools/call?session_id=original-chat"
    body = {"name": "app_mutate", "arguments": {"text": "cookie-app-once"}, "operation_id": uuid4().hex}
    assert (await b.client.post(call, json=body,
        headers={**headers, "Origin": "https://foreign.test"})).status_code == 403
    assert mcp_http_server.witness == ["initial-once"]
    assert (await b.client.post(call, json=body, headers=headers)).status_code == 200
    assert (await b.client.delete(view + "?session_id=original-chat")).status_code == 403
    assert (await b.client.delete(view + "?session_id=original-chat", headers=headers)).status_code == 200
    assert mcp_http_server.witness == ["initial-once", "cookie-app-once"]
