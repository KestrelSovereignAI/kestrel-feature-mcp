"""Native Core lease and governed dispatch with a synthetic encrypted grant.

The fixture issuer route exercises real Core authority, not the future Console
controller. Independent SDK consent and refresh are tested in their wire suites.
"""

from contextlib import AsyncExitStack
import time
from types import SimpleNamespace

from fastapi import FastAPI, Request
import httpx2
import pytest
from starlette.responses import JSONResponse

from kestrel_sovereign import server
from kestrel_sovereign.a2a.stores.unified.observability_store import ObservabilityStore
from kestrel_sovereign.a2a.stores.unified.feature_enablement_store import FeatureEnablementStore
from kestrel_sovereign.auth import caller_context_scope
from kestrel_sovereign.endpoints.auth_oauth import _create_jwt
from kestrel_sovereign.features.privacy import PrivacyAgent
from kestrel_sovereign.features.security.approval_queue import ApprovalQueue
from kestrel_sovereign.features.security.hooks import SecurityHook
from kestrel_sovereign.features.security.permissions import PermissionLevel, PermissionStore
from kestrel_sovereign.kestrel_agent import KestrelAgent
from kestrel_sovereign.llm.service import LLMService
from kestrel_sovereign.llm.adapter import ToolCall
from kestrel_sovereign.mcp_oauth import MCPOAuthAction, MCPOAuthHostPolicy
from kestrel_sovereign.security.capability_authority import HostCapabilityAccessDenied
from kestrel_sovereign.security.private_delivery import PrivateDeliveryMiddleware
from kestrel_sovereign.security.request_auth import (
    AuthenticatedSessionMiddleware, InteractiveAuthenticationLifetimeMiddleware, RequestAuthenticationService,
)
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend
from kestrel_sovereign.storage.async_storage import AsyncStorage
from kestrel_sdk.security.outbound import assert_safe_url

from kestrel_feature_mcp.connection import bind_tool_caller
from kestrel_feature_mcp.feature import MCPAgent
from kestrel_feature_mcp.oauth_credentials import OAuthConnectionCredential
from kestrel_feature_mcp.oauth_grants import OAuthGrantBinding, OAuthGrantChanged, OAuthGrantStore, OAuthGrantTokens
from tests.unit.test_oauth_grants import install_grant
from tests.unit.test_oauth_acceptance_http import oauth_peers

pytestmark = [pytest.mark.parametrize('mcp_http_server', [{'tls': True, 'oauth': {}}], indirect=True),
    pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'refresh': True}], indirect=True)]


@pytest.fixture
async def credential_boundary(oauth_peers, tmp_path, monkeypatch, owned_oauth_key):
    key, alice = 'owned-credential-operator-key', 'alice@credential.test'
    monkeypatch.setenv('KESTREL_API_KEY', key)
    monkeypatch.setenv('JWT_SECRET_KEY', 'owned-credential-jwt-signing-key-with-entropy')
    monkeypatch.setenv('KESTREL_REQUIRE_OAUTH', '1')
    monkeypatch.setenv('KESTREL_ALLOWED_EMAILS', alice)
    monkeypatch.setenv('KESTREL_HOME', str(tmp_path))
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED', 'true')
    async with AsyncExitStack() as owned:
        agent = KestrelAgent(did='did:test:credential-owner', storage_path=str(tmp_path / 'agent.db'),
            allowed_features=set(), sync_enabled=False, llm_service=LLMService(agent_data_dir=tmp_path))
        owned.push_async_callback(agent.llm_service.close)
        path = tmp_path / 'native-credentials.db'
        agent._raw_storage = AsyncStorage(str(path), agent_id=agent.did,
            semantic_capabilities=agent.semantic_capabilities)
        owned.push_async_callback(agent._raw_storage.close)
        await agent._raw_storage.initialize()
        database = agent._raw_storage.db.backend
        agent.privacy_agent = PrivacyAgent(agent._raw_storage, agent.privacy_mode)
        agent.observability_store = ObservabilityStore(database)
        await agent.observability_store.initialize()
        agent._feature_enablement_store = FeatureEnablementStore(database)
        await agent._feature_enablement_store.initialize()
        permissions = PermissionStore(str(tmp_path / 'permissions.db'))
        await permissions.initialize()
        queue = ApprovalQueue(permission_store=permissions, agent=agent)
        owned.callback(queue.cancel_all)
        agent.hooks_manager.register(SecurityHook(permissions, queue))
        feature = MCPAgent(agent)
        await agent._register_feature(feature)
        owned.push_async_callback(agent._unregister_feature_runtime, feature, unload=True)
        host = agent.create_mcp_oauth_host(feature, is_current=lambda: True)
        owned.push_async_callback(host.close)
        store = OAuthGrantStore(host.database, agent.did, max_token_bytes=4096)
        await store.initialize()
        b = SimpleNamespace(agent=agent, feature=feature, host=host, store=store,
            path=path, credential=None, connection=None, caller=None, handle=None,
            withdrawals=[], callers=[], permissions=permissions, key=key, alice=alice, peer=oauth_peers)
        app = FastAPI()
        b.app = app
        app.state.agent = agent
        app.state.mcp_oauth_policy = MCPOAuthHostPolicy(console_origin='https://console.example')
        service = RequestAuthenticationService(api_key=lambda: server.get_api_key(generate_if_missing=False))
        app.state.request_authentication = service
        app.add_middleware(InteractiveAuthenticationLifetimeMiddleware)
        app.middleware('http')(server.auth_middleware)
        app.add_middleware(AuthenticatedSessionMiddleware, secret_key='owned-credential-session-signing-key',
            session_cookie='kestrel_session', max_age=600)
        app.add_middleware(PrivateDeliveryMiddleware)

        @app.post('/api/owned-credential-connect')
        async def connect(request: Request):
            async with host._resolve_context(request) as context:
                async with host._operation(context, MCPOAuthAction.CONNECT):
                    selected = oauth_peers.selection
                    binding = OAuthGrantBinding(agent.did, context.principal_id, 'original-connection',
                        selected.server_url, selected.resource, selected.issuer, selected.client_id,
                        selected.redirect_uri, selected.scopes, selected.protected_metadata,
                        selected.authorization_metadata)
                    snapshot = await install_grant(store, binding, OAuthGrantTokens(
                        'native-fixture-access', 'native-fixture-refresh',
                        time.time() + (-100 if request.query_params.get('expired') else 3600), frozenset({'read'})))
                    lease = host.issue_lease(context, connection_id=binding.connection_id, slot_id=binding.slot_id)
                    credential = OAuthConnectionCredential(store, snapshot, lease,
                        host.client_identity(context), close_seconds=2, withdraw=b.withdrawals.append)
                    owned.push_async_callback(credential.retire)
                    await credential.admit()
                    endpoint = await assert_safe_url(selected.server_url, allowed_schemes=('https',))
                    connection = feature._new_mcp_connection(endpoint, auth=credential.bearer_auth(),
                        connect_timeout=2, call_timeout=2, close_timeout=2)
                    owned.push_async_callback(connection.close)
                    tools = await connection.connect()
                    caller = bind_tool_caller(connection, lambda: connection.is_connected,
                        binding.connection_id, tool_names=[tool.name for tool in tools], admit=credential.admit)
                    feature._mount_tools('mcp:credential', 'owned_credential',
                        [tool.model_dump(mode='json', by_alias=True) for tool in tools], caller)
                    handle = next(name for name in agent._tool_to_feature
                        if agent._tool_to_feature[name] == 'mcp:credential' and name.endswith('__echo'))
                    await permissions.set_permission('mcp:credential', handle, PermissionLevel.ALLOW)
                    b.credential, b.connection, b.caller, b.handle = credential, connection, caller, handle
                    return {'connected': True}

        @app.post('/api/owned-credential-refresh')
        async def refresh(request: Request):
            with service.bind(request) as authentication, caller_context_scope(authentication.caller):
                await b.credential.admit(force_refresh=True)
                return {'refreshed': True}

        @app.post('/api/owned-credential-call')
        async def call(request: Request):
            with service.bind(request) as authentication, caller_context_scope(authentication.caller):
                try:
                    b.callers.append(authentication.caller)
                    if request.query_params.get('mode') == 'inline':
                        executor = agent._make_inline_tool_executor('credential-chat')
                        effective_args, result = await executor(b.handle, {'text': 'owned-effect'})
                        await agent._append_executed_tool_breadcrumbs([], [{
                            'id': 'owned-native-inline-call', 'name': b.handle,
                            'arguments': effective_args, 'result': result,
                        }], session_id='credential-chat')
                        return result
                    return await agent._dispatch_tool_call(
                        ToolCall(id='owned-native-tool-call', name=b.handle, arguments={'text': 'owned-effect'}),
                        {}, {b.handle}, [], 0, 'Owned synthetic MCP call',
                        session_id='credential-chat', source='model')
                except HostCapabilityAccessDenied:
                    return JSONResponse({'error': 'original_principal_required'}, status_code=403)
                except OAuthGrantChanged:
                    return JSONResponse({'error': 'original_revision_changed'}, status_code=409)
        b.client = await owned.enter_async_context(httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url='https://console.example',
            headers={'X-API-Key': key}))
        yield b


async def test_native_owner_dispatch_reaches_the_peer_once_and_audits_it(credential_boundary):
    b = credential_boundary
    assert (await b.client.post('/api/owned-credential-connect')).status_code == 200
    result = await b.client.post('/api/owned-credential-call')
    assert result.status_code == 200, result.text
    assert b.peer.resource.witness == ['owned-effect']
    assert not b.withdrawals
    rows = await b.host.database.fetch_all('SELECT session_id,result_status FROM a2a_tool_dispatches')
    assert [tuple(row) for row in rows] == [('credential-chat', 'success')]
    assert b.peer.requests.count(('POST', '/token')) == 0


async def test_foreign_native_principal_cannot_dispatch_or_withdraw_the_owner(credential_boundary):
    b = credential_boundary
    assert (await b.client.post('/api/owned-credential-connect')).status_code == 200
    result = await b.client.post('/api/owned-credential-call', headers={
        'X-API-Key': '', 'Authorization': 'Bearer ' + _create_jwt(b.alice)})
    assert result.status_code in {200, 403}, result.text
    assert b.peer.resource.witness == []
    assert len(b.callers) == 1 and b.callers[0].identity == b.alice
    assert b.withdrawals == [] and b.connection.is_connected
    own = await b.client.post('/api/owned-credential-call')
    assert own.status_code == 200, own.text
    assert b.peer.resource.witness == ['owned-effect']


async def test_native_wire_credential_check_independently_refuses_a_foreign_request(credential_boundary):
    b = credential_boundary
    assert (await b.client.post('/api/owned-credential-connect')).status_code == 200

    @b.app.post('/api/owned-credential-wire-check')
    async def wire_check(request: Request):
        with caller_context_scope(request.state.caller):
            try:
                await b.credential.dispatch_token('principal')
            except HostCapabilityAccessDenied:
                return JSONResponse({'error': 'original_principal_required'}, status_code=403)
        return {'authorized': True}

    foreign = await b.client.post('/api/owned-credential-wire-check', headers={
        'X-API-Key': '', 'Authorization': 'Bearer ' + _create_jwt(b.alice)})
    assert foreign.status_code == 403, foreign.text
    assert not b.withdrawals and not b.peer.resource.witness
    own = await b.client.post('/api/owned-credential-wire-check')
    assert own.status_code == 200 and own.json() == {'authorized': True}
    assert not b.withdrawals and not b.peer.resource.witness


async def test_expired_grant_refreshes_under_the_original_core_connect_task(credential_boundary):
    b = credential_boundary
    result = await b.client.post('/api/owned-credential-connect?expired=1')
    assert result.status_code == 200, result.text
    assert b.peer.requests.count(('POST', '/token')) == 1
    assert ('GET', '/authorize') not in b.peer.requests
    result = await b.client.post('/api/owned-credential-call')
    assert result.status_code == 200 and b.peer.resource.witness == ['owned-effect'], result.text
    assert b.peer.requests.count(('POST', '/token')) == 1


async def test_another_native_database_owner_revocation_blocks_before_dispatch(credential_boundary):
    b = credential_boundary
    assert (await b.client.post('/api/owned-credential-connect')).status_code == 200
    other = SQLiteBackend(str(b.path))
    await other.connect()
    try:
        store = OAuthGrantStore(other, b.agent.did, max_token_bytes=4096)
        await store.revoke_local(await store.read(b.credential.snapshot.binding))
    finally:
        await other.close()
    result = await b.client.post('/api/owned-credential-call')
    assert result.status_code in {200, 409}, result.text
    assert b.peer.resource.witness == []
    assert b.withdrawals == ['reauthorization_required']


async def test_native_permission_deny_prevents_resource_dispatch_and_refresh(credential_boundary):
    b = credential_boundary
    assert (await b.client.post('/api/owned-credential-connect')).status_code == 200
    await b.permissions.set_permission('mcp:credential', b.handle, PermissionLevel.DENY)
    result = await b.client.post('/api/owned-credential-call')
    assert result.status_code == 200, result.text
    assert b.peer.resource.witness == []
    assert b.peer.requests.count(('POST', '/token')) == 0
    assert b.withdrawals == []
    audit = await b.permissions.get_audit_log()
    assert any(row['decision'] == 'auto_denied' for row in audit)


async def test_background_message_waits_for_the_original_foreground_refresh_revision(credential_boundary):
    import asyncio
    b = credential_boundary
    assert (await b.client.post('/api/owned-credential-connect')).status_code == 200
    b.peer.options['stall_token'] = True
    refresh = asyncio.create_task(b.client.post('/api/owned-credential-refresh'))
    background = None
    try:
        async with asyncio.timeout(2):
            while ('POST', '/token') not in b.peer.requests:
                await asyncio.sleep(0.001)
        assert (await b.store.read(b.credential.snapshot.binding)).state == 'refreshing'
        background = asyncio.create_task(b.credential.dispatch_token('background'))
        await asyncio.sleep(0)
        assert not background.done()
        b.peer.release_body.set()
        result = await refresh
        assert result.status_code == 200, result.text
        assert await background == 'native-fixture-access'
        assert not b.withdrawals and b.peer.requests.count(('POST', '/token')) == 1
    finally:
        b.peer.release_body.set()
        await asyncio.gather(refresh, *([background] if background else []), return_exceptions=True)
