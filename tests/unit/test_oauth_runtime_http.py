"""Real Core routes, three TLS origins, native consent, dispatch and restart."""

from contextlib import AsyncExitStack
from dataclasses import replace
from pathlib import Path
import socket
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import ValidationError

from kestrel_sovereign.endpoints.auth_oauth import _create_jwt
from kestrel_sovereign.endpoints.mcp_oauth import router as public_oauth_router
from kestrel_sovereign.features.security.permissions import PermissionLevel
from kestrel_sovereign.mcp_oauth import MCPOAuthHostPolicy

from kestrel_feature_mcp.oauth_grants import OAuthGrantStore
from kestrel_feature_mcp.oauth_runtime import OAuthRuntime, OAuthSettings
from kestrel_feature_mcp.remote import remote_owner
from tests.http_peers import serve_http
from tests.unit.test_oauth_acceptance_http import oauth_peers as oauth_peers
from tests.unit.test_oauth_credentials import credential_boundary as credential_boundary
from tests.unit.test_oauth_production_acquisition_http import approve


pytestmark = [pytest.mark.parametrize('mcp_http_server', [{'tls': True, 'oauth': {}}], indirect=True),
    pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'refresh': True}], indirect=True)]


@pytest.fixture
async def oauth_runtime(credential_boundary, tmp_path):
    b = credential_boundary
    b.app.include_router(public_oauth_router)
    await b.host.close()
    await b.feature.set_config({'oauth': {'enabled': True, 'close_seconds': 2.0}})
    b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
    b.app.include_router(b.feature.get_router())
    async with AsyncExitStack() as owned:
        console = await owned.enter_async_context(serve_http(b.app, tmp_path / 'console', certificate_host='console.example'))
        origin = 'https://console.example:' + str(urlsplit(console.url).port)
        b.app.state.mcp_oauth_policy = MCPOAuthHostPolicy(console_origin=origin,
            network_seconds=2.0, operation_seconds=10.0)
        policy = b.app.state.mcp_oauth_policy
        b.peer.wire.authorities.add(('console.example', urlsplit(console.url).port))
        with b.peer.wire.bundle.open('ab') as bundle:
            bundle.write(Path(console.certificate_file).read_bytes())
        b.peer.wire.state.client_id, b.peer.wire.state.redirect_uri = policy.client_id, policy.redirect_uri
        b.peer.selection = replace(b.peer.selection, client_id=policy.client_id, redirect_uri=policy.redirect_uri)
        b.owned = owned
        yield b


async def authorize(b):
    response = await b.client.post('/api/mcp/oauth/authorizations', json={
        'server_url': b.peer.selection.server_url, 'scopes': ['read']})
    assert response.status_code == 200, response.text
    started = response.json()
    state = parse_qs(urlsplit(started['authorization_url']).query)['state'][0]
    callback = await approve(b.peer, started | {'state': state})
    result = await b.client.post('/api/mcp/oauth/authorizations/' + started['operation_id'] + '/callback', json=callback)
    assert result.status_code == 200, result.text
    assert result.json()['state'] == 'authorized'
    return result.json()['connection_id']


async def connect(b, name, *, refresh=False):
    result = await b.client.post('/api/mcp/oauth/connections/' + name + '/connect', json={'refresh': refresh})
    assert result.status_code == 200, result.text
    assert result.json()['state'] == 'connected'
    b.handle = next(name for name, owner in b.agent._tool_to_feature.items()
        if owner == remote_owner(result.json()['connection_id']) and name.endswith('__echo'))
    await b.permissions.set_permission(remote_owner(name), b.handle, PermissionLevel.ALLOW)
    return result.json()


async def test_actual_core_consent_connect_governed_call_and_opaque_enablement(oauth_runtime):
    b = oauth_runtime
    name = await authorize(b)
    await connect(b, name)
    result = await b.client.post('/api/owned-credential-call')
    assert result.status_code == 200, result.text
    assert b.peer.resource.witness == ['owned-effect']
    assert b.peer.requests.count(('POST', '/token')) == 1
    assert b.peer.requests.count(('GET', '/authorize')) == 1
    assert len(await b.host.database.fetch_all('SELECT * FROM a2a_tool_dispatches')) == 1
    saved = await b.feature._read_server_delta(name)
    assert saved['metadata'] == {'mode': 'remote', 'auth': 'oauth',
        'url': b.peer.selection.server_url, 'grant': b.runtime._credentials[name].slot_id}
    rows = (await b.client.get('/api/mcp/oauth/connections')).json()['connections']
    assert len(rows) == 1 and rows[0]['state'] == 'connected'


async def test_foreign_core_principal_cannot_list_connect_disconnect_or_retire_owner(oauth_runtime):
    b = oauth_runtime
    name = await authorize(b)
    await connect(b, name)
    foreign = {'X-API-Key': '', 'Authorization': 'Bearer ' + _create_jwt(b.alice)}
    listed = await b.client.get('/api/mcp/oauth/connections', headers=foreign)
    assert listed.status_code == 200 and listed.json()['connections'] == []
    before = list(b.peer.resource.requests)
    response = await b.client.post('/api/mcp/oauth/connections/' + name + '/connect', headers=foreign, json={})
    assert response.status_code == 503, response.text
    response = await b.client.delete('/api/mcp/oauth/connections/' + name, headers=foreign)
    assert response.status_code == 503, response.text
    assert b.peer.resource.requests == before
    assert b.runtime._credentials[name].withdrawal_reason is None
    assert (await b.client.post('/api/owned-credential-call')).status_code == 200
    assert b.peer.resource.witness == ['owned-effect']


async def test_durable_grant_restarts_dormant_then_explicitly_refreshes_without_consent(oauth_runtime, monkeypatch):
    b = oauth_runtime
    name = await authorize(b)
    await connect(b, name)
    await b.host.close()
    before = list(b.peer.resource.requests), list(b.peer.requests)
    def forbidden(*args, **kwargs):
        raise AssertionError('Dormant OAuth restore/status must not perform DNS or decrypt')
    with monkeypatch.context() as guard:
        guard.setattr(socket, 'getaddrinfo', forbidden)
        guard.setattr(OAuthGrantStore, '_cipher', forbidden)
        await b.feature.on_agent_ready()
        assert not b.feature._remote_connections
        await b.agent._unregister_feature_runtime(b.feature, unload=False)
        await b.agent._activate_feature_runtime(b.feature)
        b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
        result = await b.client.get('/api/mcp/oauth/connections')
        assert result.status_code == 200 and result.json()['connections'][0]['state'] == 'authorized'
    assert (b.peer.resource.requests, b.peer.requests) == before
    await connect(b, name, refresh=True)
    assert b.peer.requests.count(('GET', '/authorize')) == 1
    assert b.peer.requests.count(('POST', '/token')) == 2
    result = await b.client.post('/api/owned-credential-call')
    assert result.status_code == 200 and b.peer.resource.witness == ['owned-effect'], result.text


async def test_local_disconnect_deletes_tokens_and_enablement_without_remote_revocation_claim(oauth_runtime):
    b = oauth_runtime
    name = await authorize(b)
    await connect(b, name)
    result = await b.client.delete('/api/mcp/oauth/connections/' + name)
    assert result.status_code == 200, result.text
    assert result.json() == {'local_tokens_deleted': True, 'remote_revocation': 'not_attempted'}
    assert await b.feature._read_server_delta(name) is None
    assert name not in b.feature._remote_connections
    assert b.handle not in b.agent._direct_tools
    rows = (await b.client.get('/api/mcp/oauth/connections')).json()['connections']
    assert rows[0]['state'] == 'revoked' and rows[0]['connected'] is False
    row = await b.host.database.fetch_one('SELECT ciphertext FROM mcp_oauth_credential_slots')
    assert row[0] is None


async def test_generic_mcp_unload_cannot_bypass_original_oauth_owner(oauth_runtime):
    b = oauth_runtime
    name = await authorize(b)
    await connect(b, name)
    result = await b.feature._unload_remote(name)
    assert result.status.value == 'error'
    assert name in b.feature._remote_connections
    assert await b.feature._read_server_delta(name) is not None
    assert (await b.client.post('/api/owned-credential-call')).status_code == 200
    assert b.peer.resource.witness == ['owned-effect']




async def test_changing_oauth_configuration_recreates_both_shared_generation_hosts(oauth_runtime):
    b = oauth_runtime
    original = b.feature._oauth_host
    settings = await b.feature.get_config()
    settings['apps']['max_views'] = 16
    await b.feature.set_config(settings)
    assert original.retired
    assert b.feature._oauth_host is not original and not b.feature._oauth_maintenance.done()
    result = await b.client.get('/api/mcp/oauth/connections')
    assert result.status_code == 200, result.text


async def test_invalid_oauth_settings_cannot_retire_a_current_original_host(oauth_runtime):
    b = oauth_runtime
    original = b.feature._oauth_host
    with pytest.raises(ValidationError):
        await b.feature.set_config({'oauth': {'enabled': True, 'close_seconds': -1}})
    assert b.feature._oauth_host is original and not original.retired
