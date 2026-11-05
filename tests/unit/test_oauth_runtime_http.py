"""Real Core routes, three TLS origins, native consent, dispatch and restart."""

import asyncio
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
from kestrel_sovereign.security.capability_authority import HostCapabilityAccessDenied

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


async def complete_authorization(b, *, headers=None):
    response = await b.client.post('/api/mcp/oauth/authorizations', json={
        'server_url': b.peer.selection.server_url, 'scopes': ['read']}, headers=headers)
    assert response.status_code == 200, response.text
    started = response.json()
    state = parse_qs(urlsplit(started['authorization_url']).query)['state'][0]
    callback = await approve(b.peer, started | {'state': state})
    result = await b.client.post('/api/mcp/oauth/authorizations/' + started['operation_id'] + '/callback', json=callback,
        headers=headers)
    return result


async def authorize(b, *, headers=None):
    result = await complete_authorization(b, headers=headers)
    assert result.status_code == 200, result.text
    assert result.json()['state'] == 'authorized'
    return result.json()['connection_id']


async def connect(b, name, *, refresh=False, headers=None):
    result = await b.client.post('/api/mcp/oauth/connections/' + name + '/connect', json={'refresh': refresh}, headers=headers)
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
    forbidden_attempts = []
    def forbidden(*args, **kwargs):
        forbidden_attempts.append(True)
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
    assert forbidden_attempts == []
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


async def test_changed_native_client_identity_requires_consent_before_any_restored_credential_use(
    oauth_runtime, monkeypatch,
):
    b = oauth_runtime
    name = await authorize(b)
    await connect(b, name)
    await b.agent._unregister_feature_runtime(b.feature, unload=False)
    before = list(b.peer.resource.requests), list(b.peer.requests)
    b.app.state.mcp_oauth_policy = MCPOAuthHostPolicy(console_origin='https://changed-console.example',
        network_seconds=2.0, operation_seconds=10.0)
    forbidden_attempts = []

    def forbidden(*args, **kwargs):
        forbidden_attempts.append(True)
        raise AssertionError('A changed OAuth client identity must not resolve or decrypt the old grant')

    with monkeypatch.context() as guard:
        guard.setattr(socket, 'getaddrinfo', forbidden)
        guard.setattr(OAuthGrantStore, '_cipher', forbidden)
        await b.agent._activate_feature_runtime(b.feature)
        b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
        rows = (await b.client.get('/api/mcp/oauth/connections')).json()['connections']
        assert rows[0]['state'] == 'reauthorization_required' and rows[0]['connected'] is False
        response = await b.client.post('/api/mcp/oauth/connections/' + name + '/connect', json={'refresh': True})
        assert response.status_code == 503, response.text
    assert (b.peer.resource.requests, b.peer.requests) == before
    assert forbidden_attempts == []
    assert not b.feature._remote_connections
    assert b.handle not in b.agent._direct_tools


async def test_enabled_apps_and_oauth_share_configuration_and_soft_reactivation_generation(
    oauth_runtime, apps_sandbox_url, apps_host_origin,
):
    b = oauth_runtime
    await b.feature.set_config({'apps': {'enabled': True,
        'host': {'sandbox_url': apps_sandbox_url, 'host_origin': apps_host_origin}}})
    original = b.feature._apps_host, b.feature._oauth_host
    tasks = b.feature._apps_maintenance, b.feature._oauth_maintenance
    generation = b.feature._lifecycle_generation
    configuration = await b.feature.get_config()
    configuration['oauth']['max_connections'] += 1
    await b.feature.set_config(configuration)
    assert all(host.retired for host in original) and all(task.done() for task in tasks)
    assert b.feature._lifecycle_generation == generation + 1
    assert b.feature._apps_host is not original[0] and b.feature._oauth_host is not original[1]
    assert not b.feature._apps_maintenance.done() and not b.feature._oauth_maintenance.done()
    current = b.feature._apps_host, b.feature._oauth_host
    await b.agent._unregister_feature_runtime(b.feature, unload=False)
    assert all(host.retired for host in current)
    await b.agent._activate_feature_runtime(b.feature)
    assert b.feature._apps_host is not current[0] and b.feature._oauth_host is not current[1]
    assert (await b.feature.get_config()) == configuration
    assert not b.feature._apps_maintenance.done() and not b.feature._oauth_maintenance.done()
    assert (await b.client.get('/api/mcp/oauth/connections')).status_code == 200


async def test_local_disconnect_and_actual_maintenance_tick_join_one_original_connection(
    oauth_runtime, monkeypatch,
):
    b = oauth_runtime
    await b.feature.set_config({'oauth': {'enabled': True, 'close_seconds': 2.0,
        'maintenance_seconds': 0.01}})
    b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
    name = await authorize(b)
    await connect(b, name)
    maintenance = b.feature._oauth_maintenance
    connection = b.feature._remote_connections[name].connection
    credential = b.runtime._credentials[name]
    original_close, original_retire = connection.close, b.runtime._retire_idle_connection
    entered, observed_tick, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    closes = []

    async def close_original():
        closes.append(asyncio.current_task())
        # Exercise the already-in-progress tick that the former observer missed.
        await observed_tick.wait()
        entered.set()
        await release.wait()
        await original_close()

    async def retire_original(retiring_name, retiring_credential):
        # A tick can already be in progress before close enters its barrier.
        # Observe the original retirement attempt rather than the next tick.
        if (retiring_name == name and retiring_credential is credential
                and asyncio.current_task() is maintenance):
            observed_tick.set()
        await original_retire(retiring_name, retiring_credential)

    monkeypatch.setattr(connection, 'close', close_original)
    monkeypatch.setattr(b.runtime, '_retire_idle_connection', retire_original)
    disconnect = asyncio.create_task(b.client.delete('/api/mcp/oauth/connections/' + name))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        await asyncio.wait_for(observed_tick.wait(), 2)
        await asyncio.sleep(0)
        release.set()
        response = await asyncio.wait_for(disconnect, 5)
        await asyncio.sleep(0.03)
        assert response.status_code == 200, response.text
        assert len(closes) == 1
        assert not maintenance.done() and not b.host.retired
        assert not b.runtime.has_owners and not b.feature._remote_connections
        assert (await b.client.get('/api/mcp/oauth/connections')).status_code == 200
    finally:
        release.set()
        await asyncio.gather(disconnect, return_exceptions=True)
        failure = maintenance.exception() if maintenance.done() and not maintenance.cancelled() else None
        try:
            await b.feature._close_oauth()
        except KeyError as error:
            # Preserve a clean fixture after reproducing this exact original
            # maintenance failure; the assertions above must still fail.
            assert error is failure


async def test_failed_native_exchange_retires_its_physical_owner_before_reconfiguration(oauth_runtime):
    b = oauth_runtime
    b.peer.options['token_error_status'] = 503
    result = await complete_authorization(b)
    assert result.status_code == 503, result.text
    assert b.peer.requests.count(('POST', '/token')) == 1
    assert not b.runtime.has_owners
    assert (await b.host.database.fetch_one('SELECT state FROM mcp_oauth_credential_slots'))[0] == 'exchanging'
    original = b.host
    await b.feature.set_config({'oauth': {'enabled': False}})
    assert original.retired and b.feature._oauth_host is None
    assert not b.peer.resource.witness


async def test_stale_maintenance_snapshot_cannot_retire_a_reconnected_native_owner(oauth_runtime, monkeypatch):
    b = oauth_runtime
    await b.feature.set_config({'oauth': {'enabled': True, 'close_seconds': 2.0,
        'maintenance_seconds': 60.0}})
    b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
    first = await authorize(b)
    await connect(b, first)
    foreign = {'X-API-Key': '', 'Authorization': 'Bearer ' + _create_jwt(b.alice)}
    second = await authorize(b, headers=foreign)
    await connect(b, second, headers=foreign)
    old = b.runtime._credentials[second]
    original_close = b.feature._remote_connections[first].connection.close
    entered, release = asyncio.Event(), asyncio.Event()

    async def close_original():
        entered.set()
        await release.wait()
        await original_close()

    monkeypatch.setattr(b.feature._remote_connections[first].connection, 'close', close_original)
    b.runtime._credentials[first].withdraw('reauthorization_required')
    old.withdraw('reauthorization_required')
    retiring = asyncio.create_task(b.runtime.maintain())
    try:
        await asyncio.wait_for(entered.wait(), 2)
        await connect(b, second, headers=foreign)
        current = b.feature._remote_connections[second]
        credential = b.runtime._credentials[second]
        assert credential is not old
        release.set()
        await asyncio.wait_for(retiring, 5)
        assert b.feature._remote_connections[second] is current
        assert current.connection.is_connected and not credential.retired
        assert b.runtime._credentials[second] is credential
        assert (await b.client.post('/api/owned-credential-call', headers=foreign)).status_code == 200
        assert b.callers[-1].identity == b.alice
        assert b.peer.resource.witness == ['owned-effect']
        assert b.peer.requests.count(('GET', '/authorize')) == 2
        assert b.peer.requests.count(('POST', '/token')) == 2
    finally:
        release.set()
        await asyncio.gather(retiring, return_exceptions=True)


async def test_soft_deactivation_joins_a_cancelled_native_maintenance_retirement(oauth_runtime, monkeypatch):
    b = oauth_runtime
    await b.feature.set_config({'oauth': {'enabled': True, 'close_seconds': 2.0,
        'maintenance_seconds': 0.01}})
    b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
    name = await authorize(b)
    await connect(b, name)
    old_host, maintenance = b.host, b.feature._oauth_maintenance
    connection = b.feature._remote_connections[name].connection
    original_close = connection.close
    entered, release = asyncio.Event(), asyncio.Event()

    async def close_original():
        entered.set()
        await release.wait()
        await original_close()

    monkeypatch.setattr(connection, 'close', close_original)
    old_host.withdraw()
    closing = None
    try:
        await asyncio.wait_for(entered.wait(), 2)
        closing = asyncio.create_task(b.agent._unregister_feature_runtime(b.feature, unload=False))
        await asyncio.sleep(0)
        release.set()
        await asyncio.wait_for(closing, 5)
        assert maintenance.done() and old_host.retired
        assert not connection.is_connected and not b.feature._remote_connections
        await b.agent._activate_feature_runtime(b.feature)
        assert b.feature._oauth_host is not old_host
        assert not b.feature._oauth_host.retired and not b.feature._oauth_maintenance.done()
        assert not b.feature._remote_connections
        assert (await b.client.get('/api/mcp/oauth/connections')).status_code == 200
    finally:
        release.set()
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)


async def test_shutdown_cannot_hold_the_feature_gate_over_an_admitted_native_connect(oauth_runtime, monkeypatch):
    import kestrel_feature_mcp.feature as feature_module

    b = oauth_runtime
    name = await authorize(b)
    old_host = b.host
    resolved, release = asyncio.Event(), asyncio.Event()
    original_resolver = feature_module.assert_safe_url

    async def resolve_original(*args, **kwargs):
        endpoint = await original_resolver(*args, **kwargs)
        resolved.set()
        await release.wait()
        return endpoint

    monkeypatch.setattr(feature_module, 'assert_safe_url', resolve_original)
    before = list(b.peer.resource.requests)
    connecting = asyncio.create_task(b.client.post('/api/mcp/oauth/connections/' + name + '/connect', json={}))
    closing = None
    try:
        await asyncio.wait_for(resolved.wait(), 2)
        closing = asyncio.create_task(b.agent._unregister_feature_runtime(b.feature, unload=False))
        async with asyncio.timeout(2):
            while not b.feature._closing or not b.feature._lifecycle_transition.locked():
                await asyncio.sleep(0)
        release.set()
        _, pending = await asyncio.wait({connecting, closing}, timeout=3)
        assert not pending, 'Shutdown and the admitted connection must settle without cancelling either observer'
        closing.result()
        if connecting.exception() is not None:
            assert isinstance(connecting.exception(), HostCapabilityAccessDenied)
        else:
            assert connecting.result().status_code in {403, 503}
        assert old_host.retired and not b.feature._remote_connections
        assert b.peer.resource.requests == before
    finally:
        release.set()
        if not connecting.done():
            connecting.cancel()
        await asyncio.gather(connecting, return_exceptions=True)
        if closing is not None:
            await asyncio.gather(closing, return_exceptions=True)


async def test_physically_retired_metadata_does_not_consume_a_native_connection_slot(oauth_runtime):
    b = oauth_runtime
    await b.feature.set_config({'oauth': {'enabled': True, 'close_seconds': 2.0,
        'maintenance_seconds': 60.0, 'max_connections': 1, 'max_connections_per_principal': 1}})
    b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
    first = await authorize(b)
    await connect(b, first)
    original = b.runtime._credentials[first]
    original.withdraw('reauthorization_required')
    await b.runtime.maintain()
    assert original.retired and not b.runtime.has_owners
    assert first not in b.feature._remote_connections
    foreign = {'X-API-Key': '', 'Authorization': 'Bearer ' + _create_jwt(b.alice)}
    second = await authorize(b, headers=foreign)
    await connect(b, second, headers=foreign)
    assert b.feature._remote_connections[second].connection.is_connected
    assert (await b.client.post('/api/owned-credential-call', headers=foreign)).status_code == 200
    assert b.callers[-1].identity == b.alice and b.peer.resource.witness == ['owned-effect']


async def test_unacknowledged_native_close_keeps_custody_and_capacity_until_original_retry(oauth_runtime, monkeypatch):
    b = oauth_runtime
    await b.feature.set_config({'oauth': {'enabled': True, 'close_seconds': 2.0,
        'maintenance_seconds': 60.0, 'max_connections': 1, 'max_connections_per_principal': 1}})
    b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
    first = await authorize(b)
    await connect(b, first)
    record = b.feature._remote_connections[first]
    credential = b.runtime._credentials[first]
    original_close = record.connection.close

    async def lost_acknowledgement():
        await original_close()
        raise TimeoutError('Original physical close acknowledgement was lost')

    credential.withdraw('reauthorization_required')
    with monkeypatch.context() as control:
        control.setattr(record.connection, 'close', lost_acknowledgement)
        with pytest.raises(TimeoutError, match='acknowledgement'):
            await b.runtime.maintain()
        assert credential.retired and b.runtime.has_owners
        assert b.feature._remote_connections[first] is record
        foreign = {'X-API-Key': '', 'Authorization': 'Bearer ' + _create_jwt(b.alice)}
        second = await authorize(b, headers=foreign)
        before = list(b.peer.resource.requests)
        result = await b.client.post('/api/mcp/oauth/connections/' + second + '/connect', json={}, headers=foreign)
        assert result.status_code == 503 and b.peer.resource.requests == before
    await b.runtime.maintain()
    assert first not in b.feature._remote_connections and not b.runtime.has_owners
    await connect(b, second, headers=foreign)
    assert b.feature._remote_connections[second].connection.is_connected


@pytest.mark.parametrize('status', [401, 403])
async def test_recent_resource_rejection_survives_original_close_without_retaining_capacity(
    oauth_runtime, status,
):
    b = oauth_runtime
    await b.feature.set_config({'oauth': {'enabled': True, 'close_seconds': 2.0, 'maintenance_seconds': 60.0}})
    b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
    name = await authorize(b)
    await connect(b, name)
    credential = b.runtime._credentials[name]
    b.peer.resource.settings['http_status'] = status
    await b.client.post('/api/owned-credential-call')
    assert credential.withdrawal_reason == 'resource_rejected'
    assert b.peer.resource.witness == []
    await b.runtime.maintain()
    assert not b.runtime.has_owners and not b.feature._remote_connections
    rows = (await b.client.get('/api/mcp/oauth/connections')).json()['connections']
    assert rows[0]['state'] == 'resource_rejected' and not rows[0]['connected']
    foreign = {'X-API-Key': '', 'Authorization': 'Bearer ' + _create_jwt(b.alice)}
    assert (await b.client.get('/api/mcp/oauth/connections', headers=foreign)).json()['connections'] == []
    assert (await b.client.delete('/api/mcp/oauth/connections/' + name, headers=foreign)).status_code == 503
    rows = (await b.client.get('/api/mcp/oauth/connections')).json()['connections']
    assert rows[0]['state'] == 'resource_rejected'
    b.peer.resource.settings['http_status'] = None
    await connect(b, name, refresh=True)
    assert not b.runtime._resource_rejections
    assert b.peer.requests.count(('POST', '/token')) == 2
    assert (await b.client.post('/api/owned-credential-call')).status_code == 200
    assert b.peer.resource.witness == ['owned-effect']
    await b.client.delete('/api/mcp/oauth/connections/' + name)
    assert not b.runtime._resource_rejections and not b.runtime.has_owners


async def test_recent_rejection_history_is_bounded_and_excluded_from_connection_capacity(oauth_runtime):
    b = oauth_runtime
    await b.feature.set_config({'oauth': {'enabled': True, 'close_seconds': 2.0, 'maintenance_seconds': 60.0,
        'max_status_entries': 1, 'max_connections': 1, 'max_connections_per_principal': 1}})
    b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
    foreign = {'X-API-Key': '', 'Authorization': 'Bearer ' + _create_jwt(b.alice)}
    names = []
    for headers in [None, foreign]:
        b.peer.resource.settings['http_status'] = None
        name = await authorize(b, headers=headers)
        names.append(name)
        await connect(b, name, headers=headers)
        b.peer.resource.settings['http_status'] = 401
        await b.client.post('/api/owned-credential-call', headers=headers)
        await b.runtime.maintain()
        assert not b.runtime.has_owners and not b.feature._remote_connections
        assert len(b.runtime._resource_rejections) == 1
    assert list(b.runtime._resource_rejections) == [names[-1]]
    assert (await b.client.get('/api/mcp/oauth/connections', headers=foreign)).json()['connections'][0]['state'] == 'resource_rejected'
    assert (await b.client.get('/api/mcp/oauth/connections')).json()['connections'][0]['state'] == 'authorized'
    assert b.peer.resource.witness == []
    await b.client.delete('/api/mcp/oauth/connections/' + names[-1], headers=foreign)
    assert not b.runtime._resource_rejections


async def test_resource_rejection_projection_defers_to_durable_state_and_revision(oauth_runtime):
    b = oauth_runtime
    await b.feature.set_config({'oauth': {'enabled': True, 'close_seconds': 2.0, 'maintenance_seconds': 60.0}})
    b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
    name = await authorize(b)
    await connect(b, name)
    credential = b.runtime._credentials[name]
    snapshot = credential.snapshot
    b.peer.resource.settings['http_status'] = 401
    await b.client.post('/api/owned-credential-call')
    await b.runtime.maintain()
    assert (await b.client.get('/api/mcp/oauth/connections')).json()['connections'][0]['state'] == 'resource_rejected'
    # Pure metadata projections: a diagnostic grants no authority and cannot
    # override a different committed revision or an unknown durable outcome.
    replacement = replace(snapshot, revision='different-committed-grant-revision')
    assert b.runtime._status(replacement, credential.budgets)['state'] == 'authorized'
    for state, expected in [('exchanging', 'outcome_unknown'), ('refreshing', 'refresh_unknown'),
            ('revoked', 'revoked')]:
        metadata = replace(snapshot, state=state, reason='local' if state == 'revoked' else None)
        assert b.runtime._status(metadata, credential.budgets)['state'] == expected
    assert b.peer.resource.witness == [] and not b.runtime.has_owners


@pytest.mark.parametrize('changed', ['revision', 'binding'])
async def test_status_requires_the_current_original_grant_snapshot(oauth_runtime, changed):
    b = oauth_runtime
    name = await authorize(b)
    await connect(b, name)
    credential = b.runtime._credentials[name]
    # Pure status projection of metadata changed by another durable owner.
    metadata = replace(credential.snapshot, revision='different-committed-revision') if changed == 'revision' else replace(
        credential.snapshot, binding=replace(credential.snapshot.binding, scopes=frozenset({'read', 'write'})))
    status = b.runtime._status(metadata, credential.budgets)
    assert status['state'] == 'authorized' and not status['connected']
    assert b.peer.resource.witness == []
