"""The original Core custody and grant select one native HTTP observation."""

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import socket
import time
from urllib.parse import urlsplit

import pytest
from mcp import types

from kestrel_sdk.resources import ResourceConflict, ResourceError
from kestrel_sovereign.security.request_auth import current_request_authentication
from kestrel_feature_mcp.oauth_grants import OAuthGrantStore, OAuthRefreshPending
from kestrel_feature_mcp.oauth_policy import GrantRejected
from tests.unit.test_oauth_acceptance_http import oauth_peers as oauth_peers
from tests.unit.test_oauth_credentials import credential_boundary as credential_boundary
from tests.unit.test_oauth_runtime_http import authorize, connect, oauth_runtime as oauth_runtime
from tests.unit.test_tasks_native_peer import NativeTasksPeer


pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.timeout(30),
    pytest.mark.parametrize('mcp_http_server', [{'tls': True, 'oauth': {},
        'extensions': [NativeTasksPeer()]}], indirect=True),
    pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'refresh': True}], indirect=True),
]


async def start_task(b, *, clock=None, schema=None, operation_seconds=None, task_policy=None):
    if operation_seconds is not None:
        b.app.state.mcp_oauth_policy = b.app.state.mcp_oauth_policy.model_copy(
            update={'operation_seconds': operation_seconds})
    b.agent._mcp_oauth_host_policy = b.app.state.mcp_oauth_policy
    await b.feature.set_config({'oauth': {'enabled': True, 'close_seconds': 2.0,
        'maintenance_seconds': 60.0}, 'inputs': {'enabled': True}})
    b.host, b.runtime = b.feature._oauth_host, b.feature._oauth_runtime
    await b.feature._start_tasks({'maintenance_seconds': 60.0, 'host': task_policy or {}})
    if clock is not None:
        b.feature._input_host.authority.clock = clock
    if schema is not None:
        b.peer.resource.settings['advertised_contract'] = {'output_schema': schema}
    name = await authorize(b)
    await connect(b, name)
    reply = await b.client.post('/api/owned-credential-call')
    assert reply.status_code == 200 and reply.json().get('status') == 'partial', reply.text
    b.task_parts = [part for part in reply.json().get('parts', []) if part['type'] == 'mcp_task']
    old_host = b.feature._task_host
    original, = await old_host.store.list_retained()
    assert original.phase == 'ATTACHED'
    return name, original


@pytest.mark.parametrize('state', [
    'original', 'reauthorized', 'refresh-ok', 'refresh-invalid-grant',
    'refresh-client-error', 'refresh-unknown', 'contract-drift', 'resource-recovery',
    'refresh-foreground', 'refresh-budget', 'revoked-in-flight',
])
async def test_restored_task_observation_uses_only_its_encrypted_original_grant(oauth_runtime, state):
    b = oauth_runtime
    schema = {'type': 'object', 'properties': {'result': {'type': 'integer'}}, 'required': ['result']}
    network_seconds = b.app.state.mcp_oauth_policy.network_seconds
    name, original = await start_task(b, schema=schema if state == 'contract-drift' else None,
        operation_seconds=3 * network_seconds + 1 if state == 'refresh-budget' else None)
    old_host = b.feature._task_host
    peer = b.peer.resource.settings['extensions'][0]
    assert peer.calls == ['started']
    foreground = b.runtime._credentials[name]
    if state not in {'refresh-foreground', 'resource-recovery'}:
        foreground.lease.revoke()
    if state != 'refresh-foreground':
        await b.feature._close_tasks()
        await b.feature._start_tasks({})
        assert old_host.retired
    assert current_request_authentication() is None
    runtime = b.feature._task_runtime
    peer.status = 'completed'
    if state.startswith('refresh-'):
        _, expired = await expire_grant(b, name)
    if state == 'refresh-budget':
        before = list(b.peer.resource.requests), list(b.peer.requests)
        with pytest.raises(ResourceConflict, match='insufficient time'):
            await runtime.observe(original.handle)
        assert (b.peer.resource.requests, b.peer.requests) == before
        actual = await b.store.read(foreground.snapshot.binding)
        assert actual.state == 'active'
        assert (await b.store.read_tokens(actual)).tokens == expired
        assert await runtime.host.store.read_handle(original.handle) == original
        return
    if state == 'revoked-in-flight':
        async def revoke(result):
            snapshot = await b.store.read(foreground.snapshot.binding)
            await b.store.revoke_local(snapshot)
            return result
        peer.before_response = revoke
        with pytest.raises(GrantRejected, match='authorization is unavailable'):
            await runtime.observe(original.handle)
        retained = await runtime.host.store.read_handle(original.handle)
        assert retained.phase == 'ATTACHED' and retained.envelope == original.envelope
        assert retained.local['observation_block']['reason'] == 'authorization_revoked'
        assert peer.calls == ['started', 'get']
        return
    if state in {'refresh-invalid-grant', 'refresh-client-error', 'refresh-unknown'}:
        status, code, grant_state = {
            'refresh-invalid-grant': (400, 'invalid_grant', 'revoked'),
            'refresh-client-error': (400, 'invalid_scope', 'active'),
            'refresh-unknown': (503, 'invalid_grant', 'refreshing'),
        }[state]
        b.peer.options.update(token_error_status=status, token_error_code=code)
        before = len(b.peer.resource.requests)
        exchanges = b.peer.requests.count(('POST', '/token'))
        expected_error = OAuthRefreshPending if state == 'refresh-unknown' else GrantRejected
        with pytest.raises(expected_error) as refused:
            await runtime.observe(original.handle)
        assert 'owned-sensitive-AS-error-marker' not in str(refused.value)
        assert b.peer.requests.count(('POST', '/token')) == exchanges + 1
        (resource_scope, body), = b.peer.resource.requests[before:]
        assert resource_scope['method'] == 'GET'
        assert resource_scope['path'] == urlsplit(b.peer.selection.protected_metadata).path
        assert b'authorization' not in dict(resource_scope['headers']) and not body
        assert peer.calls == ['started']
        actual = await b.store.read(foreground.snapshot.binding)
        assert actual.state == grant_state
        assert actual.authorization_identity == original.binding.authorization_id
        if state == 'refresh-client-error':
            assert (await b.store.read_tokens(actual)).tokens == expired
        if state == 'refresh-invalid-grant':
            assert actual.reason == 'refresh_rejected'
        retained = await runtime.host.store.read_handle(original.handle)
        assert retained.phase == 'ATTACHED' and retained.envelope == original.envelope
        if state == 'refresh-unknown':
            assert retained.local['observation_block'] is None
            exchanges = list(b.peer.resource.requests), list(b.peer.requests)
            with pytest.raises(OAuthRefreshPending):
                await runtime.observe(original.handle)
            assert (b.peer.resource.requests, b.peer.requests) == exchanges
        else:
            assert retained.local['observation_block']['reason'] == (
                'authorization_revoked' if state == 'refresh-invalid-grant' else 'credential_unavailable')
        return
    if state == 'reauthorized':
        snapshot = await b.store.read(foreground.snapshot.binding)
        await b.store.revoke_local(snapshot)
        assert await authorize(b) == name
        before = len(b.peer.resource.requests)
        with pytest.raises(GrantRejected, match='original MCP Task OAuth authorization'):
            await runtime.observe(original.handle)
        assert len(b.peer.resource.requests) == before and peer.calls == ['started']
        retained = await runtime.host.store.read_handle(original.handle)
        assert retained.phase == 'ATTACHED' and retained.envelope == original.envelope
        assert retained.local['observation_block']['reason'] == 'authorization_changed'
    else:
        if state == 'resource-recovery':
            wall_clock = b.host.authority.clock
            b.host.authority.clock = lambda: wall_clock() - timedelta(minutes=5)
            b.peer.resource.settings['http_status'] = 401
            with pytest.raises(ExceptionGroup) as denied:
                await runtime.observe(original.handle)
            from kestrel_feature_mcp.oauth_policy import ResourceGrantRejected

            assert denied.value.subgroup(ResourceGrantRejected) is not None
            assert not runtime.has_observation_owners
            assert b.runtime._credentials[name] is foreground and foreground.withdrawal_reason is None
            assert (await b.store.read(foreground.snapshot.binding)).state == 'active'
            retained = await runtime.host.store.read_handle(original.handle)
            assert retained.phase == 'ATTACHED' and retained.envelope == original.envelope
            assert retained.local['observation_block']['reason'] == 'resource_rejected'
            del b.peer.resource.settings['http_status']
            before = len(b.peer.resource.requests)
            with pytest.raises(ResourceConflict, match='blocked'):
                await runtime.observe(original.handle)
            assert len(b.peer.resource.requests) == before
            b.host.authority.clock = wall_clock
            await connect(b, name)
            foreground = b.runtime._credentials[name]
        exchanges = b.peer.requests.count(('POST', '/token'))
        retained = await runtime.observe(original.handle)
        assert retained.phase == 'SETTLED'
        assert retained.observation['status'] == 'completed'
        assert retained.observation['result']['structuredContent'] == {'result': 'actual deferred result'}
        assert retained.local == {'observation_block': None, 'poll_not_before': None,
            'withheld': 'contract_drift' if state == 'contract-drift' else None}
        assert peer.calls == ['started', 'get']
        reads = [(scope, json.loads(body)) for scope, body in b.peer.resource.requests
            if body and json.loads(body).get('method') == 'tasks/get']
        (scope, message), = reads
        assert dict(scope['headers'])[b'mcp-name'].decode() == peer.task_id
        capabilities = message['params']['_meta']['io.modelcontextprotocol/clientCapabilities']
        assert set(capabilities['extensions']) == {peer.identifier}
        assert not capabilities.get('elicitation')
        assert b.runtime._credentials[name] is foreground
        assert set(b.feature._remote_connections) == {name}
        assert not runtime.has_observation_owners
        refreshed = state in {'refresh-ok', 'refresh-foreground'}
        assert b.peer.requests.count(('POST', '/token')) == exchanges + refreshed
        if state == 'refresh-foreground':
            peer.return_ordinary = True
            response = await b.client.post('/api/owned-credential-call')
            assert response.status_code == 200 and response.json().get('status') == 'ok', response.text
            assert b.runtime._credentials[name] is foreground
            assert foreground.withdrawal_reason is None
            assert foreground.authorization_identity == original.binding.authorization_id
            assert b.peer.requests.count(('POST', '/token')) == exchanges + 1


async def expire_grant(b, name):
    foreground = b.runtime._credentials[name]
    active = await b.store.read_tokens(foreground.snapshot)
    expired = replace(active.tokens, expires_at=time.time() - 60)
    claim = await b.store.begin_refresh(active)
    await b.store.finish_refresh(claim, expired)
    return active.binding, expired


@pytest.mark.parametrize('termination', ['cancelled', 'withdrawn'])
async def test_unsent_refresh_claim_retires_under_original_owner(oauth_runtime, monkeypatch, termination):
    b = oauth_runtime
    name, original = await start_task(b)
    binding, tokens = await expire_grant(b, name)
    entered, release = asyncio.Event(), asyncio.Event()
    real_begin = OAuthGrantStore.begin_refresh

    async def committed_claim(store, snapshot):
        claim = await real_begin(store, snapshot)
        entered.set()
        await release.wait()
        return claim

    monkeypatch.setattr(OAuthGrantStore, 'begin_refresh', committed_claim)
    runtime = b.feature._task_runtime
    exchanges = b.peer.requests.count(('POST', '/token'))
    read = asyncio.create_task(runtime.observe(original.handle))
    try:
        await asyncio.wait_for(entered.wait(), 5)
        assert (await b.store.read(binding)).state == 'refreshing'
        if termination == 'cancelled':
            read.cancel()
        else:
            runtime.host.withdraw()
        release.set()
        with pytest.raises(asyncio.CancelledError if termination == 'cancelled' else ResourceError):
            await read
    finally:
        release.set()
        await asyncio.gather(read, return_exceptions=True)

    restored = await b.store.read(binding)
    assert restored.state == 'active'
    assert restored.authorization_identity == original.binding.authorization_id
    assert (await b.store.read_tokens(restored)).tokens == tokens
    assert b.peer.requests.count(('POST', '/token')) == exchanges


async def test_refresh_attempt_is_paced_before_authorization_discovery(oauth_runtime):
    b = oauth_runtime
    peer = b.peer.resource.settings['extensions'][0]
    peer.poll_interval_ms = 5000
    now = [datetime(2026, 11, 4, 0, 0, 2, tzinfo=UTC)]
    name, original = await start_task(b, clock=lambda: now[0])
    binding, _ = await expire_grant(b, name)
    runtime = b.feature._task_runtime
    now[0] += timedelta(seconds=5)
    requests = []

    async def inspect_attempt():
        current = await runtime.host.store.read_handle(original.handle)
        requests.append(current.local['poll_not_before'])
        raise TimeoutError('Owned issuer discovery read interrupted')

    b.peer.options['before_metadata'] = inspect_attempt
    exchanges = b.peer.requests.count(('POST', '/token'))
    await runtime.maintain(observe=True)
    await runtime.maintain(observe=True)
    await runtime.maintain(observe=True)
    assert requests == [now[0].timestamp() + 5]
    assert (await b.store.read(binding)).state == 'active'
    assert b.peer.requests.count(('POST', '/token')) == exchanges
    assert peer.calls == ['started']


@pytest.mark.parametrize('outcome', ['rejected', 'rotated'])
async def test_definite_token_outcome_is_retained_after_original_task_withdrawal(oauth_runtime, outcome):
    b = oauth_runtime
    name, original = await start_task(b)
    binding, _ = await expire_grant(b, name)
    runtime = b.feature._task_runtime

    async def withdraw():
        runtime.host.withdraw()

    b.peer.options['before_token'] = withdraw
    if outcome == 'rejected':
        b.peer.options.update(token_error_status=400, token_error_code='invalid_grant')
    else:
        b.peer.options['refresh_rotate'] = True
    exchanges = b.peer.requests.count(('POST', '/token'))
    with pytest.raises(ResourceError):
        await runtime.observe(original.handle)
    retained = await b.store.read(binding)
    if outcome == 'rejected':
        assert retained.state == 'revoked' and retained.reason == 'refresh_rejected'
    else:
        assert retained.state == 'active'
        tokens = (await b.store.read_tokens(retained)).tokens
        assert tokens.refresh_token == 'native-fixture-rotated' and not tokens.is_expired(time.time())
    assert retained.authorization_identity == original.binding.authorization_id
    assert b.peer.requests.count(('POST', '/token')) == exchanges + 1


async def test_dns_failure_is_paced_without_withdrawing_task_host(oauth_runtime, monkeypatch):
    b = oauth_runtime
    peer = b.peer.resource.settings['extensions'][0]
    now = [datetime(2026, 11, 4, 0, 0, 2, tzinfo=UTC)]
    _, original = await start_task(b, clock=lambda: now[0])
    runtime = b.feature._task_runtime
    now[0] += timedelta(seconds=1)
    real_dns = socket.getaddrinfo
    calls = []

    def unreachable(host, port, *args, **kwargs):
        if host == 'remote.example':
            calls.append(host)
            raise socket.gaierror(socket.EAI_AGAIN, 'Owned resolver temporarily unavailable')
        return real_dns(host, port, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(socket, 'getaddrinfo', unreachable)
        await runtime.maintain(observe=True)
        await runtime.maintain(observe=True)
        await runtime.maintain(observe=True)
    assert calls == ['remote.example'] and peer.calls == ['started']
    retained = await runtime.host.store.read_handle(original.handle)
    assert retained.local['poll_not_before'] == now[0].timestamp() + 1
    assert retained.local['observation_block'] is None
    runtime.host.require_current()
    now[0] += timedelta(seconds=1)
    await runtime.maintain(observe=True)
    await runtime.maintain(observe=True)
    assert peer.calls == ['started', 'get']


@pytest.mark.parametrize('receipt', [
    {'access_token': 'x' * 17000}, {'access_token': 'invalid\u0000fixture-token'},
    {'expires_in': 10 ** 400},
    {'access_token': 'a\ud800b'}, {'refresh_token': 'r\udfffs'},
], ids=['oversized-token', 'control-character', 'unrepresentable-expiry',
        'surrogate-access-token', 'surrogate-refresh-token'])
async def test_invalid_successful_refresh_does_not_withdraw_task_host(oauth_runtime, receipt):
    b = oauth_runtime
    peer = b.peer.resource.settings['extensions'][0]
    now = [datetime(2026, 11, 4, 0, 0, 2, tzinfo=UTC)]
    name, original = await start_task(b, clock=lambda: now[0])
    binding, _ = await expire_grant(b, name)
    runtime = b.feature._task_runtime
    b.peer.options['refresh_receipt_fields'] = receipt
    exchanges = b.peer.requests.count(('POST', '/token'))
    now[0] += timedelta(seconds=1)
    await runtime.maintain(observe=True)
    await runtime.maintain(observe=True)
    await runtime.maintain(observe=True)
    assert b.peer.requests.count(('POST', '/token')) == exchanges + 1
    assert (await b.store.read(binding)).state == 'refreshing'
    retained = await runtime.host.store.read_handle(original.handle)
    assert retained.local['poll_not_before'] == now[0].timestamp() + 1
    assert retained.local['observation_block'] is None
    assert peer.calls == ['started']
    runtime.host.require_current()


@pytest.mark.parametrize('case', ['other-task', 'too-large'])
async def test_invalid_native_observation_does_not_withdraw_task_host(oauth_runtime, case):
    b = oauth_runtime
    peer = b.peer.resource.settings['extensions'][0]
    now = [datetime(2026, 11, 4, 0, 0, 2, tzinfo=UTC)]
    _, original = await start_task(b, clock=lambda: now[0], task_policy={
        'max_active': 1, 'max_payload_bytes': 32768, 'max_native_claim_bytes': 4096,
        'observation_reserve_bytes': 4096})
    runtime = b.feature._task_runtime
    peer.status = 'completed'

    async def invalid(result):
        if case == 'other-task':
            result['taskId'] = 'another-native-task'
        else:
            result['result']['structuredContent']['result'] = 'x' * 65536
        return result

    peer.before_response = invalid
    now[0] += timedelta(seconds=1)
    await runtime.maintain(observe=True)
    current = await runtime.host.store.read_handle(original.handle)
    assert current.phase == 'ATTACHED' and current.envelope == original.envelope
    assert current.local['observation_block']['reason'] == 'remote_result_unusable'
    assert peer.calls == ['started', 'get']
    runtime.host.require_current()
    await runtime.maintain(observe=True)
    await runtime.maintain(observe=True)
    peer.return_ordinary = True
    response = await b.client.post('/api/owned-credential-call')
    assert response.status_code == 200 and response.json().get('status') == 'ok', response.text


@pytest.mark.parametrize('case', [
    'recursive-value', 'deep-schema', 'invalid-pointer', 'oversized-schema-regex',
    'oversized-value-regex', 'invalid-referenced-divisor', 'invalid-referenced-pattern',
    'invalid-referenced-type', 'unknown-referenced-type', 'invalid-referenced-properties',
])
async def test_schema_validation_limits_withhold_the_result_without_withdrawing_host(oauth_runtime, case):
    b = oauth_runtime
    peer = b.peer.resource.settings['extensions'][0]
    value = {}
    if case == 'recursive-value':
        schema = {'type': 'object', 'properties': {'a': {'allOf': [
            {'allOf': [{'$ref': '#'}]},
        ]}}}
        for _ in range(140):
            value = {'a': value}
    elif case == 'deep-schema':
        schema = {'type': 'object'}
        for _ in range(90):
            schema = {'allOf': [schema]}
    elif case == 'invalid-pointer':
        schema = {'type': 'object', '$ref': '#/allOf/x', 'allOf': [{}]}
    elif case == 'oversized-schema-regex':
        schema = {'type': 'object', 'properties': {'a': {'pattern': 'a{4294967295}'}}}
    elif case == 'oversized-value-regex':
        schema = {'type': 'object', 'properties': {'a': {'format': 'regex'}}}
        value = {'a': 'a{4294967295}'}
    else:
        referenced_schema, value = {
            'invalid-referenced-divisor': ({'multipleOf': 0}, {'a': 1}),
            'invalid-referenced-pattern': ({'pattern': '('}, {'a': 'value'}),
            'invalid-referenced-type': ({'type': 5}, {'a': 'value'}),
            'unknown-referenced-type': ({'type': 'unsupported'}, {'a': 'value'}),
            'invalid-referenced-properties': ({'properties': 5}, {'a': {}}),
        }[case]
        schema = {'type': 'object', 'properties': {'a': {'$ref': '#/extension'}},
            'extension': referenced_schema}
    now = [datetime(2026, 11, 4, 0, 0, 2, tzinfo=UTC)]
    _, original = await start_task(b, clock=lambda: now[0], schema=schema)
    runtime = b.feature._task_runtime

    async def completed(result):
        result['result']['structuredContent'] = value
        return result

    peer.status = 'completed'
    peer.before_response = completed
    now[0] += timedelta(seconds=1)
    await runtime.maintain(observe=True)

    runtime.host.require_current()
    retained = await runtime.host.store.read_handle(original.handle)
    assert retained.phase == 'SETTLED'
    assert retained.local['withheld'] == 'contract_drift'
    assert peer.calls == ['started', 'get']


@pytest.mark.parametrize(('settings', 'methods'), [
    ({'advertised_contract': {'meta': {'ui': 'invalid'}}}, {'tools/list'}),
    ({'duplicate_tools': True}, {'tools/list'}),
    ({'repeat_cursor': True}, {'tools/list'}),
    ({'unsupported_version': True}, {'server/discover'}),
    ({'legacy': True, 'initialize_version': '2099-01-01'}, {'initialize'}),
], ids=['invalid-contract', 'duplicate-tool', 'repeated-cursor', 'unsupported-discover',
    'unsupported-initialize'])
async def test_observation_startup_refusal_preserves_host_and_retries_after_pacing(
    oauth_runtime, settings, methods,
):
    b = oauth_runtime
    peer = b.peer.resource.settings['extensions'][0]
    now = [datetime(2026, 11, 4, 0, 0, 2, tzinfo=UTC)]
    _, original = await start_task(b, clock=lambda: now[0])
    runtime = b.feature._task_runtime
    request_offset = len(b.peer.resource.requests)
    b.peer.resource.settings.update(settings)
    now[0] += timedelta(seconds=1)

    await runtime.maintain(observe=True)

    runtime.host.require_current()
    retained = await runtime.host.store.read_handle(original.handle)
    assert retained.phase == 'ATTACHED' and retained.envelope == original.envelope
    assert retained.local['observation_block'] is None
    assert retained.local['poll_not_before'] == now[0].timestamp() + 1
    sent = {json.loads(body)['method']
            for _, body in b.peer.resource.requests[request_offset:] if body}
    assert methods <= sent and 'tasks/get' not in sent
    assert peer.calls == ['started']
    for key in settings:
        b.peer.resource.settings.pop(key)
    peer.status = 'completed'

    await runtime.maintain(observe=True)
    await runtime.maintain(observe=True)
    assert peer.calls == ['started']
    now[0] += timedelta(seconds=1)
    await runtime.maintain(observe=True)
    await runtime.maintain(observe=True)

    assert (await runtime.host.store.read_handle(original.handle)).phase == 'SETTLED'
    assert peer.calls == ['started', 'get']


@pytest.mark.parametrize('case', ['paced', 'expired', 'expiry-before-poll', 'unlimited', 'not-found'])
async def test_native_observation_pacing_and_remote_availability(oauth_runtime, case):
    b = oauth_runtime
    peer = b.peer.resource.settings['extensions'][0]
    peer.poll_interval_ms = 120_000 if case in {'expiry-before-poll', 'unlimited'} else 5000
    if case == 'unlimited':
        peer.ttl_ms = None
    now = [datetime(2026, 11, 4, 0, 0, 2, tzinfo=UTC)]
    name, original = await start_task(b, clock=lambda: now[0])
    b.runtime._credentials[name].lease.revoke()
    runtime = b.feature._task_runtime
    assert original.local['poll_not_before'] == now[0].timestamp() + peer.poll_interval_ms / 1000

    async def sweep():
        await runtime.maintain(observe=True)
        await runtime.maintain(observe=True)
        return await runtime.host.store.read_handle(original.handle)

    assert await sweep() == original
    assert peer.calls == ['started']
    if case in {'expired', 'expiry-before-poll'}:
        if case == 'expiry-before-poll':
            now[0] += timedelta(seconds=57)
            assert await sweep() == original
            now[0] += timedelta(seconds=1)
            async with b.host.borrow_task_observation(runtime.host, original.handle, scheduled=True) as lease:
                now[0] -= timedelta(seconds=1)
                async with lease.operation():
                    with pytest.raises(ResourceConflict, match='not due for observation'):
                        lease.scheduled_observation_expired()
                now[0] += timedelta(seconds=1)
        else:
            now[0] += timedelta(seconds=60)
        before = len(b.peer.resource.requests)
        expired = await sweep()
        assert expired.phase == 'ATTACHED' and expired.envelope == original.envelope
        block = expired.local['observation_block']
        assert block is not None and block['reason'] == 'remote_expired'
        assert len(b.peer.resource.requests) == before and peer.calls == ['started']
        return
    if case == 'unlimited':
        now[0] += timedelta(seconds=60)
        assert await sweep() == original
        assert peer.calls == ['started']
        now[0] += timedelta(seconds=60)
        peer.status = 'completed'
        assert (await sweep()).phase == 'SETTLED'
        assert peer.calls == ['started', 'get']
        return
    if case == 'not-found':
        peer.reject_code = types.INVALID_PARAMS
    peer.poll_interval_ms = 8000
    now[0] += timedelta(seconds=5)
    current = await sweep()
    if case == 'not-found':
        assert current.phase == 'ATTACHED' and current.envelope == original.envelope
        assert current.local['observation_block']['reason'] == 'remote_unavailable'
        assert sum(json.loads(body).get('method') == 'tasks/get' for _, body in b.peer.resource.requests if body) == 1
        return
    assert peer.calls == ['started', 'get'] and current.local['poll_not_before'] == now[0].timestamp() + 8
    now[0] += timedelta(seconds=7)
    assert await sweep() == current
    assert peer.calls == ['started', 'get']
    peer.status = 'completed'
    now[0] += timedelta(seconds=1)
    complete = await sweep()
    assert complete.phase == 'SETTLED' and complete.local['poll_not_before'] is None
    assert peer.calls == ['started', 'get', 'get']
