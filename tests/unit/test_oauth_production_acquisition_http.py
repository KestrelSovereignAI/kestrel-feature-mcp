"""Official SDK acquisition against independent TLS AS and resource servers.

These tests prove native wire acquisition and encrypted durable intent, not a
vendor grant, Console browser flow, or Core lease authority.
"""

from contextlib import AsyncExitStack
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
from mcp.client.auth import OAuthFlowError
from kestrel_sdk.security.outbound import assert_safe_url, pinned_httpx2_async_transport
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend

from kestrel_feature_mcp.oauth_acquisition import AuthorizationOperation
from kestrel_feature_mcp.oauth_grants import OAuthGrantStore
from kestrel_feature_mcp.oauth_http import BudgetedTransport
from kestrel_feature_mcp.oauth_policy import ClientIdentity, GrantRejected
from tests.unit.test_oauth_acceptance_http import oauth_peers

pytestmark = pytest.mark.parametrize('mcp_http_server', [{'tls': True, 'oauth': {}}], indirect=True)


@pytest.fixture
async def acquisition(oauth_peers, owned_oauth_key, tmp_path):
    selected = oauth_peers.selection
    identity = ClientIdentity(selected.client_id, selected.redirect_uri)
    expected = {'client_id': identity.client_id, 'client_name': 'Kestrel OAuth wire fixture',
        'application_type': 'web', 'redirect_uris': [identity.redirect_uri],
        'grant_types': ['authorization_code', 'refresh_token'], 'response_types': ['code'],
        'token_endpoint_auth_method': 'none'}
    async with AsyncExitStack() as cleanup:
        path = tmp_path / 'production-grants.db'
        db = SQLiteBackend(str(path))
        await db.connect()
        cleanup.push_async_callback(db.close)
        store = OAuthGrantStore(db, 'did:test:production-oauth', max_token_bytes=4096)
        await store.initialize()
        checks = []
        handle = object()
        operation = AuthorizationOperation(handle, store, agent_did=store.agent_did,
            principal_id='native-wire-owner', connection_id='native-wire-connection',
            server_url=selected.server_url, scopes=selected.scopes, identity=identity,
            budgets={'client_document': expected, 'network_seconds': 2, 'response_max_bytes': 65536},
            check=lambda: checks.append('begin-current'), expected=None,
            acknowledge_unknown=False, close_seconds=2)
        cleanup.push_async_callback(operation.retire)
        yield SimpleNamespace(operation=operation, store=store, path=path, checks=checks)


async def approve(peer, started):
    endpoint = await assert_safe_url(started['authorization_url'], allowed_schemes=('https',))
    async with httpx2.AsyncClient(transport=pinned_httpx2_async_transport(endpoint),
            follow_redirects=False, trust_env=False) as browser:
        response = await browser.get(started['authorization_url'])
    assert response.status_code == 302
    returned = response.headers['Location']
    assert returned.split('?', 1)[0] == peer.selection.redirect_uri
    fields = parse_qs(urlsplit(returned).query)
    assert fields['state'] == [started['state']]
    return {key: value[0] for key, value in fields.items()}


async def slot(attempt):
    return await attempt.store.read_slot('native-wire-owner', 'native-wire-connection')


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True},
    {'web_identity': True, 'omit_token_scope': True},
    {'web_identity': True, 'parent_resource': True}], indirect=True)
async def test_actual_native_web_acquisition_commits_intent_before_one_exchange(acquisition, oauth_peers):
    a, peer = acquisition, oauth_peers
    operation = a.operation
    # A second native database owner proves the exchanging intent is committed
    # and visible when the independent AS actually receives the token POST.
    observed = []
    async def before_token():
        other = SQLiteBackend(str(a.path))
        await other.connect()
        try:
            store = OAuthGrantStore(other, a.store.agent_did, max_token_bytes=4096)
            snapshot = await store.read_slot('native-wire-owner', 'native-wire-connection')
            observed.append(snapshot.state)
        finally:
            await other.close()
    peer.options['before_token'] = before_token
    started = await operation.start()
    assert started['handle'] is operation.handle
    assert (await slot(a)).state == 'authorizing'
    assert ('POST', '/token') not in peer.requests
    await operation.complete(await approve(peer, started), lambda: a.checks.append('callback-current'))
    policy, storage = operation.policy, operation.storage
    assert observed == ['exchanging']
    assert peer.requests.count(('POST', '/token')) == 1
    assert storage.claim.state == 'exchanging' and policy.exchange_started and policy.grant_ready
    assert storage.snapshot.state == 'active' and storage.snapshot.tokens is None
    payload = await a.store.read_tokens(storage.snapshot)
    assert payload.tokens.access_token == 'native-fixture-access'
    assert payload.tokens.scopes == frozenset({'read'})
    assert payload.tokens.expires_at > 1_700_000_000
    assert await storage.get_tokens() is None
    assert 'begin-current' in a.checks and 'callback-current' in a.checks
    assert peer.resource.witness == []
    for path in a.path.parent.glob(a.path.name + '*'):
        raw = path.read_bytes()
        assert b'native-fixture-access' not in raw and b'native-fixture-refresh' not in raw


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True}], indirect=True)
@pytest.mark.parametrize('changed', [{'state': 'different-owned-attempt'},
    {'iss': 'https://other-issuer.example'}, {'iss': None}])
async def test_native_sdk_callback_refusal_sends_no_token_post(acquisition, oauth_peers, changed):
    a = acquisition
    started = await a.operation.start()
    callback = await approve(oauth_peers, started)
    callback.update(changed)
    with pytest.raises(OAuthFlowError):
        await a.operation.complete(callback, lambda: None)
    assert oauth_peers.requests.count(('POST', '/token')) == 0
    assert (await slot(a)).state == 'authorizing'
    assert oauth_peers.resource.witness == []


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'overgrant': True}], indirect=True)
async def test_native_overgrant_retains_unknown_intent_without_resource_credential(acquisition, oauth_peers):
    a = acquisition
    started = await a.operation.start()
    with pytest.raises(GrantRejected, match='approved grant'):
        await a.operation.complete(await approve(oauth_peers, started), lambda: None)
    assert oauth_peers.requests.count(('POST', '/token')) == 1
    assert (await slot(a)).state == 'exchanging'
    assert a.operation.storage.snapshot is None and not a.operation.policy.grant_ready
    assert oauth_peers.resource.witness == []


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True}], indirect=True)
async def test_lost_durable_exchange_ack_prevents_token_post_and_replay(acquisition, oauth_peers, monkeypatch):
    a = acquisition
    original = a.store.begin_exchange
    async def unacknowledged(claim):
        await original(claim)
        raise TimeoutError('native commit acknowledgment lost')
    monkeypatch.setattr(a.store, 'begin_exchange', unacknowledged)
    started = await a.operation.start()
    callback = await approve(oauth_peers, started)
    with pytest.raises(TimeoutError):
        await a.operation.complete(callback, lambda: None)
    assert (await slot(a)).state == 'exchanging'
    with pytest.raises(GrantRejected, match='another callback'):
        await a.operation.complete(callback, lambda: None)
    assert oauth_peers.requests.count(('POST', '/token')) == 0


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True}], indirect=True)
async def test_original_acquisition_cancel_physically_joins_without_exchange(acquisition, oauth_peers):
    a = acquisition
    await a.operation.start()
    original = a.operation._task
    await a.operation.retire()
    await a.operation.retire()
    assert a.operation._task is original and original.done() and original.cancelled()
    assert a.operation._transport.transport._transports == {}
    assert a.operation._identity_transport.transport._transports == {}
    assert oauth_peers.requests.count(('POST', '/token')) == 0
    assert (await slot(a)).state == 'authorizing'


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True}], indirect=True)
async def test_original_cimd_transport_is_retained_after_failed_close(acquisition, monkeypatch):
    a = acquisition
    original = BudgetedTransport.aclose
    failed = []
    async def unacknowledged(transport):
        if not failed:
            failed.append(transport)
            raise TimeoutError('original CIMD close observer failed')
        await original(transport)
    monkeypatch.setattr(BudgetedTransport, 'aclose', unacknowledged)
    try:
        with pytest.raises(TimeoutError):
            await a.operation.start()
        assert failed == [a.operation._identity_transport]
        assert a.operation._identity_transport.transport._transports
        await a.operation.retire()
        assert a.operation._identity_transport.transport._transports == {}
        assert await slot(a) is None
    finally:
        # Even a deliberately broken retirement must release this fixture's
        # original TLS socket before its independent server shuts down.
        if a.operation._identity_transport is not None:
            await original(a.operation._identity_transport)


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'token_error_status': 400},
    {'web_identity': True, 'token_error_status': 401},
    {'web_identity': True, 'token_error_status': 503}], indirect=True)
async def test_real_token_error_disposition_is_durable_and_diagnostic_is_content_free(acquisition, oauth_peers):
    a = acquisition
    started = await a.operation.start()
    with pytest.raises(GrantRejected) as caught:
        await a.operation.complete(await approve(oauth_peers, started), lambda: None)
    assert 'owned-sensitive-AS-error-marker' not in str(caught.value)
    assert oauth_peers.requests.count(('POST', '/token')) == 1
    snapshot = await slot(a)
    if oauth_peers.options['token_error_status'] in {400, 401}:
        assert snapshot.state == 'revoked' and snapshot.reason == 'exchange_rejected'
    else:
        assert snapshot.state == 'exchanging'
    assert a.operation.storage.snapshot is None and oauth_peers.resource.witness == []


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True}], indirect=True)
async def test_native_acquisition_task_has_no_ambient_caller_context(acquisition):
    import asyncio
    from contextvars import ContextVar
    marker = ContextVar('owned-caller-authority-marker', default=None)
    owner = asyncio.current_task()
    observations = []
    def check():
        observations.append((asyncio.current_task() is owner, marker.get()))
    a = acquisition
    a.operation._phase_check = check
    token = marker.set('original-request')
    try:
        await a.operation.start()
    finally:
        marker.reset(token)
    assert (True, 'original-request') in observations
    assert (False, None) in observations
    assert (False, 'original-request') not in observations


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'stall_metadata': True},
    {'web_identity': True, 'stall_token': True}], indirect=True)
async def test_withdrawn_worker_does_not_cancel_the_original_http_observer(acquisition, oauth_peers):
    import asyncio
    a, peer = acquisition, oauth_peers
    if peer.options.get('stall_metadata'):
        observer = asyncio.create_task(a.operation.start())
        expected = ('GET', '/.well-known/oauth-authorization-server')
    else:
        started = await a.operation.start()
        callback = await approve(peer, started)
        observer = asyncio.create_task(a.operation.complete(callback, lambda: None))
        expected = ('POST', '/token')
    try:
        async with asyncio.timeout(2):
            while expected not in peer.requests:
                await asyncio.sleep(0.001)
        a.operation.withdraw()
        with pytest.raises(GrantRejected, match='withdrawn'):
            await observer
        assert observer.cancelling() == 0 and not observer.cancelled()
        assert a.operation._task.cancelled()
        snapshot = await slot(a)
        if peer.options.get('stall_token'):
            assert snapshot.state == 'exchanging'
        else:
            assert snapshot is None
    finally:
        peer.release_body.set()
        a.operation.withdraw()
        await asyncio.gather(observer, return_exceptions=True)


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True}], indirect=True)
async def test_explicit_cancel_abandons_its_original_unexchanged_slot(acquisition):
    a = acquisition
    await a.operation.start()
    await a.operation.cancel(lambda: None)
    await a.operation.cancel(lambda: None)
    snapshot = await slot(a)
    assert snapshot.state == 'revoked' and snapshot.reason == 'abandoned'


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'denied_authenticated_get': 403}], indirect=True)
async def test_post_commit_resource_refusal_preserves_metadata_and_names_its_disposition(acquisition, oauth_peers):
    a = acquisition
    started = await a.operation.start()
    with pytest.raises(GrantRejected) as caught:
        await a.operation.complete(await approve(oauth_peers, started), lambda: None)
    assert type(caught.value).__name__ == 'ResourceGrantRejected'
    assert a.operation.storage.snapshot.state == 'active'
    assert a.operation.storage.snapshot.tokens is None
    assert (await slot(a)).state == 'active'
    assert oauth_peers.requests.count(('POST', '/token')) == 1


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True}], indirect=True)
async def test_post_commit_phase_refusal_keeps_committed_grant_metadata(acquisition, oauth_peers, monkeypatch):
    a = acquisition
    active = []
    original = a.store.complete_authorization
    async def commit(claim, receipt):
        snapshot = await original(claim, receipt)
        active.append(snapshot)
        return snapshot
    def check():
        if active:
            raise GrantRejected('Original request authority expired after commit')
    monkeypatch.setattr(a.store, 'complete_authorization', commit)
    started = await a.operation.start()
    with pytest.raises(GrantRejected, match='after commit'):
        await a.operation.complete(await approve(oauth_peers, started), check)
    assert a.operation.storage.snapshot is not None
    assert a.operation.storage.snapshot.revision == active[0].revision
    assert a.operation.storage.snapshot.tokens is None
    assert not a.operation.policy.grant_ready
    assert (await slot(a)).state == 'active'


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True}], indirect=True)
async def test_failed_identity_retirement_does_not_skip_original_acquisition_transport(acquisition, monkeypatch):
    a = acquisition
    await a.operation.start()
    await a.operation.retire()
    identity, resource = a.operation._identity_transport, a.operation._transport
    original = BudgetedTransport.aclose
    attempted = []
    async def close(transport):
        attempted.append(transport)
        if transport is identity:
            raise TimeoutError('original identity close not acknowledged')
        await original(transport)
    monkeypatch.setattr(BudgetedTransport, 'aclose', close)
    try:
        with pytest.raises(TimeoutError):
            await a.operation.retire()
        assert attempted == [identity, resource]
    finally:
        monkeypatch.setattr(BudgetedTransport, 'aclose', original)


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True, 'stall_metadata': True}], indirect=True)
async def test_real_http_observer_cancellation_is_not_converted_into_worker_withdrawal(acquisition, oauth_peers):
    import asyncio
    a = acquisition
    observer = asyncio.create_task(a.operation.start())
    try:
        async with asyncio.timeout(2):
            while ('GET', '/.well-known/oauth-authorization-server') not in oauth_peers.requests:
                await asyncio.sleep(0.001)
        observer.cancel('owned request cancellation')
        a.operation.withdraw()
        with pytest.raises(asyncio.CancelledError):
            await observer
        assert observer.cancelled() and observer.cancelling() == 1
    finally:
        oauth_peers.release_body.set()
        await asyncio.gather(observer, return_exceptions=True)


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True}], indirect=True)
async def test_denied_callback_abandons_before_returning_a_safe_failure(acquisition):
    a = acquisition
    started = await a.operation.start()
    with pytest.raises(GrantRejected, match='denied'):
        await a.operation.complete({'state': started['state'], 'error': 'access_denied'}, lambda: None)
    assert (await slot(a)).reason == 'abandoned'
    assert a.operation._withdrawn


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True}], indirect=True)
async def test_retiring_an_old_authorization_does_not_abandon_a_replacement_slot(acquisition):
    a = acquisition
    await a.operation.start()
    original = await slot(a)
    replacement = await a.store.begin_authorization(original.binding, expected=original)
    await a.operation.retire()
    current = await slot(a)
    assert current.state == 'authorizing' and current.revision == replacement.revision


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True}], indirect=True)
async def test_failed_abandon_ack_attempts_every_original_close_and_is_retryable(acquisition, monkeypatch):
    a = acquisition
    await a.operation.start()
    original = a.store.abandon_authorization
    calls = []
    async def lost_ack(claim):
        calls.append(claim)
        await original(claim)
        raise TimeoutError('original abandon commit acknowledgement lost')
    monkeypatch.setattr(a.store, 'abandon_authorization', lost_ack)
    with pytest.raises(TimeoutError):
        await a.operation.cancel(lambda: None)
    assert not a.operation.storage._abandoned
    assert not a.operation._identity_transport.transport._transports
    assert not a.operation._transport.transport._transports
    assert (await slot(a)).reason == 'abandoned'
    await a.operation.cancel(lambda: None)
    assert a.operation.storage._abandoned and len(calls) == 1


@pytest.mark.parametrize('oauth_peers', [{'web_identity': True}], indirect=True)
async def test_background_retirement_preserves_the_original_custody_revision(acquisition, monkeypatch):
    a = acquisition
    await a.operation.start()
    before = await slot(a)
    def forbidden_write(*args, **kwargs):
        raise AssertionError('Background retirement must not write durable custody')
    monkeypatch.setattr(a.store, '_replace', forbidden_write)
    await a.operation.retire()
    after = await slot(a)
    assert after == before
