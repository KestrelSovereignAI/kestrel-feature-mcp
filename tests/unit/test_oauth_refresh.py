"""Production Authlib refresh, native durable intent and independent real TLS."""

from contextlib import AsyncExitStack
import time
from types import SimpleNamespace

import pytest
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend

from kestrel_feature_mcp.oauth_grants import OAuthGrantBinding, OAuthGrantStore, OAuthGrantTokens, OAuthGrantChanged
from kestrel_feature_mcp.oauth_policy import GrantRejected
from kestrel_feature_mcp.oauth_refresh import OAuthRefresher
from tests.unit.test_oauth_grants import install_grant
from tests.unit.test_oauth_acceptance_http import oauth_peers

pytestmark = pytest.mark.parametrize('mcp_http_server', [{'tls': True, 'oauth': {}}], indirect=True)


@pytest.fixture
async def refresh_attempt(oauth_peers, owned_oauth_key, tmp_path):
    selected = oauth_peers.selection
    binding = OAuthGrantBinding('did:test:production-refresh', 'original-principal', 'original-connection',
        selected.server_url, selected.resource, selected.issuer, selected.client_id, selected.redirect_uri,
        selected.scopes, selected.protected_metadata, selected.authorization_metadata)
    async with AsyncExitStack() as cleanup:
        db = SQLiteBackend(str(tmp_path / 'owned-refresh.db'))
        await db.connect()
        cleanup.push_async_callback(db.close)
        store = OAuthGrantStore(db, binding.agent_did, max_token_bytes=4096)
        await store.initialize()
        snapshot = await install_grant(store, binding, OAuthGrantTokens(
            'owned-expired-access', 'native-fixture-refresh', time.time() - 100, frozenset({'read'})))
        owner = OAuthRefresher(store, {'network_seconds': 0.75, 'response_max_bytes': 65536}, close_seconds=2)
        cleanup.push_async_callback(owner.retire)
        yield SimpleNamespace(store=store, snapshot=snapshot, owner=owner, binding=binding)


@pytest.mark.parametrize('oauth_peers', [{'refresh': True, 'web_identity': True,
    'refresh_rotate': True}, {'refresh': True, 'web_identity': True, 'refresh_rotate': False}], indirect=True)
async def test_production_refresh_commits_one_native_rotation_and_cannot_replay(refresh_attempt, oauth_peers):
    a = refresh_attempt
    fresh = await a.owner.run(a.snapshot, lambda: None)
    assert fresh.tokens is None and fresh.state == 'active'
    payload = await a.store.read_tokens(fresh)
    assert payload.tokens.access_token == 'native-fixture-access'
    assert payload.tokens.refresh_token == ('native-fixture-rotated'
        if oauth_peers.options['refresh_rotate'] else 'native-fixture-refresh')
    assert not payload.tokens.is_expired(time.time())
    assert oauth_peers.requests.count(('POST', '/token')) == 1
    assert ('GET', '/authorize') not in oauth_peers.requests
    with pytest.raises(GrantRejected, match='cannot be replayed'):
        await a.owner.run(fresh, lambda: None)
    assert oauth_peers.requests.count(('POST', '/token')) == 1
    assert oauth_peers.resource.witness == []


@pytest.mark.parametrize('oauth_peers', [{'refresh': True, 'web_identity': True,
    'wrong_issuer_spelling': True}], indirect=True)
async def test_changed_native_metadata_refuses_refresh_before_token_http(refresh_attempt, oauth_peers):
    a = refresh_attempt
    with pytest.raises(GrantRejected):
        await a.owner.run(a.snapshot, lambda: None)
    assert (await a.store.read(a.binding)).state == 'active'
    assert oauth_peers.requests.count(('POST', '/token')) == 0


@pytest.mark.parametrize('oauth_peers', [{'refresh': True, 'web_identity': True, 'token_error_status': 400},
    {'refresh': True, 'web_identity': True, 'token_error_status': 401},
    {'refresh': True, 'web_identity': True, 'token_error_status': 503}], indirect=True)
async def test_refresh_error_tombstone_or_unknown_is_durable_and_content_free(refresh_attempt, oauth_peers):
    a = refresh_attempt
    with pytest.raises(GrantRejected) as caught:
        await a.owner.run(a.snapshot, lambda: None)
    assert 'owned-sensitive-AS-error-marker' not in str(caught.value)
    result = await a.store.read(a.binding)
    if oauth_peers.options['token_error_status'] in {400, 401}:
        assert result.state == 'revoked' and result.reason == 'refresh_rejected'
    else:
        assert result.state == 'refreshing'
    assert oauth_peers.requests.count(('POST', '/token')) == 1


@pytest.mark.parametrize('oauth_peers', [{'refresh': True, 'web_identity': True}], indirect=True)
async def test_lost_refresh_intent_ack_prevents_the_actual_token_post(refresh_attempt, oauth_peers, monkeypatch):
    a = refresh_attempt
    original = a.store.begin_refresh
    async def unacknowledged(snapshot):
        await original(snapshot)
        raise TimeoutError('original durable refresh acknowledgment lost')
    monkeypatch.setattr(a.store, 'begin_refresh', unacknowledged)
    with pytest.raises(TimeoutError):
        await a.owner.run(a.snapshot, lambda: None)
    assert (await a.store.read(a.binding)).state == 'refreshing'
    assert oauth_peers.requests.count(('POST', '/token')) == 0


@pytest.mark.parametrize('oauth_peers', [{'refresh': True, 'web_identity': True, 'stall_token': True}], indirect=True)
async def test_stalled_refresh_is_unknown_and_another_owner_cannot_replay(refresh_attempt, oauth_peers):
    a = refresh_attempt
    with pytest.raises(TimeoutError):
        await a.owner.run(a.snapshot, lambda: None)
    assert (await a.store.read(a.binding)).state == 'refreshing'
    other = OAuthRefresher(a.store, a.owner.budgets, close_seconds=2)
    try:
        with pytest.raises(OAuthGrantChanged):
            await other.run(a.snapshot, lambda: None)
    finally:
        await other.retire()
    assert oauth_peers.requests.count(('POST', '/token')) == 1
    assert oauth_peers.resource.witness == []


@pytest.mark.parametrize('oauth_peers', [{'refresh': True, 'web_identity': True, 'stall_token': True}], indirect=True)
async def test_refresh_close_timeout_retains_and_later_joins_the_original_foreground_frame(refresh_attempt, oauth_peers):
    import asyncio
    a = refresh_attempt
    entered = asyncio.Event()
    async def before_token():
        entered.set()
    oauth_peers.options['before_token'] = before_token
    a.owner.close_seconds = 0.025
    original = asyncio.create_task(a.owner.run(a.snapshot, lambda: None))
    try:
        await entered.wait()
        with pytest.raises(TimeoutError):
            await a.owner.retire()
        assert a.owner._owner is original and not original.done() and original.cancelling() == 0
        oauth_peers.release_body.set()
        result = await original
        await a.owner.retire()
        assert result.state == 'active' and a.owner._done.is_set()
        assert a.owner._transport.transport._transports == {}
        assert oauth_peers.requests.count(('POST', '/token')) == 1
    finally:
        oauth_peers.release_body.set()
        if not original.done():
            await original
