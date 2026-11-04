"""Real encrypted SQL grant custody, independent owners, and stale completion."""

import asyncio
import base64
from contextlib import asynccontextmanager
from dataclasses import replace

import pytest

from kestrel_sdk.security.exceptions import DecryptionError
from kestrel_sdk.storage.database import TransactionError
from kestrel_sovereign.storage.db.sqlite import SQLiteBackend
from kestrel_feature_mcp.oauth_grants import (
    OAuthGrantBinding, OAuthGrantChanged, OAuthGrantRejected,
    OAuthGrantStore, OAuthGrantTokens,
)


@pytest.fixture
def binding():
    return OAuthGrantBinding('did:test:oauth-owner', 'operator-one', 'connection-one',
        'https://remote.example/mcp', 'https://remote.example/mcp',
        'https://issuer.example', 'vendor-registered-client',
        'https://host.example/oauth/callback', frozenset({'read', 'write'}))


@pytest.fixture
def tokens():
    return OAuthGrantTokens('synthetic-access-secret', 'synthetic-refresh-secret',
                           1_700_000_000, frozenset({'read'}))


@pytest.fixture
async def owners(tmp_path, monkeypatch, binding):
    monkeypatch.setenv('KESTREL_DATA_KEY', base64.urlsafe_b64encode(b'k' * 32).decode())
    databases = [SQLiteBackend(str(tmp_path / 'grants.db')) for _ in range(2)]
    try:
        for db in databases:
            await db.connect()
        stores = [OAuthGrantStore(db, binding.agent_did, max_token_bytes=4096) for db in databases]
        for store in stores:
            await store.initialize()
        yield databases, stores
    finally:
        for db in reversed(databases):
            await db.close()


@pytest.mark.asyncio
async def test_encrypted_grant_survives_independent_store_restart(owners, binding, tokens):
    databases, (first, second) = owners
    installed = await first.install(binding, tokens)
    restored = await second.read(binding)
    assert restored == installed and restored.tokens.expires_at == 1_700_000_000
    row = await databases[0].fetch_one('SELECT ciphertext FROM mcp_oauth_grants')
    assert row[0].startswith('KSAv2:')
    assert tokens.access_token not in row[0] and tokens.refresh_token not in row[0]
    assert tokens.access_token not in repr(restored) and tokens.refresh_token not in repr(tokens)


@pytest.mark.asyncio
@pytest.mark.parametrize('field,value', [
    ('principal_id', 'operator-two'), ('connection_id', 'connection-two'),
    ('server_url', 'https://remote.example/other'), ('resource', 'https://remote.example'),
    ('issuer', 'https://other-issuer.example'), ('client_id', 'other-client'),
    ('redirect_uri', 'https://host.example/other'), ('scopes', frozenset({'read'})),
])
async def test_every_frozen_binding_field_isolated(owners, binding, tokens, field, value):
    databases, (store, _) = owners
    await store.install(binding, tokens)
    other = replace(binding, **{field: value})
    assert await store.read(other) is None
    # Even a ciphertext copied to the other binding cannot decrypt there.
    await databases[0].execute('INSERT INTO mcp_oauth_grants '
        '(agent_did, grant_id, revision, state, ciphertext) '
        'SELECT agent_did, ?, revision, state, ciphertext FROM mcp_oauth_grants',
        (other.identifier,))
    with pytest.raises(DecryptionError):
        await store.read(other)


@pytest.mark.asyncio
async def test_other_agent_is_rejected_before_storage(owners, binding, tokens):
    _, (store, _) = owners
    other = replace(binding, agent_did='did:test:other')
    with pytest.raises(OAuthGrantRejected, match='another agent'):
        await store.install(other, tokens)
    with pytest.raises(OAuthGrantRejected, match='another agent'):
        await store.read(other)


@pytest.mark.asyncio
async def test_only_one_independent_refresh_claim_can_commit(owners, binding, tokens):
    _, (first, second) = owners
    installed = await first.install(binding, tokens)
    results = await asyncio.gather(first.begin_refresh(installed),
                                   second.begin_refresh(installed), return_exceptions=True)
    claims = [result for result in results if not isinstance(result, BaseException)]
    assert len(claims) == 1
    assert sum(isinstance(result, OAuthGrantChanged) for result in results) == 1
    claim = claims[0]
    assert claim.state == 'refreshing'
    restored = await second.read(binding)
    assert restored == claim
    with pytest.raises(OAuthGrantRejected, match='another refresh'):
        await second.begin_refresh(restored)
    rotated = replace(tokens, access_token='next-access', refresh_token='rotated-refresh',
                      expires_at=1_900_000_000)
    complete = await first.finish_refresh(claim, rotated)
    assert complete.state == 'active' and complete.tokens == rotated
    with pytest.raises(OAuthGrantChanged):
        await second.finish_refresh(claim, rotated)
    next_claim = await second.begin_refresh(complete)
    with pytest.raises(OAuthGrantChanged):
        await first.begin_refresh(installed)
    with pytest.raises(OAuthGrantChanged):
        await first.finish_refresh(claim, rotated)
    assert (await first.read(binding)) == next_claim


@pytest.mark.asyncio
async def test_local_revocation_cannot_be_undone_by_stale_refresh_or_insert(owners, binding, tokens):
    _, (first, second) = owners
    installed = await first.install(binding, tokens)
    claim = await first.begin_refresh(installed)
    revoked = await second.revoke_local(claim)
    assert revoked.state == 'revoked' and revoked.tokens is None
    with pytest.raises(OAuthGrantChanged):
        await first.finish_refresh(claim, replace(tokens, refresh_token='rotated'))
    with pytest.raises(OAuthGrantChanged):
        await first.install(binding, tokens)
    # Replacement requires the current tombstone and a separately authorized
    # host call; possessing this revision alone confers no operator authority.
    new = await first.install(binding, tokens, expected=revoked)
    assert new.state == 'active' and new.revision != installed.revision


@pytest.mark.asyncio
async def test_scope_expansion_refused_before_initial_or_rotated_storage(owners, binding, tokens):
    databases, (store, _) = owners
    with pytest.raises(OAuthGrantRejected, match='approved scopes'):
        await store.install(binding, replace(tokens, scopes=frozenset({'admin'})))
    assert await databases[0].fetch_val('SELECT COUNT(*) FROM mcp_oauth_grants') == 0
    claim = await store.begin_refresh(await store.install(binding, tokens))
    with pytest.raises(OAuthGrantRejected, match='original token scopes'):
        await store.finish_refresh(claim, replace(tokens, scopes=frozenset({'read', 'write'})))
    assert (await store.read(binding)) == claim


@pytest.mark.asyncio
async def test_lost_commit_ack_retains_real_refresh_claim_without_retry(owners, binding, tokens, monkeypatch):
    databases, (first, second) = owners
    installed = await first.install(binding, tokens)
    transaction = databases[0].transaction

    @asynccontextmanager
    async def lose_ack():
        async with transaction():
            yield
        raise TransactionError('Synthetic loss of the real committed ACK')

    monkeypatch.setattr(databases[0], 'transaction', lose_ack)
    with pytest.raises(TransactionError, match='committed ACK'):
        await first.begin_refresh(installed)
    retained = await second.read(binding)
    assert retained.state == 'refreshing' and retained.revision != installed.revision
    with pytest.raises(OAuthGrantRejected, match='another refresh'):
        await second.begin_refresh(retained)


@pytest.mark.asyncio
async def test_revocation_between_commit_and_readback_refuses_publication(owners, binding, tokens, monkeypatch):
    databases, (first, second) = owners
    installed = await first.install(binding, tokens)
    transaction = databases[0].transaction

    @asynccontextmanager
    async def revoke_after_commit():
        async with transaction():
            yield
        committed = await second.read(binding)
        assert committed.state == 'refreshing'
        await second.revoke_local(committed)

    monkeypatch.setattr(databases[0], 'transaction', revoke_after_commit)
    with pytest.raises(OAuthGrantChanged, match='acknowledged'):
        await first.begin_refresh(installed)
    retained = await second.read(binding)
    assert retained.state == 'revoked' and retained.tokens is None


@pytest.mark.asyncio
@pytest.mark.parametrize('column,value', [('revision', 'swapped-revision'), ('state', 'refreshing')])
async def test_custody_state_and_revision_authenticated(owners, binding, tokens, column, value):
    databases, (store, _) = owners
    await store.install(binding, tokens)
    assert column in {'revision', 'state'}
    await databases[0].execute('UPDATE mcp_oauth_grants SET ' + column + ' = ?', (value,))
    with pytest.raises(DecryptionError):
        await store.read(binding)


@pytest.mark.asyncio
async def test_token_budget_refuses_write_and_oversized_stored_ciphertext(owners, binding, tokens):
    databases, (store, _) = owners
    with pytest.raises(OAuthGrantRejected, match='storage budget'):
        await store.install(binding, replace(tokens, access_token='x' * 5000))
    await store.install(binding, tokens)
    await databases[0].execute('UPDATE mcp_oauth_grants SET ciphertext = ?', ('x' * 6000,))
    with pytest.raises(OAuthGrantRejected, match='storage budget'):
        await store.read(binding)


@pytest.mark.parametrize('expiry', [True, -1, float('nan'), float('inf'), '3600'])
def test_expiry_is_absolute_finite_and_never_coerced(tokens, expiry):
    with pytest.raises(OAuthGrantRejected, match='absolute finite timestamp'):
        replace(tokens, expires_at=expiry)
